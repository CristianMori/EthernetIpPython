"""Regression tests: fragmented services (0x52 / 0x53) on walker-member paths.

Before the fix, LogixDispatcher._dispatch_walked matched 0x52 / 0x53 but
called the non-walker fragmented handlers without threading the WalkResult
through, so a request like ``Program:MainProgram.motor.counts[5]`` with
service 0x52 silently read from byte 0 of the root tag — and the reply
prefix carried the root UDT's structure handle, not the walked member's.
Writes to a struct member were rejected because the type/handle validation
compared against the root tag rather than the walked member.

These tests exercise the three symptoms through the public dispatcher:
read of a scalar UDT member, read of a UDT array-member element, and
write-then-read of a UDT array-member element with neighbor-preservation.
"""

from __future__ import annotations
import struct

from ethernetip.cip.path import (
    CipPath,
    ElementPathSegment,
    SymbolicPathSegment,
)
from ethernetip.logix import data_types as dt
from ethernetip.logix.logix_dispatcher import LogixDispatcher
from ethernetip.logix.tag_database import (
    TagDatabase,
    TemplateDefinition,
    TemplateMemberInfo,
)
from ethernetip.logix.tag_services import (
    READ_TAG_FRAGMENTED,
    WRITE_TAG_FRAGMENTED,
)


def _frag_read_body(element_count: int, byte_offset: int) -> bytes:
    return struct.pack('<HI', element_count, byte_offset)


def _frag_write_body(tag_type: int, element_count: int,
                     byte_offset: int, payload: bytes) -> bytes:
    return struct.pack('<HHI', tag_type, element_count, byte_offset) + payload


def _motor_scalar_tpl() -> TemplateDefinition:
    """Motor { Speed: REAL @0, Count: DINT @4 } — structure_size=8."""
    return TemplateDefinition(
        instance_id=0x400, name="Motor", struct_handle=0x8400,
        member_count=2, structure_size=8,
        members=[
            TemplateMemberInfo("Speed", dt.REAL, 1, 0, 4, 0),
            TemplateMemberInfo("Count", dt.DINT, 1, 4, 4, 0),
        ],
    )


def _motor_array_tpl() -> TemplateDefinition:
    """Motor { Speed: REAL @0, counts: DINT[10] @4 } — structure_size=44."""
    return TemplateDefinition(
        instance_id=0x401, name="MotorArr", struct_handle=0x8401,
        member_count=2, structure_size=44,
        members=[
            TemplateMemberInfo("Speed", dt.REAL, 1, 0, 4, 0),
            TemplateMemberInfo("counts", dt.DINT, 10, 4, 4, 10),
        ],
    )


def test_fragmented_read_udt_member_dint():
    """Fragmented read of ``motor.Count`` returns the Count value and the
    DINT atomic type code, not the Speed bytes or the root UDT prefix."""
    db = TagDatabase()
    tpl = _motor_scalar_tpl()
    db.add_template_prebuilt(tpl)
    tag = db.add_struct_tag("motor", tpl)

    # Seed: Speed = +inf-sentinel pattern (0x7F800000); Count = 1234567.
    struct.pack_into('<I', tag._data, 0, 0x7F800000)
    struct.pack_into('<i', tag._data, 4, 1234567)

    logix = LogixDispatcher(tags=db)
    path = CipPath(segments=(
        SymbolicPathSegment("motor"),
        SymbolicPathSegment("Count"),
    ))
    resp = logix.dispatch(READ_TAG_FRAGMENTED, path,
                          _frag_read_body(element_count=1, byte_offset=0))

    assert resp.status.is_success, f"status=0x{resp.status.general_status:02X}"
    reply = bytes(resp.data)
    # Atomic member → 2-byte type prefix, not the 4-byte struct prefix.
    assert len(reply) == 2 + 4
    tc = struct.unpack_from('<H', reply, 0)[0]
    assert tc == dt.DINT, f"expected DINT type code, got 0x{tc:04X}"
    val = struct.unpack_from('<i', reply, 2)[0]
    assert val == 1234567, f"expected Count=1234567, got {val} (likely Speed bytes)"


def test_fragmented_read_udt_member_array():
    """Fragmented read of ``motor.counts[5]`` returns counts[5]=505, not
    counts[0] or the root UDT start."""
    db = TagDatabase()
    tpl = _motor_array_tpl()
    db.add_template_prebuilt(tpl)
    tag = db.add_struct_tag("motor", tpl)

    # counts @ byte_offset 4; counts[i] at 4 + i*4
    for i in range(10):
        struct.pack_into('<i', tag._data, 4 + i * 4, 500 + i)

    logix = LogixDispatcher(tags=db)
    path = CipPath(segments=(
        SymbolicPathSegment("motor"),
        SymbolicPathSegment("counts"),
        ElementPathSegment(5),
    ))
    resp = logix.dispatch(READ_TAG_FRAGMENTED, path,
                          _frag_read_body(element_count=1, byte_offset=0))

    assert resp.status.is_success, f"status=0x{resp.status.general_status:02X}"
    reply = bytes(resp.data)
    assert len(reply) == 2 + 4
    tc = struct.unpack_from('<H', reply, 0)[0]
    assert tc == dt.DINT
    val = struct.unpack_from('<i', reply, 2)[0]
    assert val == 505, f"expected counts[5]=505, got {val}"


def test_fragmented_write_udt_member_array():
    """Fragmented write of 7777 to ``motor.counts[7]`` lands on counts[7]
    only; counts[6], counts[8], and Speed stay as they were."""
    db = TagDatabase()
    tpl = _motor_array_tpl()
    db.add_template_prebuilt(tpl)
    tag = db.add_struct_tag("motor", tpl)

    # Pre-seed everything so neighbor preservation is observable.
    struct.pack_into('<I', tag._data, 0, 0xDEADBEEF)  # Speed bit pattern
    for i in range(10):
        struct.pack_into('<i', tag._data, 4 + i * 4, 500 + i)

    logix = LogixDispatcher(tags=db)
    path = CipPath(segments=(
        SymbolicPathSegment("motor"),
        SymbolicPathSegment("counts"),
        ElementPathSegment(7),
    ))

    write_payload = struct.pack('<i', 7777)
    write_req = _frag_write_body(dt.DINT, element_count=1,
                                 byte_offset=0, payload=write_payload)
    write_resp = logix.dispatch(WRITE_TAG_FRAGMENTED, path, write_req)
    assert write_resp.status.is_success, (
        f"write status=0x{write_resp.status.general_status:02X}")

    # Read back counts[7] via fragmented too.
    read_resp = logix.dispatch(READ_TAG_FRAGMENTED, path,
                               _frag_read_body(element_count=1, byte_offset=0))
    assert read_resp.status.is_success
    val = struct.unpack_from('<i', bytes(read_resp.data), 2)[0]
    assert val == 7777

    # Direct byte check: counts[6], counts[8], Speed untouched.
    assert struct.unpack_from('<i', tag._data, 4 + 6 * 4)[0] == 506
    assert struct.unpack_from('<i', tag._data, 4 + 8 * 4)[0] == 508
    assert struct.unpack_from('<I', tag._data, 0)[0] == 0xDEADBEEF
