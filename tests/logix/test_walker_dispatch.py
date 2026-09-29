"""End-to-end walker dispatch tests via LogixDispatcher.

Uses the in-process dispatcher (no TCP) — a client wraps the request in
a CipPath and calls dispatcher.dispatch(); the response comes back
synchronously.
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
from ethernetip.logix.tag_services import READ_TAG, WRITE_TAG


def _timer_tpl() -> TemplateDefinition:
    """Timer with EN/TT/DN packed at bits 0/1/2 of the host byte at offset 8."""
    return TemplateDefinition(
        instance_id=0x300, name="Timer", struct_handle=0x8300,
        member_count=5, structure_size=12,
        members=[
            TemplateMemberInfo("PRE", dt.DINT, 1, 0, 4, 0),
            TemplateMemberInfo("ACC", dt.DINT, 1, 4, 4, 0),
            TemplateMemberInfo("EN", dt.BOOL, 1, 8, 0, 0),
            TemplateMemberInfo("TT", dt.BOOL, 1, 8, 0, 1),
            TemplateMemberInfo("DN", dt.BOOL, 1, 8, 0, 2),
        ],
    )


def _dispatcher_with_timer():
    db = TagDatabase()
    tpl = _timer_tpl()
    db.add_template_prebuilt(tpl)
    tag = db.add_struct_tag("MyTimer", tpl)
    return LogixDispatcher(tags=db), db, tag


def test_read_scalar_member():
    logix, db, tag = _dispatcher_with_timer()
    struct.pack_into('<i', tag._data, 4, 6789)
    path = CipPath(segments=(
        SymbolicPathSegment("MyTimer"),
        SymbolicPathSegment("ACC"),
    ))
    resp = logix.dispatch(READ_TAG, path, struct.pack('<H', 1))
    assert resp.status.is_success, f"status=0x{resp.status.general_status:02X}"
    tc = struct.unpack_from('<H', resp.data, 0)[0]
    val = struct.unpack_from('<i', resp.data, 2)[0]
    assert tc == dt.DINT
    assert val == 6789


def test_read_bool_member_bit():
    logix, db, tag = _dispatcher_with_timer()
    tag._data[8] = 0b0000_0100  # DN set
    path = CipPath(segments=(
        SymbolicPathSegment("MyTimer"),
        SymbolicPathSegment("DN"),
    ))
    resp = logix.dispatch(READ_TAG, path, struct.pack('<H', 1))
    assert resp.status.is_success
    tc = struct.unpack_from('<H', resp.data, 0)[0]
    assert tc == dt.BOOL
    assert resp.data[2] == 1


def test_write_bool_member_bit_preserves_neighbors():
    logix, db, tag = _dispatcher_with_timer()
    tag._data[8] = 0b0000_0010  # TT set
    path = CipPath(segments=(
        SymbolicPathSegment("MyTimer"),
        SymbolicPathSegment("DN"),
    ))
    payload = struct.pack('<HH', dt.BOOL, 1) + bytes([1])
    resp = logix.dispatch(WRITE_TAG, path, payload)
    assert resp.status.is_success, f"status=0x{resp.status.general_status:02X}"
    assert tag._data[8] == 0b0000_0110  # TT still set, DN now set


def test_read_multi_dim_element():
    db = TagDatabase()
    tag = db.add_tag("Matrix", dt.DINT, dims=(5, 10, 4))
    struct.pack_into('<i', tag._data, 204, 999)  # ((1*10+2)*4+3)*4 = 204
    logix = LogixDispatcher(tags=db)
    path = CipPath(segments=(
        SymbolicPathSegment("Matrix"),
        ElementPathSegment(1),
        ElementPathSegment(2),
        ElementPathSegment(3),
    ))
    resp = logix.dispatch(READ_TAG, path, struct.pack('<H', 1))
    assert resp.status.is_success
    val = struct.unpack_from('<i', resp.data, 2)[0]
    assert val == 999


def test_write_bool_array_bit():
    db = TagDatabase()
    tag = db.add_tag("Flags", dt.BOOL, element_count=32)
    logix = LogixDispatcher(tags=db)
    path = CipPath(segments=(
        SymbolicPathSegment("Flags"),
        ElementPathSegment(5),
    ))
    payload = struct.pack('<HH', dt.BOOL, 1) + bytes([1])
    resp = logix.dispatch(WRITE_TAG, path, payload)
    assert resp.status.is_success
    assert tag._data[0] == 0b0010_0000
    assert tag._data[1] == 0


def test_program_scoped_read_write():
    db = TagDatabase()
    db.register_program("Cell")
    tag = db.add_program_tag("Cell", "Rate", dt.DINT)
    struct.pack_into('<i', tag._data, 0, 4242)
    logix = LogixDispatcher(tags=db)

    path = CipPath(segments=(
        SymbolicPathSegment("Program:Cell"),
        SymbolicPathSegment("Rate"),
    ))
    resp = logix.dispatch(READ_TAG, path, struct.pack('<H', 1))
    assert resp.status.is_success, f"status=0x{resp.status.general_status:02X}"
    val = struct.unpack_from('<i', resp.data, 2)[0]
    assert val == 4242


def test_flat_symbolic_fast_path_still_works():
    db = TagDatabase()
    tag = db.add_tag("rate", dt.DINT)
    struct.pack_into('<i', tag._data, 0, 42)
    logix = LogixDispatcher(tags=db)
    # No segments — force the fast path via symbolic_name only.
    path = CipPath(symbolic_name="rate")
    resp = logix.dispatch(READ_TAG, path, struct.pack('<H', 1))
    assert resp.status.is_success
    val = struct.unpack_from('<i', resp.data, 2)[0]
    assert val == 42
