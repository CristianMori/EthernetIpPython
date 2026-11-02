"""Regression tests for the fragmented-path element-offset asymmetry.

Read_Tag / Write_Tag honored ``request.path.element_id``, but
Read_Tag_Fragmented (0x52) and Write_Tag_Fragmented (0x53) did not — a
client sending ``Class 0x6B + Instance N + Element i + 0x52`` read from
byte 0 of the tag instead of element i. The symbolic / walker path was
always correct via the walker-aware ``*_at`` handlers; this covers the
instance-ID-plus-element path that ``TagClient`` uses after a browse.

Pulled from PR #1 exploration (SRCthird).
"""

import struct

from ethernetip.cip.path import CipPath
from ethernetip.logix import data_types as dt
from ethernetip.logix import tag_services as ts
from ethernetip.logix.logix_dispatcher import LogixDispatcher
from ethernetip.logix.tag_database import TagDatabase


def _fragmented_read_body(element_count: int, byte_offset_in_elements: int) -> bytes:
    return struct.pack('<HI', element_count, byte_offset_in_elements)


def _fragmented_write_body(tag_type: int, element_count: int,
                            byte_offset_in_elements: int, payload: bytes) -> bytes:
    return struct.pack('<HHI', tag_type, element_count, byte_offset_in_elements) + payload


def test_symbol_object_fragmented_read_honors_element_segment():
    db = TagDatabase()
    tag = db.add_tag("counts", dt.DINT, element_count=10)
    for i in range(10):
        tag.write_dint(i * 4, 100 + i)

    logix = LogixDispatcher(db)
    # Class 0x6B · Instance tag.instance_id · Element 5 · Read_Tag_Fragmented
    path = CipPath(class_id=0x6B, instance_id=tag.instance_id, element_id=5)
    req = _fragmented_read_body(element_count=1, byte_offset_in_elements=0)

    resp = logix.dispatch(ts.READ_TAG_FRAGMENTED, path, req)

    assert resp.status.is_success, f"status=0x{resp.status.general_status:02X}"
    # Reply payload: [type:UINT][data...]
    reply_data = bytes(resp.data)
    assert struct.unpack_from('<H', reply_data, 0)[0] == dt.DINT
    assert struct.unpack_from('<i', reply_data, 2)[0] == 105


def test_symbol_object_fragmented_read_no_element_segment_reads_from_byte_zero():
    # Confirm the fix does not break the "no element segment" case.
    db = TagDatabase()
    tag = db.add_tag("counts", dt.DINT, element_count=10)
    for i in range(10):
        tag.write_dint(i * 4, 100 + i)

    logix = LogixDispatcher(db)
    path = CipPath(class_id=0x6B, instance_id=tag.instance_id)
    req = _fragmented_read_body(element_count=1, byte_offset_in_elements=0)

    resp = logix.dispatch(ts.READ_TAG_FRAGMENTED, path, req)

    assert resp.status.is_success
    assert struct.unpack_from('<i', bytes(resp.data), 2)[0] == 100


def test_symbol_object_fragmented_write_honors_element_segment():
    db = TagDatabase()
    tag = db.add_tag("counts", dt.DINT, element_count=10)

    logix = LogixDispatcher(db)
    path = CipPath(class_id=0x6B, instance_id=tag.instance_id, element_id=7)
    payload = struct.pack('<i', 7777)
    req = _fragmented_write_body(dt.DINT, element_count=1,
                                   byte_offset_in_elements=0, payload=payload)

    resp = logix.dispatch(ts.WRITE_TAG_FRAGMENTED, path, req)

    assert resp.status.is_success, f"status=0x{resp.status.general_status:02X}"
    assert tag.read_dint(7 * 4) == 7777
    # Neighbors untouched.
    assert tag.read_dint(6 * 4) == 0
    assert tag.read_dint(8 * 4) == 0


def test_symbol_object_fragmented_read_asymmetry_parity_with_atomic_read_tag():
    """Pin the fix: the same element segment through atomic Read_Tag (which
    already honored element_id) and fragmented Read_Tag_Fragmented must
    produce the same element value."""
    db = TagDatabase()
    tag = db.add_tag("counts", dt.DINT, element_count=10)
    for i in range(10):
        tag.write_dint(i * 4, 1000 + i)

    logix = LogixDispatcher(db)
    path = CipPath(class_id=0x6B, instance_id=tag.instance_id, element_id=3)

    atomic_req = struct.pack('<H', 1)
    atomic_resp = logix.dispatch(ts.READ_TAG, path, atomic_req)
    assert atomic_resp.status.is_success
    atomic_value = struct.unpack_from('<i', bytes(atomic_resp.data), 2)[0]

    frag_req = _fragmented_read_body(element_count=1, byte_offset_in_elements=0)
    frag_resp = logix.dispatch(ts.READ_TAG_FRAGMENTED, path, frag_req)
    assert frag_resp.status.is_success
    frag_value = struct.unpack_from('<i', bytes(frag_resp.data), 2)[0]

    assert atomic_value == 1003
    assert frag_value == atomic_value
