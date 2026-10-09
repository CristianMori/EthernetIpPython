"""Tests for the CIP Vol 1 §C-6.1 unsigned integer and bit-string atomic types."""

from __future__ import annotations
import io
import struct

import pytest

from ethernetip.cip.path import CipPath
from ethernetip.logix import data_types as dt
from ethernetip.logix.logix_dispatcher import LogixDispatcher
from ethernetip.logix.persistence import load, save
from ethernetip.logix.tag_database import TagDatabase, TemplateMember
from ethernetip.logix.tag_services import READ_TAG, WRITE_TAG


ADDED_TYPES = [
    (dt.USINT, 1), (dt.UINT, 2), (dt.UDINT, 4), (dt.ULINT, 8),
    (dt.BYTE, 1), (dt.WORD, 2), (dt.DWORD, 4), (dt.LWORD, 8),
]


@pytest.mark.parametrize("code,expected_size", ADDED_TYPES)
def test_get_element_size(code, expected_size):
    assert dt.get_element_size(code) == expected_size


def test_add_tag_udint_succeeds():
    """The specific EscaFlow crash: Unknown tag type 0x00C8."""
    db = TagDatabase()
    tag = db.add_tag("counter", dt.UDINT)
    assert tag.element_size == 4
    assert tag.data_size == 4


@pytest.mark.parametrize("code,max_val,fmt", [
    (dt.USINT, 0xFF,                       '<B'),
    (dt.UINT,  0xFFFF,                     '<H'),
    (dt.UDINT, 0xFFFFFFFF,                 '<I'),
    (dt.ULINT, 0xFFFFFFFFFFFFFFFF,         '<Q'),
])
def test_unsigned_boundary_values_round_trip(code, max_val, fmt):
    db = TagDatabase()
    tag = db.add_tag("x", code)
    tag.set_data(struct.pack(fmt, max_val))
    assert struct.unpack_from(fmt, tag.get_data(), 0)[0] == max_val


@pytest.mark.parametrize("code,width", [(dt.BYTE, 1), (dt.WORD, 2), (dt.LWORD, 8)])
def test_bit_string_types_allocate_correct_width(code, width):
    db = TagDatabase()
    tag = db.add_tag("bits", code)
    assert tag.data_size == width


def test_add_array_of_udint_allocates_n_times_4_bytes():
    db = TagDatabase()
    tag = db.add_tag("counters", dt.UDINT, element_count=16)
    assert tag.data_size == 64
    struct.pack_into('<I', tag._data, 15 * 4, 0xDEADBEEF)
    assert struct.unpack_from('<I', tag.get_data(), 15 * 4)[0] == 0xDEADBEEF


def test_udt_member_with_each_new_type():
    """A UDT with one scalar member of every added type packs correctly
    under Logix alignment rules (bytes-aligned types pack tight, 2-byte
    at even, 4-byte at %4, 8-byte at %8)."""
    db = TagDatabase()
    tpl = db.add_template(
        "All",
        TemplateMember("U8",   dt.USINT),
        TemplateMember("U16",  dt.UINT),
        TemplateMember("U32",  dt.UDINT),
        TemplateMember("U64",  dt.ULINT),
        TemplateMember("B8",   dt.BYTE),
        TemplateMember("W16",  dt.WORD),
        TemplateMember("LW64", dt.LWORD),
    )
    offsets = {m.name: m.byte_offset for m in tpl.members}
    assert offsets["U8"]   == 0
    assert offsets["U16"]  == 2
    assert offsets["U32"]  == 4
    assert offsets["U64"]  == 8
    assert offsets["B8"]   == 16
    assert offsets["W16"]  == 18
    assert offsets["LW64"] == 24
    assert tpl.structure_size == 32


def test_persistence_round_trips_unsigned_and_bitstring_tags():
    db = TagDatabase()
    writes = {
        "u8":   (dt.USINT, '<B', 0xAB),
        "u16":  (dt.UINT,  '<H', 0xBEEF),
        "u32":  (dt.UDINT, '<I', 0xDEADBEEF),
        "u64":  (dt.ULINT, '<Q', 0xFEEDFACECAFEBABE),
        "b8":   (dt.BYTE,  '<B', 0xFF),
        "w16":  (dt.WORD,  '<H', 0xFFFE),
        "dw32": (dt.DWORD, '<I', 0x11223344),
        "lw64": (dt.LWORD, '<Q', 0x1122334455667788),
    }
    for name, (code, fmt, value) in writes.items():
        db.add_tag(name, code).set_data(struct.pack(fmt, value))

    buf = io.BytesIO()
    save(db, buf)

    db2 = TagDatabase()
    for name, (code, _, _) in writes.items():
        db2.add_tag(name, code)

    buf.seek(0)
    result = load(db2, buf)
    assert result.tags_restored == 8
    assert result.tags_skipped == 0
    for name, (_, fmt, expected) in writes.items():
        actual = struct.unpack_from(fmt, db2.find_by_name(name).get_data(), 0)[0]
        assert actual == expected, f"{name}: expected {expected:x}, got {actual:x}"


def test_dispatcher_write_udint_accepts_udint_type_code():
    """End-to-end: writing with tag_type=0x00C8 against a UDINT-registered
    tag must succeed and the bytes must land verbatim."""
    db = TagDatabase()
    tag = db.add_tag("counter", dt.UDINT)
    logix = LogixDispatcher(tags=db)

    path = CipPath(symbolic_name="counter")
    payload = struct.pack('<HHI', dt.UDINT, 1, 0xFFFFFFFF)
    resp = logix.dispatch(WRITE_TAG, path, payload)
    assert resp.status.is_success, f"status=0x{resp.status.general_status:02X}"
    assert struct.unpack_from('<I', tag.get_data(), 0)[0] == 0xFFFFFFFF
