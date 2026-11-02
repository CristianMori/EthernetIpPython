"""Coverage for the CIP SHORT_STRING atomic type (0xDA) as a Logix tag type.

SHORT_STRING (CIP Vol 1 §C-6.3) is one USINT length byte followed by ASCII
chars.  Distinct from the predefined Logix STRING UDT (which is a structure
with LEN:DINT + DATA:SINT[82]) and distinct from CIP STRING (0xD0, UINT
length).  Logix controllers do not expose application tags as SHORT_STRING,
but a Logix-shaped symbol service can serve one.

Based on the exploration in PR #1 (SRCthird) against the C# port; narrowed
to just the atomic SHORT_STRING feature so it does not collide with the
UDT STRING handling.
"""

import struct

import pytest

from ethernetip.logix import data_types as dt
from ethernetip.logix import tag_services as ts
from ethernetip.logix.tag_database import TagDatabase


def test_metadata_short_string_element_is_81_bytes():
    assert dt.get_element_size(dt.SHORT_STRING) == 81
    assert dt.SHORT_STRING_STORAGE_SIZE == 81
    assert dt.SHORT_STRING_MAX_LENGTH == 80


def test_add_tag_short_string_atomic_has_expected_layout():
    db = TagDatabase()
    tag = db.add_tag("name", dt.SHORT_STRING)

    assert tag.is_sstring
    assert tag.element_size == 81
    assert tag.element_count == 1
    assert tag.data_size == 81


def test_add_tag_short_string_array_sizes_in_81_byte_slots():
    db = TagDatabase()
    tag = db.add_tag("names", dt.SHORT_STRING, element_count=4)

    assert tag.element_count == 4
    assert tag.element_size == 81
    assert tag.data_size == 4 * 81


# ---------- Helper round-trip ----------

def test_write_sstring_read_back_matches():
    db = TagDatabase()
    tag = db.add_tag("asset", dt.SHORT_STRING)

    tag.write_sstring("Asset-32")

    assert tag.read_sstring() == "Asset-32"
    assert tag.get_data(0, 1)[0] == len("Asset-32")


def test_write_sstring_array_element_isolates_from_neighbors():
    db = TagDatabase()
    tag = db.add_tag("names", dt.SHORT_STRING, element_count=3)

    tag.write_sstring("first", element_index=0)
    tag.write_sstring("second-is-longer", element_index=1)
    tag.write_sstring("third", element_index=2)

    assert tag.read_sstring(0) == "first"
    assert tag.read_sstring(1) == "second-is-longer"
    assert tag.read_sstring(2) == "third"


def test_write_sstring_shorter_over_longer_clears_trailing_bytes():
    db = TagDatabase()
    tag = db.add_tag("asset", dt.SHORT_STRING)

    tag.write_sstring("x" * 40)
    tag.write_sstring("hi")

    assert tag.read_sstring() == "hi"
    # From position 3 to end should be all zeros (no leftover 'x').
    for i in range(3, tag.data_size):
        assert tag.get_data(i, 1)[0] == 0


def test_write_sstring_rejects_over_max_length():
    db = TagDatabase()
    tag = db.add_tag("asset", dt.SHORT_STRING)

    with pytest.raises(ValueError, match="SHORT_STRING"):
        tag.write_sstring("x" * (dt.SHORT_STRING_MAX_LENGTH + 1))


def test_write_sstring_rejects_non_ascii():
    db = TagDatabase()
    tag = db.add_tag("asset", dt.SHORT_STRING)

    with pytest.raises(ValueError):
        tag.write_sstring("café")


def test_read_sstring_on_non_short_string_tag_raises():
    db = TagDatabase()
    tag = db.add_tag("rate", dt.DINT)

    with pytest.raises(ValueError):
        tag.read_sstring()


def test_write_sstring_out_of_range_element_raises():
    db = TagDatabase()
    tag = db.add_tag("names", dt.SHORT_STRING, element_count=2)

    with pytest.raises(IndexError):
        tag.write_sstring("nope", element_index=5)


# ---------- CIP wire shape ----------

def test_handle_read_tag_short_string_emits_two_byte_atomic_prefix():
    db = TagDatabase()
    tag = db.add_tag("asset", dt.SHORT_STRING)
    tag.write_sstring("Asset-32")

    resp = ts.handle_read_tag(tag, ts.READ_TAG, b"\x01\x00")

    assert resp.status.is_success
    data = bytes(resp.data)
    # Atomic prefix is 2 bytes (SHORT_STRING is NOT a structure, so no 0x02A0).
    assert len(data) == 2 + dt.SHORT_STRING_STORAGE_SIZE
    type_code = struct.unpack_from('<H', data, 0)[0]
    assert type_code == dt.SHORT_STRING
    # Length byte then ASCII chars.
    assert data[2] == len("Asset-32")
    assert data[3:3 + len("Asset-32")].decode('ascii') == "Asset-32"


def test_handle_write_tag_short_string_accepts_atomic_header():
    db = TagDatabase()
    tag = db.add_tag("asset", dt.SHORT_STRING)

    # Atomic Write_Tag header: [type:UINT][count:UINT][payload...]
    value = "Asset-32"
    payload = bytearray(dt.SHORT_STRING_STORAGE_SIZE)
    payload[0] = len(value)
    payload[1:1 + len(value)] = value.encode('ascii')
    req = struct.pack('<HH', dt.SHORT_STRING, 1) + bytes(payload)

    resp = ts.handle_write_tag(tag, ts.WRITE_TAG, req)

    assert resp.status.is_success
    assert tag.read_sstring() == "Asset-32"


def test_handle_write_tag_wrong_type_code_rejected():
    db = TagDatabase()
    tag = db.add_tag("asset", dt.SHORT_STRING)

    # Send a mismatched tag type (DINT instead of SHORT_STRING).
    req = struct.pack('<HH', dt.DINT, 1) + b'\x00' * dt.SHORT_STRING_STORAGE_SIZE

    resp = ts.handle_write_tag(tag, ts.WRITE_TAG, req)

    assert not resp.status.is_success
    assert resp.status.general_status == 0xFF
    assert 0x2107 in resp.status.additional_status
