"""Edge case tests for Logix tag services."""

import struct
import pytest

from ethernetip.logix.logix_dispatcher import LogixDispatcher
from ethernetip.logix.tag_database import TagDatabase
from ethernetip.logix import data_types as dt
from ethernetip.cip.path import CipPath


def _make():
    tags = TagDatabase()
    tags.add_tag("TestDint", dt.DINT)
    tags.add_tag("TestArr", dt.DINT, element_count=100)
    return LogixDispatcher(tags), tags


def test_read_too_many_elements():
    d, tags = _make()
    path = CipPath(symbolic_name="TestDint")
    resp = d.dispatch(0x4C, path, struct.pack('<H', 100))  # 100 elements but tag has 1
    assert not resp.status.is_success


def test_write_wrong_type():
    d, tags = _make()
    path = CipPath(symbolic_name="TestDint")
    write_data = struct.pack('<HHi', dt.REAL, 1, 0)  # Wrong type
    resp = d.dispatch(0x4D, path, write_data)
    assert not resp.status.is_success


def test_write_insufficient_data():
    d, tags = _make()
    path = CipPath(symbolic_name="TestDint")
    resp = d.dispatch(0x4D, path, b'\xC4\x00')  # Only 2 bytes, need 4+
    assert not resp.status.is_success


def test_read_empty_data():
    d, tags = _make()
    path = CipPath(symbolic_name="TestDint")
    resp = d.dispatch(0x4C, path, b'')  # Empty data
    assert not resp.status.is_success


def test_fragmented_read():
    d, tags = _make()
    tag = tags.find_by_name("TestArr")
    for i in range(100):
        struct.pack_into('<i', tag._data, i * 4, i + 1)

    path = CipPath(symbolic_name="TestArr")
    # Read 100 elements starting at offset 0
    resp = d.dispatch(0x52, path, struct.pack('<HI', 100, 0))
    # Should succeed (may be partial if > 480 bytes)
    assert resp.data is not None
    # First value after tag_type should be 1
    assert struct.unpack_from('<i', resp.data, 2)[0] == 1


def test_read_modify_write():
    d, tags = _make()
    tag = tags.find_by_name("TestDint")
    tag.set_data(struct.pack('<I', 0xFF00FF00))

    path = CipPath(symbolic_name="TestDint")
    # mask_size=4, OR mask=0x000000FF, AND mask=0xFFFF00FF
    rmw_data = struct.pack('<H', 4) + struct.pack('<I', 0x000000FF) + struct.pack('<I', 0xFFFF00FF)
    resp = d.dispatch(0x4E, path, rmw_data)
    assert resp.status.is_success

    result = struct.unpack_from('<I', tag.get_data())[0]
    assert result == 0xFF0000FF


def test_case_insensitive_tag_lookup():
    d, tags = _make()
    tags.find_by_name("TestDint").set_data(struct.pack('<i', 77))

    path = CipPath(symbolic_name="testdint")
    resp = d.dispatch(0x4C, path, struct.pack('<H', 1))
    assert resp.status.is_success
    assert struct.unpack_from('<i', resp.data, 2)[0] == 77


def test_tag_change_notification():
    d, tags = _make()
    changes = []
    tags.on_any_tag_changed.append(lambda tag, info: changes.append(tag.name))

    path = CipPath(symbolic_name="TestDint")
    d.dispatch(0x4D, path, struct.pack('<HHi', dt.DINT, 1, 42))
    assert len(changes) == 1
    assert changes[0] == "TestDint"
