"""TagDatabase persistence — cross-port binary format tests."""

from __future__ import annotations
import io
import struct

import pytest

from ethernetip.logix import data_types as dt
from ethernetip.logix.persistence import load, save
from ethernetip.logix.tag_database import TagDatabase


def _make_schema() -> TagDatabase:
    db = TagDatabase()
    db.add_tag("rate", dt.DINT)
    db.add_tag("arr", dt.DINT, element_count=8)
    db.add_tag("flags", dt.BOOL, element_count=32)
    return db


def test_round_trip_preserves_values():
    db = _make_schema()
    struct.pack_into('<i', db.find_by_name("rate")._data, 0, 12345)
    for i in range(8):
        struct.pack_into('<i', db.find_by_name("arr")._data, i * 4, 100 + i)
    db.find_by_name("flags")._data[:] = bytes([0xAB, 0xCD, 0xEF, 0x12])

    buf = io.BytesIO()
    save(db, buf)

    db2 = _make_schema()
    buf.seek(0)
    result = load(db2, buf)

    assert result.tags_restored == 3
    assert result.tags_skipped == 0
    assert struct.unpack_from('<i', db2.find_by_name("rate")._data, 0)[0] == 12345
    assert bytes(db2.find_by_name("flags")._data) == bytes([0xAB, 0xCD, 0xEF, 0x12])


def test_program_scope_round_trip():
    db = TagDatabase()
    db.add_tag("controller_tag", dt.DINT)
    struct.pack_into('<i', db.find_by_name("controller_tag")._data, 0, 111)
    db.register_program("Cell")
    db.add_program_tag("Cell", "Rate", dt.DINT)
    struct.pack_into('<i', db.find_program_tag("Cell", "Rate")._data, 0, 222)

    buf = io.BytesIO()
    save(db, buf)

    db2 = TagDatabase()
    db2.add_tag("controller_tag", dt.DINT)
    db2.register_program("Cell")
    db2.add_program_tag("Cell", "Rate", dt.DINT)

    buf.seek(0)
    result = load(db2, buf)
    assert result.tags_restored == 2
    assert struct.unpack_from('<i', db2.find_program_tag("Cell", "Rate")._data, 0)[0] == 222


def test_missing_tag_skipped():
    db = _make_schema()
    buf = io.BytesIO()
    save(db, buf)

    db2 = TagDatabase()
    db2.add_tag("rate", dt.DINT)  # arr and flags missing

    buf.seek(0)
    result = load(db2, buf)
    assert result.tags_restored == 1
    assert result.tags_skipped == 2
    assert any("'arr'" in w for w in result.warnings)


def test_type_mismatch_skipped():
    db = TagDatabase()
    db.add_tag("x", dt.DINT)
    struct.pack_into('<i', db.find_by_name("x")._data, 0, 42)
    buf = io.BytesIO()
    save(db, buf)

    db2 = TagDatabase()
    db2.add_tag("x", dt.REAL)
    buf.seek(0)
    result = load(db2, buf)
    assert result.tags_skipped == 1
    assert any("mismatch" in w for w in result.warnings)


def test_bad_magic_raises():
    db = TagDatabase()
    with pytest.raises(ValueError):
        load(db, io.BytesIO(b"\x00" * 8))


def test_future_version_raises():
    db = TagDatabase()
    payload = b"EIPS" + bytes([99, 0, 0, 0]) + struct.pack('<I', 0) + struct.pack('<I', 0)
    with pytest.raises(ValueError):
        load(db, io.BytesIO(payload))


def test_load_is_silent():
    db = _make_schema()
    struct.pack_into('<i', db.find_by_name("rate")._data, 0, 42)
    buf = io.BytesIO()
    save(db, buf)

    db2 = _make_schema()
    fired = []
    db2.on_any_tag_changed.append(lambda t, i: fired.append(t.name))

    buf.seek(0)
    load(db2, buf)
    assert fired == []
