"""Regression tests for the Logix structured-tag wire contract.

CIP Vol 1 §C-4.4.5: struct reads/writes carry a 4-byte wire prefix
``[0x02A0][structure_handle]`` ahead of the data. libplctag and pycomm3
both enforce this split. Mirrors the C#/C++ port tests.
"""

from __future__ import annotations

import struct

from ethernetip.cip.path import SymbolicPathSegment
from ethernetip.logix import data_types as dt
from ethernetip.logix import tag_services as ts
from ethernetip.logix.tag import Tag
from ethernetip.logix.tag_database import (
    TagDatabase, TemplateDefinition, TemplateMember, TemplateMemberInfo,
)
from ethernetip.logix.walker import walk


STRUCT_TYPE_INDICATOR = 0x02A0


# ---------- Whole-tag path ----------

def test_handle_read_tag_struct_emits_four_byte_prefix():
    db = TagDatabase()
    tpl = db.add_template("Timer",
                          TemplateMember("PRE", dt.DINT),
                          TemplateMember("ACC", dt.DINT))
    tag = db.add_struct_tag("t1", tpl)
    tag.set_data(struct.pack("<ii", 123, 456))

    resp = ts.handle_read_tag(tag, ts.READ_TAG, b"\x01\x00")

    assert resp.status.is_success
    data = resp.data
    assert len(data) == 4 + tpl.structure_size
    assert struct.unpack_from("<H", data, 0)[0] == STRUCT_TYPE_INDICATOR
    assert struct.unpack_from("<H", data, 2)[0] == tpl.struct_handle
    assert struct.unpack_from("<i", data, 4)[0] == 123
    assert struct.unpack_from("<i", data, 8)[0] == 456


def test_handle_read_tag_atomic_stays_two_byte_prefix():
    tag = Tag(1, "rate",
              symbol_type=dt.make_atomic_symbol_type(dt.DINT),
              tag_type=dt.DINT, element_size=4, element_count=1)
    tag.set_data(struct.pack("<i", 42))

    resp = ts.handle_read_tag(tag, ts.READ_TAG, b"\x01\x00")

    assert resp.status.is_success
    data = resp.data
    assert len(data) == 6
    assert struct.unpack_from("<H", data, 0)[0] == dt.DINT
    assert struct.unpack_from("<i", data, 2)[0] == 42


def test_handle_write_tag_struct_accepts_six_byte_header():
    db = TagDatabase()
    tpl = db.add_template("Timer",
                          TemplateMember("PRE", dt.DINT),
                          TemplateMember("ACC", dt.DINT))
    tag = db.add_struct_tag("t1", tpl)

    req = (struct.pack("<HHH", STRUCT_TYPE_INDICATOR, tpl.struct_handle, 1)
           + struct.pack("<ii", 777, 888))

    resp = ts.handle_write_tag(tag, ts.WRITE_TAG, req)

    assert resp.status.is_success
    assert struct.unpack_from("<i", tag.get_data(0, 4), 0)[0] == 777
    assert struct.unpack_from("<i", tag.get_data(4, 4), 0)[0] == 888


def test_handle_write_tag_struct_wrong_indicator_rejected():
    db = TagDatabase()
    tpl = db.add_template("Timer", TemplateMember("PRE", dt.DINT))
    tag = db.add_struct_tag("t1", tpl)

    req = struct.pack("<HHH", 0x1234, tpl.struct_handle, 1) + b"\x00" * 4

    resp = ts.handle_write_tag(tag, ts.WRITE_TAG, req)

    assert not resp.status.is_success
    assert resp.status.general_status == 0xFF
    assert 0x2107 in resp.status.additional_status


def test_handle_write_tag_struct_wrong_handle_rejected():
    db = TagDatabase()
    tpl = db.add_template("Timer", TemplateMember("PRE", dt.DINT))
    tag = db.add_struct_tag("t1", tpl)

    req = (struct.pack("<HHH", STRUCT_TYPE_INDICATOR, tpl.struct_handle ^ 0xFFFF, 1)
           + b"\x00" * 4)

    resp = ts.handle_write_tag(tag, ts.WRITE_TAG, req)

    assert not resp.status.is_success
    assert resp.status.general_status == 0xFF
    assert 0x2107 in resp.status.additional_status


def test_handle_write_tag_atomic_still_accepts_four_byte_header():
    tag = Tag(1, "rate",
              symbol_type=dt.make_atomic_symbol_type(dt.DINT),
              tag_type=dt.DINT, element_size=4, element_count=1)

    req = struct.pack("<HHi", dt.DINT, 1, 99)
    resp = ts.handle_write_tag(tag, ts.WRITE_TAG, req)

    assert resp.status.is_success
    assert struct.unpack_from("<i", tag.get_data(0, 4), 0)[0] == 99


def test_handle_read_tag_fragmented_struct_emits_four_byte_prefix():
    # Need total > MaxReplyData so first fragment is partial.
    db = TagDatabase()
    members = [TemplateMember(f"m{i}", dt.DINT) for i in range(130)]
    tpl = db.add_template("BigUdt", *members)
    tag = db.add_struct_tag("big", tpl)

    req = struct.pack("<HI", 1, 0)
    resp = ts.handle_read_tag_fragmented(tag, ts.READ_TAG_FRAGMENTED, req)

    assert resp.service_code == ts.READ_TAG_FRAGMENTED | 0x80
    assert resp.status.general_status == 0x06
    assert struct.unpack_from("<H", resp.data, 0)[0] == STRUCT_TYPE_INDICATOR
    assert struct.unpack_from("<H", resp.data, 2)[0] == tpl.struct_handle


def test_handle_write_tag_fragmented_struct_accepts_ten_byte_header():
    db = TagDatabase()
    tpl = db.add_template("Timer",
                          TemplateMember("PRE", dt.DINT),
                          TemplateMember("ACC", dt.DINT))
    tag = db.add_struct_tag("t1", tpl)

    req = (struct.pack("<HHHI", STRUCT_TYPE_INDICATOR, tpl.struct_handle, 1, 4)
           + struct.pack("<i", 321))

    resp = ts.handle_write_tag_fragmented(tag, ts.WRITE_TAG_FRAGMENTED, req)

    assert resp.status.is_success
    assert struct.unpack_from("<i", tag.get_data(4, 4), 0)[0] == 321


# ---------- Walker-aware path ----------

def _motor_fixture():
    """Build Motor { Speed:REAL, Timer:Timer } with Timer as nested struct."""
    db = TagDatabase()
    timer_tpl = db.add_template("Timer",
                                TemplateMember("PRE", dt.DINT),
                                TemplateMember("ACC", dt.DINT))
    motor_tpl = TemplateDefinition(
        instance_id=0x301, name="Motor", struct_handle=0xBEEF,
        member_count=2, structure_size=4 + timer_tpl.structure_size,
        members=[
            TemplateMemberInfo("Speed", dt.REAL, 1, 0, 4, 0),
            TemplateMemberInfo("Timer",
                                0x8000 | timer_tpl.instance_id,
                                1, 4, timer_tpl.structure_size, 0),
        ],
    )
    db.add_template_prebuilt(motor_tpl)
    tag = db.add_struct_tag("m1", motor_tpl)
    return db, timer_tpl, motor_tpl, tag


def test_handle_read_tag_at_struct_member_emits_four_byte_prefix():
    db, timer_tpl, motor_tpl, tag = _motor_fixture()
    tag.set_data(struct.pack("<i", 11), 4)   # Timer.PRE
    tag.set_data(struct.pack("<i", 22), 8)   # Timer.ACC

    walked, err = walk(tag, [SymbolicPathSegment("Timer")], db)
    assert err is None, err

    resp = ts.handle_read_tag_at(tag, ts.READ_TAG, b"\x01\x00", walked)

    assert resp.status.is_success
    data = resp.data
    assert len(data) == 4 + timer_tpl.structure_size
    assert struct.unpack_from("<H", data, 0)[0] == STRUCT_TYPE_INDICATOR
    assert struct.unpack_from("<H", data, 2)[0] == timer_tpl.struct_handle
    assert struct.unpack_from("<i", data, 4)[0] == 11
    assert struct.unpack_from("<i", data, 8)[0] == 22


def test_handle_read_tag_at_atomic_member_stays_two_byte_prefix():
    db = TagDatabase()
    tpl = db.add_template("Timer",
                          TemplateMember("PRE", dt.DINT),
                          TemplateMember("ACC", dt.DINT))
    tag = db.add_struct_tag("t1", tpl)
    tag.set_data(struct.pack("<i", 777), 4)

    walked, err = walk(tag, [SymbolicPathSegment("ACC")], db)
    assert err is None, err

    resp = ts.handle_read_tag_at(tag, ts.READ_TAG, b"\x01\x00", walked)

    assert resp.status.is_success
    data = resp.data
    assert len(data) == 6
    assert struct.unpack_from("<H", data, 0)[0] == dt.DINT
    assert struct.unpack_from("<i", data, 2)[0] == 777


def test_handle_write_tag_at_struct_member_accepts_six_byte_header():
    db, timer_tpl, motor_tpl, tag = _motor_fixture()

    walked, err = walk(tag, [SymbolicPathSegment("Timer")], db)
    assert err is None, err

    req = (struct.pack("<HHH", STRUCT_TYPE_INDICATOR, timer_tpl.struct_handle, 1)
           + struct.pack("<ii", 555, 666))

    resp = ts.handle_write_tag_at(tag, ts.WRITE_TAG, req, walked)

    assert resp.status.is_success
    assert struct.unpack_from("<i", tag.get_data(4, 4), 0)[0] == 555
    assert struct.unpack_from("<i", tag.get_data(8, 4), 0)[0] == 666


def test_handle_write_tag_at_struct_member_wrong_handle_rejected():
    db, timer_tpl, motor_tpl, tag = _motor_fixture()

    walked, err = walk(tag, [SymbolicPathSegment("Timer")], db)
    assert err is None, err

    req = (struct.pack("<HHH", STRUCT_TYPE_INDICATOR,
                       timer_tpl.struct_handle ^ 0xFFFF, 1)
           + b"\x00" * timer_tpl.structure_size)

    resp = ts.handle_write_tag_at(tag, ts.WRITE_TAG, req, walked)

    assert not resp.status.is_success
    assert resp.status.general_status == 0xFF
    assert 0x2107 in resp.status.additional_status
