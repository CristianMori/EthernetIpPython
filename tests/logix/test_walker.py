"""Walker unit tests — mirrors the C# TagPathWalker tests."""

from __future__ import annotations

from ethernetip.cip.path import ElementPathSegment, SymbolicPathSegment
from ethernetip.logix.tag_database import TagDatabase, TemplateMember
from ethernetip.logix import data_types as dt
from ethernetip.logix.walker import walk


def _timer_db():
    db = TagDatabase()
    tpl = db.add_template(
        "Timer",
        TemplateMember("PRE", dt.DINT),
        TemplateMember("ACC", dt.DINT),
        TemplateMember("EN", dt.BOOL),
        TemplateMember("TT", dt.BOOL),
        TemplateMember("DN", dt.BOOL),
    )
    tag = db.add_struct_tag("t1", tpl)
    return db, tpl, tag


def test_scalar_member_offset():
    db, _, tag = _timer_db()
    result, err = walk(tag, [SymbolicPathSegment("ACC")], db)
    assert err is None, err
    assert result.offset == 4
    assert result.type_code == dt.DINT


def test_bool_member_bit_position():
    # Reset template so BOOL packing is unambiguous (bit_pos comes from
    # the walker's stored info). The default add_template above packs BOOLs
    # into a hidden host but writes `info=0` for a scalar BOOL member — so
    # rebuild the walker path to use a pre-resolved template that puts EN,
    # TT, DN at bits 0/1/2 of the host byte at offset 8.
    from ethernetip.logix.tag_database import TemplateDefinition, TemplateMemberInfo
    db = TagDatabase()
    tpl = TemplateDefinition(
        instance_id=0x200, name="Timer", struct_handle=0x8200,
        member_count=3, structure_size=12,
        members=[
            TemplateMemberInfo("PRE", dt.DINT, 1, 0, 4, 0),
            TemplateMemberInfo("ACC", dt.DINT, 1, 4, 4, 0),
            TemplateMemberInfo("EN", dt.BOOL, 1, 8, 0, 0),
            TemplateMemberInfo("TT", dt.BOOL, 1, 8, 0, 1),
            TemplateMemberInfo("DN", dt.BOOL, 1, 8, 0, 2),
        ],
    )
    db.add_template_prebuilt(tpl)
    tag = db.add_struct_tag("t1", tpl)
    result, err = walk(tag, [SymbolicPathSegment("DN")], db)
    assert err is None, err
    assert result.offset == 8
    assert result.bit_pos == 2


def test_multi_dim_row_major():
    db = TagDatabase()
    db.add_tag("m", dt.DINT, dims=(5, 10, 4))
    tag = db.find_by_name("m")
    result, err = walk(tag, [ElementPathSegment(1), ElementPathSegment(2), ElementPathSegment(3)], db)
    assert err is None
    assert result.offset == 204   # ((1*10+2)*4+3)*4


def test_under_indexed_errors():
    db = TagDatabase()
    db.add_tag("m", dt.DINT, dims=(5, 10, 4))
    tag = db.find_by_name("m")
    result, err = walk(tag, [ElementPathSegment(1), ElementPathSegment(2)], db)
    assert result is None
    assert "under-indexed" in err


def test_bool_array_bit_indexing():
    db = TagDatabase()
    db.add_tag("flags", dt.BOOL, element_count=32)
    tag = db.find_by_name("flags")
    result, err = walk(tag, [ElementPathSegment(5)], db)
    assert err is None
    assert result.offset == 0
    assert result.bit_pos == 5


def test_bool_array_across_dword_boundary():
    db = TagDatabase()
    db.add_tag("big", dt.BOOL, element_count=128)
    tag = db.find_by_name("big")
    result, err = walk(tag, [ElementPathSegment(65)], db)
    assert err is None
    assert result.offset == 8
    assert result.bit_pos == 1


def test_bool_array_non_multiple_of_32_rejected():
    db = TagDatabase()
    import pytest
    with pytest.raises(ValueError, match="multiple of 32"):
        db.add_tag("bad", dt.BOOL, element_count=10)
