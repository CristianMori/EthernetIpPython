"""Tests for the FormalStrucTypeSpec + CRC-16 structure handle helper.

Mirrors the C# LogixStructureHandleTests and the Rust
logix_structure_handle module tests. Shipped behavior is opt-in: the
helper computes a plausible handle for atomic-only UDTs and returns
``None`` for anything else, and TagDatabase.add_template is unchanged.
"""
from __future__ import annotations

from ethernetip.logix.logix_structure_handle import (
    try_build_formal_struc_spec,
    try_compute_structure_handle,
)
from ethernetip.logix.tag_database import (
    TagDatabase,
    TemplateDefinition,
    TemplateMemberInfo,
)


def _mk_scalar_tpl(name: str, member_codes: list[tuple[str, int]]) -> TemplateDefinition:
    """Make a TemplateDefinition out of ``(name, data_type)`` pairs with
    plausible offsets/sizes. The helper doesn't look at offset / size, so
    the exact numbers don't matter — only the data_type field does."""
    return TemplateDefinition(
        instance_id=0x100,
        name=name,
        struct_handle=0x8100,
        member_count=len(member_codes),
        structure_size=0,
        members=[
            TemplateMemberInfo(
                name=n, data_type=code, array_size=1,
                byte_offset=0, element_size=1, info=0,
            )
            for n, code in member_codes
        ],
    )


def test_three_atomic_members_match_spec_example_bytes():
    # CIP Vol 1 §C-6.1 Example 3: STRUCT ::= { UINT, SINT, INT } encodes
    # as [A2][03][C7][C2][C3]. Hashing it should give the spec's quoted
    # 0x5159.
    tpl = _mk_scalar_tpl("Three", [("A", 0xC7), ("B", 0xC2), ("C", 0xC3)])
    assert try_build_formal_struc_spec(tpl) == bytes([0xA2, 0x03, 0xC7, 0xC2, 0xC3])


def test_spec_example_crc_is_0x5159():
    tpl = _mk_scalar_tpl("Three", [("A", 0xC7), ("B", 0xC2), ("C", 0xC3)])
    assert try_compute_structure_handle(tpl) == 0x5159


def test_unsigned_and_bitstring_members_encode_as_expected_bytes():
    tpl = _mk_scalar_tpl("Mixed", [("U32", 0xC8), ("U8", 0xC6), ("W", 0xD2)])
    assert try_build_formal_struc_spec(tpl) == bytes([0xA2, 0x03, 0xC8, 0xC6, 0xD2])


def test_packed_bool_member_refused():
    # Scalar BOOL packed into a host byte: data_type == 0x00C1,
    # element_size == 0 (array_size then carries the bit position).
    # The simple formal encoding cannot represent that; refuse rather
    # than ship a plausible wrong handle.
    tpl = TemplateDefinition(
        instance_id=0x200,
        name="WithBool",
        struct_handle=0x8200,
        member_count=2,
        structure_size=12,
        members=[
            TemplateMemberInfo(
                name="A", data_type=0x00C4, array_size=1,
                byte_offset=0, element_size=4, info=0,
            ),
            TemplateMemberInfo(
                name="B", data_type=0x00C1, array_size=0,
                byte_offset=8, element_size=0, info=0,
            ),
        ],
    )
    assert try_build_formal_struc_spec(tpl) is None


def test_array_member_refused():
    tpl = TemplateDefinition(
        instance_id=0x300,
        name="WithArray",
        struct_handle=0x8300,
        member_count=1,
        structure_size=16,
        members=[
            TemplateMemberInfo(
                name="Buf", data_type=0x00C2, array_size=16,
                byte_offset=0, element_size=1, info=16,
            ),
        ],
    )
    assert try_build_formal_struc_spec(tpl) is None


def test_nested_struct_member_refused():
    tpl = TemplateDefinition(
        instance_id=0x400,
        name="WithNested",
        struct_handle=0x8400,
        member_count=1,
        structure_size=4,
        members=[
            TemplateMemberInfo(
                name="Inner", data_type=0x8ABC, array_size=1,
                byte_offset=0, element_size=4, info=0,
            ),
        ],
    )
    assert try_build_formal_struc_spec(tpl) is None


def test_add_template_default_handle_still_structure_handle_only():
    # Explicit regression guard: TagDatabase.add_template must NOT flip
    # to the computed CRC-16 handle silently. The helper is opt-in only;
    # callers who want it call try_compute_structure_handle themselves.
    from ethernetip.logix.tag_database import TemplateMember

    db = TagDatabase()
    tpl = db.add_template(
        "Three",
        TemplateMember(name="A", data_type=0xC7),
        TemplateMember(name="B", data_type=0xC2),
        TemplateMember(name="C", data_type=0xC3),
    )
    assert tpl.struct_handle != 0x5159
