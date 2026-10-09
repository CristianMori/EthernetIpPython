"""Helpers for computing a Logix-style structure handle (the 16-bit value
Template Object attribute 1 returns and the client sends as the
``tag_type`` on struct ``Read_Tag`` / ``Write_Tag``).

**Status: provisional.** Mirrors the C# ``LogixStructureHandle`` helper and
the Rust ``logix_structure_handle`` module: build the FormalStrucTypeSpec
byte stream from a :class:`~ethernetip.logix.tag_database.TemplateDefinition`
per CIP Vol 1 §C-6.1 / §C-6.2.1 and hash it with the CIP 16-bit CRC
(:func:`ethernetip.cip.cip_crc.crc16`, polynomial 0xA001).

The algorithm has *not* been validated against a captured Studio 5000
``Read_Template`` reply for a non-trivial UDT, so callers who want this
value opt in — :meth:`TagDatabase.add_template` still assigns the
default ``0x8000 | instance_id`` handle. Scope today is UDTs whose
members are all scalar atomic types: nested structs, arrays, and packed
scalar BOOLs each return ``None`` so the server never ships a
plausible-but-unverified handle on the wire.
"""
from __future__ import annotations

from ..cip.cip_crc import crc16
from .tag_database import TemplateDefinition

# CIP Vol 1 §C-6.2.1 Table C-6.3 constants for the FormalStrucTypeSpec:
#
#   [0xA2][length][type_code_1][type_code_2]...[type_code_N]
#
# ``length`` counts the type_code bytes that follow (so the structure's
# on-wire size is ``2 + length``). Each atomic type is a single byte.
_FORMAL_STRUCT_PREFIX = 0xA2

# Known single-byte atomic type codes. Any member outside this set means
# the simple encoding cannot describe the layout — refuse rather than
# ship a wrong handle.
_ATOMIC_RANGES = (
    range(0xC1, 0xCC),  # BOOL(C1) .. ULINT(C9), REAL(CA), LREAL(CB)
    range(0xD1, 0xD5),  # BYTE(D1), WORD(D2), DWORD(D3), LWORD(D4)
)


def _is_known_atomic(code: int) -> bool:
    base = code & 0x00FF
    return any(base in r for r in _ATOMIC_RANGES)


def try_build_formal_struc_spec(template: TemplateDefinition) -> bytes | None:
    """Build the FormalStrucTypeSpec byte stream for a UDT whose members
    are all scalar atomic types. Return ``None`` for anything else.
    """
    type_codes: list[int] = []
    for m in template.members:
        # Arrays — out of scope. array_size on scalar members is 0 or 1
        # (depending on how the member was added); only > 1 means a real
        # array.
        if m.array_size > 1:
            return None
        # Nested struct — out of scope. data_type's high bit flags it.
        if (m.data_type & 0x8000) != 0:
            return None
        # Scalar BOOLs packed into a host byte: data_type is 0x00C1 and
        # element_size == 0 (array_size then carries the bit position
        # 0..7). The simple formal encoding can't represent that;
        # refuse rather than ship a plausible wrong handle.
        if m.data_type == 0x00C1 and m.element_size == 0:
            return None
        if not _is_known_atomic(m.data_type):
            return None
        type_codes.append(m.data_type & 0x00FF)

    if not type_codes or len(type_codes) > 0xFF:
        return None

    return bytes([_FORMAL_STRUCT_PREFIX, len(type_codes), *type_codes])


def try_compute_structure_handle(template: TemplateDefinition) -> int | None:
    """Compute the structure handle for an atomic-only UDT by hashing
    its FormalStrucTypeSpec with the CIP 16-bit CRC. Return ``None`` when
    :func:`try_build_formal_struc_spec` rejects the template.
    """
    spec = try_build_formal_struc_spec(template)
    if spec is None:
        return None
    return crc16(spec)
