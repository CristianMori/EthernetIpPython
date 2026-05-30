"""Logical EPATH builder for CIP requests.

Each field picks the smallest logical-segment format that fits:
  8-bit  (value <= 0xFF)         — 2 bytes
  16-bit (value <= 0xFFFF)       — 4 bytes (segment + pad + LE value)
  32-bit (value <= 0xFFFFFFFF)   — 6 bytes (segment + pad + LE value)
Empty (None) optionals are skipped, so the helper covers class-only and
class+instance paths as well.
"""
from __future__ import annotations

import struct


# Logical segment format byte = 001 LLL FF (LLL = type, FF = format).
_CLASS  = (0x20, 0x21, 0x22)
_INST   = (0x24, 0x25, 0x26)
_ATTR   = (0x30, 0x31, 0x32)
_ELEM   = (0x28, 0x29, 0x2A)


def _emit(out: bytearray, value: int, segs: tuple[int, int, int]) -> None:
    if value <= 0xFF:
        out.append(segs[0])
        out.append(value)
    elif value <= 0xFFFF:
        out.append(segs[1])
        out.append(0)               # pad to word
        out.extend(struct.pack('<H', value))
    else:
        out.append(segs[2])
        out.append(0)               # pad
        out.extend(struct.pack('<I', value))


def build_path(class_id: int | None = None,
               instance_id: int | None = None,
               attribute_id: int | None = None,
               element_id: int | None = None) -> bytes:
    out = bytearray()
    if class_id    is not None: _emit(out, class_id,    _CLASS)
    if instance_id is not None: _emit(out, instance_id, _INST)
    if attribute_id is not None: _emit(out, attribute_id, _ATTR)
    if element_id  is not None: _emit(out, element_id,  _ELEM)
    return bytes(out)
