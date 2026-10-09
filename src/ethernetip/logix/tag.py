"""Logix controller tag — data buffer with change notifications.

Concurrency model mirrors the C# reference: scalar writes on aligned
offsets are effectively atomic on x86/x64, multi-scalar and struct reads
MAY tear if the scan-side writer races a CIP-side reader (that matches
how a real 1756 behaves; clients coordinate atomic reads themselves).
Do NOT wrap the hot read/write path in a lock — the transpiler-generated
scan writes 10⁵–10⁶ times per scan.
"""

from __future__ import annotations
import struct
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class TagChangeInfo:
    byte_offset: int
    byte_length: int


class Tag:
    """A single Logix controller tag with typed data and change notifications."""

    def __init__(self, instance_id: int, name: str, symbol_type: int, tag_type: int,
                 element_size: int, element_count: int = 1,
                 dims: tuple[int, ...] = (), data_size: int | None = None):
        self.instance_id = instance_id
        self.name = name
        self.symbol_type = symbol_type
        self.tag_type = tag_type
        self.element_size = element_size
        self.element_count = element_count
        # Array shape: empty for scalar, one entry for 1-D array, up to three
        # for a Logix multi-dimensional array like DINT[5,10,2].
        self.dims: tuple[int, ...] = dims if dims else ((element_count,) if element_count > 1 else ())
        # Template reference — populated by TagDatabase.add_struct_tag so a
        # view layer can walk member offsets without a second registry lookup.
        self.template = None
        if data_size is None:
            self._data = bytearray(element_size * element_count)
        else:
            self._data = bytearray(data_size)
        self.on_value_changed: list[Callable[[Tag, TagChangeInfo], None]] = []

    @property
    def data_size(self) -> int:
        return len(self._data)

    def get_data(self, offset: int = 0, length: int | None = None) -> bytes:
        if length is None:
            return bytes(self._data[offset:])
        return bytes(self._data[offset:offset + length])

    def read_dint(self, offset: int = 0) -> int:
        return struct.unpack_from('<i', self._data, offset)[0]

    def read_real(self, offset: int = 0) -> float:
        return struct.unpack_from('<f', self._data, offset)[0]

    def write_dint(self, offset: int, value: int) -> None:
        struct.pack_into('<i', self._data, offset, value)
        self._fire_changed(offset, 4)

    def write_real(self, offset: int, value: float) -> None:
        struct.pack_into('<f', self._data, offset, value)
        self._fire_changed(offset, 4)

    def set_data(self, source: bytes | bytearray | memoryview, byte_offset: int = 0) -> None:
        n = min(len(source), len(self._data) - byte_offset)
        self._data[byte_offset:byte_offset + n] = source[:n]
        self._fire_changed(byte_offset, n)

    def set_data_silent(self, source: bytes | bytearray | memoryview, byte_offset: int = 0) -> None:
        """Bulk write without firing on_value_changed. Gap 8 fast path."""
        n = min(len(source), len(self._data) - byte_offset)
        self._data[byte_offset:byte_offset + n] = source[:n]

    def write_dint_silent(self, offset: int, value: int) -> None:
        """Silent variant for the transpiler-generated scan hot path."""
        struct.pack_into('<i', self._data, offset, value)

    def atomic_set_bit(self, byte_offset: int, bit_pos: int, value: bool) -> None:
        """Set or clear a single bit at byte_offset. Python's GIL makes the
        single-byte |= / &= atomic; used by BOOL member writes so two writers
        to different bits of the same host byte can't stomp each other."""
        if not 0 <= bit_pos <= 7:
            raise ValueError(f"bit_pos {bit_pos} out of range")
        if not 0 <= byte_offset < len(self._data):
            raise IndexError(f"byte_offset {byte_offset} out of range")
        mask = 1 << bit_pos
        if value:
            self._data[byte_offset] |= mask
        else:
            self._data[byte_offset] &= (~mask) & 0xFF
        self._fire_changed(byte_offset, 1)

    def _fire_changed(self, offset: int, length: int) -> None:
        info = TagChangeInfo(offset, length)
        for cb in self.on_value_changed:
            cb(self, info)

    def __repr__(self) -> str:
        return f"{self.name} ({self.element_count}x{self.element_size}B, type=0x{self.tag_type:04X})"
