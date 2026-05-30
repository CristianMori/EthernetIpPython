"""Logix controller tag — data buffer with change notifications."""

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
                 element_size: int, element_count: int = 1):
        self.instance_id = instance_id
        self.name = name
        self.symbol_type = symbol_type
        self.tag_type = tag_type
        self.element_size = element_size
        self.element_count = element_count
        self._data = bytearray(element_size * element_count)
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

    def _fire_changed(self, offset: int, length: int) -> None:
        info = TagChangeInfo(offset, length)
        for cb in self.on_value_changed:
            cb(self, info)

    def __repr__(self) -> str:
        return f"{self.name} ({self.element_count}x{self.element_size}B, type=0x{self.tag_type:04X})"
