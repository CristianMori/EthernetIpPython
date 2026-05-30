"""CIP attribute — a typed, access-controlled value identified by numeric ID."""

from __future__ import annotations
import struct
from enum import IntFlag

from .data_types import CipDataType
from . import data_serializer as ds


class AttributeAccess(IntFlag):
    NONE = 0
    GET_SINGLE = 1   # Readable via GetAttributeSingle (0x0E)
    SET_SINGLE = 2   # Writable via SetAttributeSingle (0x10)
    GET_ALL = 4      # Included in GetAttributeAll (0x01) response
    ALL = GET_SINGLE | SET_SINGLE | GET_ALL


class CipAttribute:
    """A single CIP attribute with typed data and access control.

    Data is stored as a raw bytearray in wire format (little-endian).
    Subclassable — e.g. AssemblyDataAttribute backs the attribute with a live I/O buffer.
    """

    def __init__(self, attr_id: int, data_type: CipDataType, access: AttributeAccess,
                 initial_data: bytes | bytearray):
        self.id = attr_id
        self.data_type = data_type
        self.access = access
        self._data = bytearray(initial_data)

    @property
    def data(self) -> memoryview:
        return memoryview(self._data)

    @property
    def data_length(self) -> int:
        return len(self._data)

    def set_data(self, value: bytes | bytearray | memoryview) -> None:
        if len(value) != len(self._data):
            self._data = bytearray(len(value))
        self._data[:] = value

    def encode_to(self, dst: bytearray, offset: int = 0) -> int:
        """Copy attribute data into dst at offset. Returns bytes written."""
        n = len(self._data)
        dst[offset:offset + n] = self._data
        return n

    # --- Factory methods ---

    @staticmethod
    def create_byte(attr_id: int, data_type: CipDataType, access: AttributeAccess,
                    value: int) -> CipAttribute:
        return CipAttribute(attr_id, data_type, access, bytes([value & 0xFF]))

    @staticmethod
    def create_uint(attr_id: int, data_type: CipDataType, access: AttributeAccess,
                    value: int) -> CipAttribute:
        data = bytearray(2)
        ds.write_uint(data, 0, value)
        return CipAttribute(attr_id, data_type, access, data)

    @staticmethod
    def create_udint(attr_id: int, data_type: CipDataType, access: AttributeAccess,
                     value: int) -> CipAttribute:
        data = bytearray(4)
        ds.write_udint(data, 0, value)
        return CipAttribute(attr_id, data_type, access, data)

    @staticmethod
    def create_short_string(attr_id: int, access: AttributeAccess,
                            value: str) -> CipAttribute:
        data = bytearray(1 + len(value))
        ds.write_short_string(data, 0, value)
        return CipAttribute(attr_id, CipDataType.SHORT_STRING, access, data)
