"""CIP EPATH parser — logical segments, symbolic segments, and raw path bytes."""

from __future__ import annotations
import struct
from dataclasses import dataclass, field


# Segment type constants
_SEGMENT_TYPE_MASK = 0xE0
_LOGICAL_SEGMENT = 0x20
_SYMBOLIC_SEGMENT_BYTE = 0x91  # ANSI Extended Symbolic

# Logical segment type (bits 4-2)
_LOGICAL_TYPE_MASK = 0x1C
_LOGICAL_TYPE_CLASS = 0x00
_LOGICAL_TYPE_INSTANCE = 0x04
_LOGICAL_TYPE_ELEMENT = 0x08
_LOGICAL_TYPE_CONN_POINT = 0x0C
_LOGICAL_TYPE_ATTRIBUTE = 0x10

# Logical segment format (bits 1-0)
_LOGICAL_FORMAT_MASK = 0x03
_LOGICAL_FORMAT_8BIT = 0x00
_LOGICAL_FORMAT_16BIT = 0x01
_LOGICAL_FORMAT_32BIT = 0x02


@dataclass(frozen=True)
class CipPath:
    class_id: int | None = None
    instance_id: int | None = None
    attribute_id: int | None = None
    connection_point: int | None = None
    element_id: int | None = None
    symbolic_name: str | None = None
    raw_path: bytes | None = None

    @staticmethod
    def parse(data: bytes | bytearray | memoryview) -> tuple[CipPath, int]:
        """Parse an EPATH from bytes. Returns (path, bytes_consumed)."""
        class_id = None
        instance_id = None
        attribute_id = None
        connection_point = None
        element_id = None
        symbolic_parts: list[str] = []
        offset = 0

        while offset < len(data):
            seg_byte = data[offset]

            # ANSI Extended Symbolic Segment (0x91)
            if seg_byte == _SYMBOLIC_SEGMENT_BYTE:
                offset += 1
                char_count = data[offset]
                offset += 1
                name = bytes(data[offset:offset + char_count]).decode('ascii')
                offset += char_count
                if char_count % 2 != 0:
                    offset += 1  # pad to word boundary
                symbolic_parts.append(name)
                continue

            seg_type = seg_byte & _SEGMENT_TYPE_MASK

            if seg_type == _LOGICAL_SEGMENT:
                logical_type = seg_byte & _LOGICAL_TYPE_MASK
                fmt = seg_byte & _LOGICAL_FORMAT_MASK
                offset += 1

                if fmt == _LOGICAL_FORMAT_8BIT:
                    value = data[offset]
                    offset += 1
                elif fmt == _LOGICAL_FORMAT_16BIT:
                    if offset % 2 != 0:
                        offset += 1
                    value = struct.unpack_from('<H', data, offset)[0]
                    offset += 2
                elif fmt == _LOGICAL_FORMAT_32BIT:
                    if offset % 2 != 0:
                        offset += 1
                    value = struct.unpack_from('<I', data, offset)[0]
                    offset += 4
                else:
                    break  # unknown format

                match logical_type:
                    case 0x00:  # class
                        class_id = value
                    case 0x04:  # instance
                        instance_id = value
                    case 0x10:  # attribute
                        attribute_id = value
                    case 0x0C:  # connection point
                        connection_point = value
                    case 0x08:  # element
                        element_id = value
            else:
                break  # unknown segment type

        symbolic_name = '.'.join(symbolic_parts) if symbolic_parts else None

        path = CipPath(
            class_id=class_id,
            instance_id=instance_id,
            attribute_id=attribute_id,
            connection_point=connection_point,
            element_id=element_id,
            symbolic_name=symbolic_name,
            raw_path=bytes(data[:offset]),
        )
        return path, offset

    @staticmethod
    def encode_logical_8(dst: bytearray, offset: int, logical_type: int, value: int) -> int:
        """Encode an 8-bit logical segment. Returns 2 (bytes written)."""
        dst[offset] = _LOGICAL_SEGMENT | logical_type | _LOGICAL_FORMAT_8BIT
        dst[offset + 1] = value
        return 2

    def __str__(self) -> str:
        parts = []
        if self.symbolic_name is not None:
            parts.append(f'Sym="{self.symbolic_name}"')
        if self.class_id is not None:
            parts.append(f'Class=0x{self.class_id:02X}')
        if self.instance_id is not None:
            parts.append(f'Instance={self.instance_id}')
        if self.attribute_id is not None:
            parts.append(f'Attr={self.attribute_id}')
        if self.connection_point is not None:
            parts.append(f'ConnPt={self.connection_point}')
        if self.element_id is not None:
            parts.append(f'Elem={self.element_id}')
        return ', '.join(parts)
