"""Common Packet Format (CPF) — item type IDs, parsing, and writing."""

from __future__ import annotations
import struct
from dataclasses import dataclass
from enum import IntEnum


class CpfItemType(IntEnum):
    NULL_ADDRESS = 0x0000
    CIP_IDENTITY = 0x000C
    CONNECTED_ADDRESS = 0x00A1
    CONNECTED_DATA = 0x00B1
    UNCONNECTED_DATA = 0x00B2
    LIST_SERVICES_RESPONSE = 0x0100
    SOCKADDR_INFO_OT = 0x8000
    SOCKADDR_INFO_TO = 0x8001
    SEQUENCED_ADDRESS = 0x8002


@dataclass(frozen=True)
class CpfItem:
    type_id: CpfItemType
    data: bytes = b''


def parse_cpf(data: bytes | bytearray | memoryview) -> list[CpfItem]:
    """Parse CPF items from bytes. Returns empty list if data is too short."""
    if len(data) < 2:
        return []

    item_count = struct.unpack_from('<H', data, 0)[0]
    items: list[CpfItem] = []
    offset = 2

    for _ in range(item_count):
        if offset + 4 > len(data):
            break
        type_id, length = struct.unpack_from('<HH', data, offset)
        offset += 4
        if offset + length > len(data):
            break
        items.append(CpfItem(
            type_id=CpfItemType(type_id),
            data=bytes(data[offset:offset + length]),
        ))
        offset += length

    return items


def write_cpf(dst: bytearray, offset: int, items: list[CpfItem]) -> int:
    """Write CPF items to buffer. Returns bytes written."""
    pos = offset
    struct.pack_into('<H', dst, pos, len(items))
    pos += 2

    for item in items:
        struct.pack_into('<HH', dst, pos, int(item.type_id), len(item.data))
        pos += 4
        dst[pos:pos + len(item.data)] = item.data
        pos += len(item.data)

    return pos - offset


def encode_cpf(items: list[CpfItem]) -> bytes:
    """Encode CPF items to bytes. Convenience wrapper."""
    size = 2 + sum(4 + len(item.data) for item in items)
    buf = bytearray(size)
    write_cpf(buf, 0, items)
    return bytes(buf)
