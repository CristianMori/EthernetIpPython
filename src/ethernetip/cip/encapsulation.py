"""EtherNet/IP encapsulation header — 24-byte codec for TCP port 44818."""

from __future__ import annotations
import struct
from dataclasses import dataclass
from enum import IntEnum


class EncapsulationCommand(IntEnum):
    NOP = 0x0000
    LIST_SERVICES = 0x0004
    LIST_IDENTITY = 0x0063
    LIST_INTERFACES = 0x0064
    REGISTER_SESSION = 0x0065
    UNREGISTER_SESSION = 0x0066
    SEND_RR_DATA = 0x006F
    SEND_UNIT_DATA = 0x0070


class EncapsulationStatus(IntEnum):
    SUCCESS = 0x0000
    INVALID_COMMAND = 0x0001
    INSUFFICIENT_MEMORY = 0x0002
    INCORRECT_DATA = 0x0003
    INVALID_SESSION_HANDLE = 0x0064
    INVALID_LENGTH = 0x0065
    UNSUPPORTED_PROTOCOL_VERSION = 0x0069


# Struct format: command(H) + length(H) + session(I) + status(I) + context(Q) + options(I) = 24 bytes
_HEADER_STRUCT = struct.Struct('<HHIIQI')
SIZE = 24


@dataclass
class EncapsulationHeader:
    command: EncapsulationCommand = EncapsulationCommand.NOP
    length: int = 0
    session_handle: int = 0
    status: EncapsulationStatus = EncapsulationStatus.SUCCESS
    sender_context: int = 0
    options: int = 0

    @staticmethod
    def parse(data: bytes | bytearray | memoryview) -> EncapsulationHeader:
        if len(data) < SIZE:
            raise ValueError(f"Encapsulation header requires {SIZE} bytes, got {len(data)}")
        cmd, length, session, status, context, options = _HEADER_STRUCT.unpack_from(data)
        return EncapsulationHeader(
            command=EncapsulationCommand(cmd),
            length=length,
            session_handle=session,
            status=EncapsulationStatus(status),
            sender_context=context,
            options=options,
        )

    def write_to(self, dst: bytearray, offset: int = 0) -> int:
        _HEADER_STRUCT.pack_into(dst, offset,
                                 int(self.command), self.length,
                                 self.session_handle, int(self.status),
                                 self.sender_context, self.options)
        return SIZE

    def to_bytes(self) -> bytes:
        buf = bytearray(SIZE)
        self.write_to(buf)
        return bytes(buf)
