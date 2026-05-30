"""Encapsulation RegisterSession (0x0065). 4-byte payload: protocol version + options flags."""
from __future__ import annotations
import struct
from dataclasses import dataclass

from ...cip.encapsulation import (
    EncapsulationHeader, EncapsulationCommand, EncapsulationStatus, SIZE as HEADER_SIZE,
)


@dataclass
class RegisterSessionMessage:
    session_handle: int = 0
    status: EncapsulationStatus = EncapsulationStatus.SUCCESS
    sender_context: int = 0
    protocol_version: int = 1
    options_flags: int = 0
    remote_addr: tuple[str, int] = ('0.0.0.0', 0)

    @property
    def wire_size(self) -> int:
        return HEADER_SIZE + 4

    def to_bytes(self) -> bytes:
        buf = bytearray(self.wire_size)
        EncapsulationHeader(
            command=EncapsulationCommand.REGISTER_SESSION,
            length=4,
            session_handle=self.session_handle,
            status=self.status,
            sender_context=self.sender_context,
        ).write_to(buf, 0)
        struct.pack_into('<HH', buf, HEADER_SIZE, self.protocol_version, self.options_flags)
        return bytes(buf)

    @staticmethod
    def parse(header: EncapsulationHeader, payload: bytes,
              remote_addr: tuple[str, int]) -> 'RegisterSessionMessage | None':
        if len(payload) < 4:
            return None
        proto, opts = struct.unpack_from('<HH', payload, 0)
        return RegisterSessionMessage(
            session_handle=header.session_handle,
            status=header.status,
            sender_context=header.sender_context,
            protocol_version=proto,
            options_flags=opts,
            remote_addr=remote_addr,
        )
