"""Encapsulation ListServices (0x0004).

Request: header only. Response: header + CPF (one CommServices item, 0x0100).
"""
from __future__ import annotations
from dataclasses import dataclass

from ...cip.encapsulation import (
    EncapsulationHeader, EncapsulationCommand, EncapsulationStatus, SIZE as HEADER_SIZE,
)


@dataclass
class ListServicesMessage:
    session_handle: int = 0
    status: EncapsulationStatus = EncapsulationStatus.SUCCESS
    sender_context: int = 0
    response_payload: bytes = b''
    remote_addr: tuple[str, int] = ('0.0.0.0', 0)

    @property
    def wire_size(self) -> int:
        return HEADER_SIZE + len(self.response_payload)

    def to_bytes(self) -> bytes:
        buf = bytearray(self.wire_size)
        EncapsulationHeader(
            command=EncapsulationCommand.LIST_SERVICES,
            length=len(self.response_payload),
            session_handle=self.session_handle,
            status=self.status,
            sender_context=self.sender_context,
        ).write_to(buf, 0)
        buf[HEADER_SIZE:] = self.response_payload
        return bytes(buf)

    @staticmethod
    def parse(header: EncapsulationHeader, payload: bytes,
              remote_addr: tuple[str, int]) -> 'ListServicesMessage':
        return ListServicesMessage(
            session_handle=header.session_handle,
            status=header.status,
            sender_context=header.sender_context,
            response_payload=bytes(payload),
            remote_addr=remote_addr,
        )
