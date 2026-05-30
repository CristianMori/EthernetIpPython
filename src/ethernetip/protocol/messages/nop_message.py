"""Encapsulation Nop (0x0000). Header-only — never elicits a reply."""
from __future__ import annotations
from dataclasses import dataclass, field

from ...cip.encapsulation import EncapsulationHeader, EncapsulationCommand, SIZE as HEADER_SIZE


@dataclass
class NopMessage:
    session_handle: int = 0
    sender_context: int = 0
    remote_addr: tuple[str, int] = ('0.0.0.0', 0)

    @property
    def wire_size(self) -> int:
        return HEADER_SIZE

    def to_bytes(self) -> bytes:
        return EncapsulationHeader(
            command=EncapsulationCommand.NOP,
            session_handle=self.session_handle,
            sender_context=self.sender_context,
        ).to_bytes()

    @staticmethod
    def parse(header: EncapsulationHeader, payload: bytes,
              remote_addr: tuple[str, int]) -> 'NopMessage':
        return NopMessage(
            session_handle=header.session_handle,
            sender_context=header.sender_context,
            remote_addr=remote_addr,
        )
