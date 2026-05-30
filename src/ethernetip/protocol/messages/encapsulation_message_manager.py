"""Dispatch raw encapsulation bytes into typed message instances.

Designed for use over TCP — the caller accumulates raw bytes into a
buffer and calls try_parse in a loop, advancing by `consumed` after each
successful parse.
"""
from __future__ import annotations
from typing import Optional

from ...cip.encapsulation import EncapsulationHeader, EncapsulationCommand, SIZE as HEADER_SIZE
from .imessage import IMessage
from .encapsulation_message import EncapsulationMessage
from .nop_message import NopMessage
from .register_session_message import RegisterSessionMessage
from .unregister_session_message import UnregisterSessionMessage
from .list_identity_message import ListIdentityMessage
from .list_services_message import ListServicesMessage
from .send_rr_data_message import SendRRDataMessage
from .send_unit_data_message import SendUnitDataMessage


class EncapsulationMessageManager:
    """Parse a stream of encapsulation bytes into typed messages.

    Returns (message, consumed) — consumed is 0 with message None when more
    bytes are needed to complete the current frame. Unknown commands fall
    back to a generic EncapsulationMessage with the raw payload preserved.
    """

    def try_parse(self, data: bytes, remote_addr: tuple[str, int]
                  ) -> tuple[Optional[IMessage], int]:
        if len(data) < HEADER_SIZE:
            return None, 0  # need at least the header

        header = EncapsulationHeader.parse(data)
        total = HEADER_SIZE + header.length
        if len(data) < total:
            return None, 0  # need more for the full payload

        payload = data[HEADER_SIZE:total]

        if header.command == EncapsulationCommand.NOP:
            return NopMessage.parse(header, payload, remote_addr), total
        if header.command == EncapsulationCommand.REGISTER_SESSION:
            return RegisterSessionMessage.parse(header, payload, remote_addr), total
        if header.command == EncapsulationCommand.UNREGISTER_SESSION:
            return UnregisterSessionMessage.parse(header, payload, remote_addr), total
        if header.command == EncapsulationCommand.LIST_IDENTITY:
            return ListIdentityMessage.parse(header, payload, remote_addr), total
        if header.command == EncapsulationCommand.LIST_SERVICES:
            return ListServicesMessage.parse(header, payload, remote_addr), total
        if header.command == EncapsulationCommand.SEND_RR_DATA:
            return SendRRDataMessage.parse(header, payload, remote_addr), total
        if header.command == EncapsulationCommand.SEND_UNIT_DATA:
            return SendUnitDataMessage.parse(header, payload, remote_addr), total

        return EncapsulationMessage(
            header=header,
            payload=bytes(payload),
            remote_addr=remote_addr,
        ), total
