"""Encapsulation SendRRData (0x006F). Unconnected explicit messaging (UCMM).

Wire layout (after the 24-byte encapsulation header):
    InterfaceHandle(4) + Timeout(2) + CPF { NullAddress(0x0000) + UnconnectedData(0x00B2) }

The unconnected data carries a CIP MessageRouter request/reply.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass

from ...cip.encapsulation import (
    EncapsulationHeader, EncapsulationCommand, EncapsulationStatus, SIZE as HEADER_SIZE,
)

_NULL_ADDR_TYPE = 0x0000
_UNCONN_DATA_TYPE = 0x00B2
_PREAMBLE = 6                # InterfaceHandle(4) + Timeout(2)
_CPF_OVERHEAD = 2 + 4 + 4    # itemCount + null-addr header + data header


@dataclass
class SendRRDataMessage:
    session_handle: int = 0
    status: EncapsulationStatus = EncapsulationStatus.SUCCESS
    sender_context: int = 0
    interface_handle: int = 0
    timeout: int = 0
    # CIP MessageRouter bytes (the UnconnectedData item's contents).
    cip_data: bytes = b''
    remote_addr: tuple[str, int] = ('0.0.0.0', 0)

    @property
    def wire_size(self) -> int:
        return HEADER_SIZE + _PREAMBLE + _CPF_OVERHEAD + len(self.cip_data)

    def to_bytes(self) -> bytes:
        payload_len = _PREAMBLE + _CPF_OVERHEAD + len(self.cip_data)
        buf = bytearray(HEADER_SIZE + payload_len)
        EncapsulationHeader(
            command=EncapsulationCommand.SEND_RR_DATA,
            length=payload_len,
            session_handle=self.session_handle,
            status=self.status,
            sender_context=self.sender_context,
        ).write_to(buf, 0)

        o = HEADER_SIZE
        struct.pack_into('<IH', buf, o, self.interface_handle, self.timeout); o += 6
        struct.pack_into('<H', buf, o, 2); o += 2                              # item count
        struct.pack_into('<HH', buf, o, _NULL_ADDR_TYPE, 0); o += 4
        struct.pack_into('<HH', buf, o, _UNCONN_DATA_TYPE, len(self.cip_data)); o += 4
        buf[o:o + len(self.cip_data)] = self.cip_data
        return bytes(buf)

    @staticmethod
    def parse(header: EncapsulationHeader, payload: bytes,
              remote_addr: tuple[str, int]) -> 'SendRRDataMessage | None':
        if len(payload) < _PREAMBLE + _CPF_OVERHEAD:
            return None

        o = 0
        interface, timeout = struct.unpack_from('<IH', payload, o); o += 6
        (item_count,) = struct.unpack_from('<H', payload, o); o += 2
        if item_count < 2:
            return None

        addr_type, addr_len = struct.unpack_from('<HH', payload, o); o += 4
        if addr_type != _NULL_ADDR_TYPE or addr_len != 0:
            return None

        if o + 4 > len(payload):
            return None
        data_type, data_len = struct.unpack_from('<HH', payload, o); o += 4
        if data_type != _UNCONN_DATA_TYPE:
            return None
        if o + data_len > len(payload):
            return None

        return SendRRDataMessage(
            session_handle=header.session_handle,
            status=header.status,
            sender_context=header.sender_context,
            interface_handle=interface,
            timeout=timeout,
            cip_data=bytes(payload[o:o + data_len]),
            remote_addr=remote_addr,
        )
