"""Encapsulation SendUnitData (0x0070). Connected explicit messaging.

Wire layout (after the 24-byte encapsulation header):
    InterfaceHandle(4) + Timeout(2) + CPF { ConnectedAddress(0x00A1) + ConnectedData(0x00B1) }

ConnectedAddress carries a 4-byte connection ID; ConnectedData carries
the CIP service request/reply.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass

from ...cip.encapsulation import (
    EncapsulationHeader, EncapsulationCommand, EncapsulationStatus, SIZE as HEADER_SIZE,
)

_CONN_ADDR_TYPE = 0x00A1
_CONN_DATA_TYPE = 0x00B1
_PREAMBLE = 6                # InterfaceHandle(4) + Timeout(2)
_CPF_OVERHEAD = 2 + 4 + 4 + 4  # itemCount + addr hdr + addr connId + data hdr


@dataclass
class SendUnitDataMessage:
    session_handle: int = 0
    status: EncapsulationStatus = EncapsulationStatus.SUCCESS
    sender_context: int = 0
    interface_handle: int = 0
    timeout: int = 0
    connection_id: int = 0
    cip_data: bytes = b''
    remote_addr: tuple[str, int] = ('0.0.0.0', 0)

    @property
    def wire_size(self) -> int:
        return HEADER_SIZE + _PREAMBLE + _CPF_OVERHEAD + len(self.cip_data)

    def to_bytes(self) -> bytes:
        payload_len = _PREAMBLE + _CPF_OVERHEAD + len(self.cip_data)
        buf = bytearray(HEADER_SIZE + payload_len)
        EncapsulationHeader(
            command=EncapsulationCommand.SEND_UNIT_DATA,
            length=payload_len,
            session_handle=self.session_handle,
            status=self.status,
            sender_context=self.sender_context,
        ).write_to(buf, 0)

        o = HEADER_SIZE
        struct.pack_into('<IH', buf, o, self.interface_handle, self.timeout); o += 6
        struct.pack_into('<H', buf, o, 2); o += 2  # item count
        struct.pack_into('<HHI', buf, o, _CONN_ADDR_TYPE, 4, self.connection_id); o += 8
        struct.pack_into('<HH', buf, o, _CONN_DATA_TYPE, len(self.cip_data)); o += 4
        buf[o:o + len(self.cip_data)] = self.cip_data
        return bytes(buf)

    @staticmethod
    def parse(header: EncapsulationHeader, payload: bytes,
              remote_addr: tuple[str, int]) -> 'SendUnitDataMessage | None':
        if len(payload) < _PREAMBLE + _CPF_OVERHEAD:
            return None

        o = 0
        interface, timeout = struct.unpack_from('<IH', payload, o); o += 6
        (item_count,) = struct.unpack_from('<H', payload, o); o += 2
        if item_count < 2:
            return None

        addr_type, addr_len = struct.unpack_from('<HH', payload, o); o += 4
        if addr_type != _CONN_ADDR_TYPE or addr_len != 4:
            return None
        (connection_id,) = struct.unpack_from('<I', payload, o); o += 4

        if o + 4 > len(payload):
            return None
        data_type, data_len = struct.unpack_from('<HH', payload, o); o += 4
        if data_type != _CONN_DATA_TYPE:
            return None
        if o + data_len > len(payload):
            return None

        return SendUnitDataMessage(
            session_handle=header.session_handle,
            status=header.status,
            sender_context=header.sender_context,
            interface_handle=interface,
            timeout=timeout,
            connection_id=connection_id,
            cip_data=bytes(payload[o:o + data_len]),
            remote_addr=remote_addr,
        )
