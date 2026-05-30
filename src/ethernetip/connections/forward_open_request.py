"""Parsed Forward Open / Large Forward Open request parameters."""

from __future__ import annotations
import struct
from dataclasses import dataclass
from .io_connection import TransportClass


@dataclass(frozen=True)
class NetworkConnectionParams:
    redundant_owner: bool = False
    connection_type: int = 0     # 0=Null, 1=Multicast, 2=P2P
    priority: int = 0
    is_variable: bool = False
    connection_size: int = 0

    @property
    def is_null(self) -> bool:
        return self.connection_type == 0

    @staticmethod
    def parse_16(raw: int) -> NetworkConnectionParams:
        return NetworkConnectionParams(
            redundant_owner=bool(raw & 0x8000),
            connection_type=(raw >> 13) & 0x03,
            priority=(raw >> 10) & 0x03,
            is_variable=bool(raw & 0x0200),
            connection_size=raw & 0x01FF,
        )

    @staticmethod
    def parse_32(raw: int) -> NetworkConnectionParams:
        return NetworkConnectionParams(
            redundant_owner=bool(raw & 0x80000000),
            connection_type=(raw >> 29) & 0x03,
            priority=(raw >> 26) & 0x03,
            is_variable=bool(raw & 0x02000000),
            connection_size=raw & 0xFFFF,
        )


@dataclass(frozen=True)
class ForwardOpenRequest:
    priority_time_tick: int = 0
    timeout_ticks: int = 0
    ot_connection_id: int = 0
    to_connection_id: int = 0
    connection_serial_number: int = 0
    originator_vendor_id: int = 0
    originator_serial_number: int = 0
    connection_timeout_multiplier: int = 0
    ot_rpi: int = 0
    ot_params: NetworkConnectionParams = NetworkConnectionParams()
    to_rpi: int = 0
    to_params: NetworkConnectionParams = NetworkConnectionParams()
    transport_class_trigger: int = 0
    connection_path_size_words: int = 0
    connection_path: bytes = b''
    is_large_forward_open: bool = False
    # Raw service data bytes (priority/tick through end of path). Used for
    # CPCRC validation on safety FwdOpens — must reflect the exact wire bytes.
    raw_service_data: bytes = b''

    @property
    def transport_class(self) -> TransportClass:
        # CIP transport class is the low 4 bits of the trigger byte (per Vol.1
        # Table 3-4.4.3). Masking with 0x03 truncates Class 6 (CIP Safety) to
        # Class 2, and Class 3 (used by pycomm3 for connected explicit
        # messaging after Forward Open) doesn't fit in 2 bits either.
        return TransportClass(self.transport_class_trigger & 0x0F)

    @staticmethod
    def parse(data: bytes | bytearray | memoryview, is_large: bool = False) -> ForwardOpenRequest:
        min_size = 40 if is_large else 36
        if len(data) < min_size:
            raise ValueError(f"Forward Open requires at least {min_size} bytes, got {len(data)}")

        offset = 0
        ptt = data[offset]; offset += 1
        tt = data[offset]; offset += 1
        ot_conn = struct.unpack_from('<I', data, offset)[0]; offset += 4
        to_conn = struct.unpack_from('<I', data, offset)[0]; offset += 4
        conn_serial = struct.unpack_from('<H', data, offset)[0]; offset += 2
        orig_vendor = struct.unpack_from('<H', data, offset)[0]; offset += 2
        orig_serial = struct.unpack_from('<I', data, offset)[0]; offset += 4
        timeout_mult = data[offset]; offset += 1
        offset += 3  # reserved

        ot_rpi = struct.unpack_from('<I', data, offset)[0]; offset += 4

        if is_large:
            ot_params = NetworkConnectionParams.parse_32(struct.unpack_from('<I', data, offset)[0]); offset += 4
            to_rpi = struct.unpack_from('<I', data, offset)[0]; offset += 4
            to_params = NetworkConnectionParams.parse_32(struct.unpack_from('<I', data, offset)[0]); offset += 4
        else:
            ot_params = NetworkConnectionParams.parse_16(struct.unpack_from('<H', data, offset)[0]); offset += 2
            to_rpi = struct.unpack_from('<I', data, offset)[0]; offset += 4
            to_params = NetworkConnectionParams.parse_16(struct.unpack_from('<H', data, offset)[0]); offset += 2

        tct = data[offset]; offset += 1
        path_size = data[offset]; offset += 1
        path_bytes = path_size * 2

        if offset + path_bytes > len(data):
            raise ValueError(f"Connection path requires {path_bytes} bytes at offset {offset}")

        path = bytes(data[offset:offset + path_bytes])
        raw = bytes(data[:offset + path_bytes])

        return ForwardOpenRequest(
            priority_time_tick=ptt, timeout_ticks=tt,
            ot_connection_id=ot_conn, to_connection_id=to_conn,
            connection_serial_number=conn_serial,
            originator_vendor_id=orig_vendor, originator_serial_number=orig_serial,
            connection_timeout_multiplier=timeout_mult,
            ot_rpi=ot_rpi, ot_params=ot_params,
            to_rpi=to_rpi, to_params=to_params,
            transport_class_trigger=tct, connection_path_size_words=path_size,
            connection_path=path, is_large_forward_open=is_large,
            raw_service_data=raw,
        )
