"""EtherNet/IP UDP transport for Class 0/1 I/O data on port 2222."""

from __future__ import annotations
import asyncio
import socket
import struct
from typing import Callable

IO_PORT = 0x08AE  # 2222
CPF_OVERHEAD = 18


class EipUdpTransport:
    """UDP I/O transport — sends/receives CPF-formatted Class 0/1 data."""

    def __init__(self, bind_address: str = '0.0.0.0', bind_port: int = IO_PORT):
        self._bind_address = bind_address
        self._bind_port = bind_port
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _UdpProtocol | None = None
        self.actual_port: int = bind_port

        # Callbacks: (connection_id, data)
        self.on_data_received: list[Callable[[int, bytes], None]] = []
        # Callbacks: (connection_id, (host, port))
        self.on_data_received_with_sender: list[Callable[[int, tuple[str, int]], None]] = []

    async def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        loop = loop or asyncio.get_running_loop()
        self._protocol = _UdpProtocol(self)
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: self._protocol,
            local_addr=(self._bind_address, self._bind_port),
            family=socket.AF_INET,
        )
        # Get actual bound port (for ephemeral port=0)
        sock = self._transport.get_extra_info('socket')
        if sock:
            self.actual_port = sock.getsockname()[1]

    def send_io_data(self, destination: tuple[str, int], connection_id: int,
                     encap_seq_num: int, data: bytes) -> None:
        if self._transport is None:
            return

        packet_size = CPF_OVERHEAD + len(data)
        packet = bytearray(packet_size)
        offset = 0

        # Item count = 2
        struct.pack_into('<H', packet, offset, 2); offset += 2
        # Sequenced Address item (0x8002, 8 bytes)
        struct.pack_into('<HH', packet, offset, 0x8002, 8); offset += 4
        struct.pack_into('<II', packet, offset, connection_id, encap_seq_num); offset += 8
        # Connected Data item (0x00B1)
        struct.pack_into('<HH', packet, offset, 0x00B1, len(data)); offset += 4
        packet[offset:offset + len(data)] = data

        self._transport.sendto(bytes(packet), destination)

    async def close(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None

    def _process_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) < CPF_OVERHEAD:
            return

        item_count = struct.unpack_from('<H', data, 0)[0]
        if item_count < 2:
            return

        offset = 2
        addr_type = struct.unpack_from('<H', data, offset)[0]
        addr_len = struct.unpack_from('<H', data, offset + 2)[0]
        offset += 4

        if addr_type != 0x8002 or addr_len != 8:
            return

        connection_id = struct.unpack_from('<I', data, offset)[0]
        offset += 8  # skip conn_id + encap_seq

        if offset + 4 > len(data):
            return
        data_type = struct.unpack_from('<H', data, offset)[0]
        data_len = struct.unpack_from('<H', data, offset + 2)[0]
        offset += 4

        if data_type != 0x00B1 or offset + data_len > len(data):
            return

        io_data = data[offset:offset + data_len]

        for cb in self.on_data_received:
            cb(connection_id, io_data)
        for cb in self.on_data_received_with_sender:
            cb(connection_id, addr)


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, transport: EipUdpTransport):
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._transport._process_packet(data, addr)

    def error_received(self, exc: Exception) -> None:
        pass  # Transient UDP errors
