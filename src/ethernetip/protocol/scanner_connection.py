"""Active I/O connection from the scanner (originator) side."""

from __future__ import annotations
import asyncio
import struct
from typing import Callable, TYPE_CHECKING

from .forward_open_config import ForwardOpenConfig
from .eip_udp_transport import EipUdpTransport

if TYPE_CHECKING:
    from .eip_scanner import EipScanner


class ScannerConnection:
    """Produces O→T data at RPI, consumes T→O data from target."""

    def __init__(self, scanner: EipScanner, udp: EipUdpTransport,
                 config: ForwardOpenConfig, target_endpoint: tuple[str, int],
                 ot_connection_id: int, to_connection_id: int,
                 connection_serial: int, originator_vendor: int, originator_serial: int):
        self._scanner = scanner
        self._udp = udp
        self.config = config
        self.target_endpoint = target_endpoint
        self.ot_connection_id = ot_connection_id
        self.to_connection_id = to_connection_id
        self.connection_serial = connection_serial
        self.originator_vendor = originator_vendor
        self.originator_serial = originator_serial

        self._consumed_data = bytearray(config.consumed_size)  # O→T
        self._produced_data = bytearray(config.produced_size)   # T→O
        self._encap_seq_num = 0
        self._cip_seq_count = 0
        self._production_task: asyncio.Task | None = None
        self.is_open = True
        self.send_count = 0
        self.receive_count = 0

        self.on_data_received: list[Callable[[bytes], None]] = []

    def start(self) -> None:
        self._udp.on_data_received.append(self._on_udp_data)
        self._production_task = asyncio.ensure_future(self._production_loop())

    @property
    def produced_data(self) -> bytes:
        return bytes(self._produced_data)

    def set_consumed_data(self, data: bytes | bytearray) -> None:
        n = min(len(data), len(self._consumed_data))
        self._consumed_data[:n] = data[:n]

    def write_dint(self, offset: int, value: int) -> None:
        struct.pack_into('<i', self._consumed_data, offset, value)

    def read_dint(self, offset: int = 0) -> int:
        return struct.unpack_from('<i', self._produced_data, offset)[0]

    async def _production_loop(self) -> None:
        interval = max(self.config.rpi / 1_000_000.0, 0.001)
        while self.is_open:
            await asyncio.sleep(interval)
            if not self.is_open:
                break
            self._produce_data()

    def _produce_data(self) -> None:
        self._encap_seq_num += 1

        if self.config.is_class1:
            self._cip_seq_count = (self._cip_seq_count + 1) & 0xFFFF
            io_data = bytearray(2 + 4 + len(self._consumed_data))
            struct.pack_into('<H', io_data, 0, self._cip_seq_count)
            struct.pack_into('<I', io_data, 2, 0x00000001)  # RUN
            io_data[6:] = self._consumed_data
        else:
            io_data = bytes(self._consumed_data)

        self._udp.send_io_data(self.target_endpoint, self.ot_connection_id,
                               self._encap_seq_num, bytes(io_data))
        self.send_count += 1

    def _on_udp_data(self, connection_id: int, data: bytes) -> None:
        if connection_id != self.to_connection_id or not self.is_open:
            return

        if self.config.is_class1 and len(data) >= 2:
            io_data = data[2:]
        else:
            io_data = data

        n = min(len(io_data), len(self._produced_data))
        self._produced_data[:n] = io_data[:n]
        self.receive_count += 1
        for cb in self.on_data_received:
            cb(io_data)

    async def close(self) -> None:
        if not self.is_open:
            return
        self.is_open = False

        if self._production_task:
            self._production_task.cancel()
            try:
                await self._production_task
            except asyncio.CancelledError:
                pass

        if self._on_udp_data in self._udp.on_data_received:
            self._udp.on_data_received.remove(self._on_udp_data)

        await self._scanner.forward_close(
            self.connection_serial, self.originator_vendor, self.originator_serial)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()
