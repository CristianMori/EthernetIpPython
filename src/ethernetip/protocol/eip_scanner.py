"""EtherNet/IP Scanner (originator/client) — connects to adapters, sends CIP requests."""

from __future__ import annotations
import asyncio
import struct
import socket
import os

from ..cip.encapsulation import (
    EncapsulationHeader, EncapsulationCommand, EncapsulationStatus, SIZE as HEADER_SIZE,
)
from ..cip.cpf import CpfItem, CpfItemType, parse_cpf, encode_cpf
from ..cip import mr_codec
from ..cip.service import CipServiceResponse
from ..cip.status import CipStatus

from .eip_adapter import DEFAULT_PORT
from .eip_udp_transport import EipUdpTransport, IO_PORT
from .forward_open_config import ForwardOpenConfig
from .scanner_connection import ScannerConnection


class EipScanner:
    """EtherNet/IP client — connects to a target, registers a session, sends CIP messages."""

    def __init__(self):
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._send_lock = asyncio.Lock()
        self._udp: EipUdpTransport | None = None
        self._next_conn_serial = 1
        self.session_handle: int = 0
        self.local_endpoint: tuple[str, int] | None = None
        self.remote_endpoint: tuple[str, int] | None = None
        self._last_response_header: EncapsulationHeader | None = None

    @property
    def is_connected(self) -> bool:
        return self._writer is not None and self.session_handle != 0

    @property
    def udp(self) -> EipUdpTransport | None:
        """The scanner's UDP transport. Available after connect()."""
        return self._udp

    async def connect(self, host: str, port: int = DEFAULT_PORT) -> None:
        self._reader, self._writer = await asyncio.open_connection(host, port)
        sock = self._writer.get_extra_info('socket')
        self.local_endpoint = sock.getsockname()[:2]
        self.remote_endpoint = sock.getpeername()[:2]

        # Start UDP on ephemeral port
        self._udp = EipUdpTransport(bind_address='0.0.0.0', bind_port=0)
        await self._udp.start()

        self.session_handle = await self._register_session()

    async def send_explicit(self, service_code: int, path_bytes: bytes,
                            service_data: bytes = b'') -> CipServiceResponse:
        if not self.is_connected:
            raise RuntimeError("Not connected")

        mr_data = mr_codec.encode_request(service_code, path_bytes, service_data)

        items = [
            CpfItem(CpfItemType.NULL_ADDRESS, b''),
            CpfItem(CpfItemType.UNCONNECTED_DATA, mr_data),
        ]
        cpf_data = encode_cpf(items)

        payload = bytearray(6 + len(cpf_data))
        payload[6:] = cpf_data

        resp_payload = await self._send_encapsulated(EncapsulationCommand.SEND_RR_DATA, bytes(payload))

        resp_items = parse_cpf(resp_payload[6:])
        for item in resp_items:
            if item.type_id == CpfItemType.UNCONNECTED_DATA:
                result = mr_codec.try_parse_response(item.data)
                if result is None:
                    raise RuntimeError("Malformed MR response")
                reply_svc, status, data = result
                return CipServiceResponse(service_code=reply_svc, status=status, data=data)

        raise RuntimeError("No unconnected data in response")

    async def forward_open(self, config: ForwardOpenConfig) -> ScannerConnection:
        if not self.is_connected:
            raise RuntimeError("Not connected")

        conn_serial = self._next_conn_serial
        self._next_conn_serial += 1
        orig_vendor = 0x0001
        orig_serial = os.getpid() & 0xFFFFFFFF

        conn_path = bytes([
            0x20, 0x04,
            0x24, config.config_assembly & 0xFF,
            0x2C, config.consumed_assembly & 0xFF,
            0x2C, config.produced_assembly & 0xFF,
        ])

        ot_conn_size = (4 + config.consumed_size) if config.is_class1 else config.consumed_size
        to_conn_size = config.produced_size
        ot_params = 0x4200 | (ot_conn_size & 0x01FF)
        to_params = 0x4200 | (to_conn_size & 0x01FF)
        to_conn_id = 0x10000000 | conn_serial

        fwd_data = bytearray(36 + len(conn_path))
        off = 0
        fwd_data[off] = 0x0A; off += 1
        fwd_data[off] = 0x05; off += 1
        struct.pack_into('<I', fwd_data, off, 0); off += 4
        struct.pack_into('<I', fwd_data, off, to_conn_id); off += 4
        struct.pack_into('<H', fwd_data, off, conn_serial); off += 2
        struct.pack_into('<H', fwd_data, off, orig_vendor); off += 2
        struct.pack_into('<I', fwd_data, off, orig_serial); off += 4
        fwd_data[off] = config.timeout_multiplier; off += 1
        off += 3
        struct.pack_into('<I', fwd_data, off, config.rpi); off += 4
        struct.pack_into('<H', fwd_data, off, ot_params); off += 2
        struct.pack_into('<I', fwd_data, off, config.rpi); off += 4
        struct.pack_into('<H', fwd_data, off, to_params); off += 2
        fwd_data[off] = config.transport_class; off += 1
        fwd_data[off] = len(conn_path) // 2; off += 1
        fwd_data[off:off + len(conn_path)] = conn_path

        cm_path = bytes([0x20, 0x06, 0x24, 0x01])
        response, cpf_items = await self.send_explicit_raw(0x54, cm_path, bytes(fwd_data))

        if not response.status.is_success:
            raise RuntimeError(f"Forward Open failed: status=0x{response.status.general_status:02X}")

        resp_data = response.data
        resp_ot_conn_id = struct.unpack_from('<I', resp_data, 0)[0]
        resp_to_conn_id = struct.unpack_from('<I', resp_data, 4)[0]

        target_udp_port = IO_PORT
        target_udp_addr = self.remote_endpoint[0]
        for item in cpf_items:
            if item.type_id == CpfItemType.SOCKADDR_INFO_OT and len(item.data) >= 8:
                target_udp_port = struct.unpack_from('>H', item.data, 2)[0]
                addr_bytes = item.data[4:8]
                sock_addr = socket.inet_ntoa(addr_bytes)
                if sock_addr != '0.0.0.0':
                    target_udp_addr = sock_addr
                break

        conn = ScannerConnection(
            self, self._udp, config, (target_udp_addr, target_udp_port),
            ot_connection_id=resp_ot_conn_id,
            to_connection_id=resp_to_conn_id,
            connection_serial=conn_serial,
            originator_vendor=orig_vendor,
            originator_serial=orig_serial,
        )
        conn.start()
        return conn

    async def open_explicit(self):
        """Open a Class 3 connected-explicit messaging connection to the target.

        Returns a ConnectedExplicit handle whose send() / send_raw() methods
        route over TCP via SendUnitData (encap 0x70) instead of SendRRData.
        Close the handle (or use it as an async context manager) to issue the
        Forward Close.
        """
        from .connected_explicit import ConnectedExplicit  # local import to avoid cycle
        import time

        if not self.is_connected:
            raise RuntimeError("Not connected")

        conn_serial = self._next_conn_serial
        self._next_conn_serial = (self._next_conn_serial + 1) & 0xFFFF
        orig_vendor = 0x0001
        orig_serial = int(time.monotonic_ns() // 1000) & 0xFFFFFFFF

        # Class 3 messaging — target Message Router (class 2, instance 1).
        app_path    = bytes([0x20, 0x02, 0x24, 0x01])
        to_conn_id  = 0x80000000 | conn_serial
        # P2P + priority high + fixed + 504 bytes — matches Logix MSG / pycomm3.
        net_params  = 0x43F8
        transport   = 0xA3                   # server direction, app trigger, class 3
        rpi         = 2_500_000              # 2.5 s

        fo = bytearray(36 + len(app_path))
        struct.pack_into('<BB', fo, 0, 0x07, 0x09)             # priority_tick + timeout_ticks
        struct.pack_into('<I',  fo, 2, 0)                       # OT conn ID (target picks)
        struct.pack_into('<I',  fo, 6, to_conn_id)
        struct.pack_into('<H',  fo, 10, conn_serial)
        struct.pack_into('<H',  fo, 12, orig_vendor)
        struct.pack_into('<I',  fo, 14, orig_serial)
        fo[18] = 0x03                                          # connection timeout multiplier (=x32)
        # reserved[3] at 19..21
        struct.pack_into('<I',  fo, 22, rpi)                    # OT RPI
        struct.pack_into('<H',  fo, 26, net_params)             # OT params
        struct.pack_into('<I',  fo, 28, rpi)                    # TO RPI
        struct.pack_into('<H',  fo, 32, net_params)             # TO params
        fo[34] = transport
        fo[35] = len(app_path) // 2
        fo[36:36 + len(app_path)] = app_path

        cm_path = bytes([0x20, 0x06, 0x24, 0x01])
        response, _cpf = await self.send_explicit_raw(0x54, cm_path, bytes(fo))
        if not response.status.is_success:
            raise RuntimeError(
                f"Class 3 Forward Open failed: status=0x{response.status.general_status:02X}")
        if len(response.data) < 8:
            raise RuntimeError("Class 3 Forward Open: response too short")
        resp_ot = struct.unpack_from('<I', response.data, 0)[0]
        resp_to = struct.unpack_from('<I', response.data, 4)[0]

        return ConnectedExplicit(self, resp_ot, resp_to,
                                   conn_serial, orig_vendor, orig_serial)

    async def _send_connected_mr(self, oto_t_connection_id: int, seq_count: int,
                                   service_code: int, path_bytes: bytes,
                                   service_data: bytes) -> CipServiceResponse:
        """Send an MR request over an existing Class 3 connection via SendUnitData.

        Encodes the MR, wraps it in a ConnectedAddress (0x00A1) +
        ConnectedData (0x00B1) CPF inside the SendUnitData payload, sends over
        TCP, and returns the inner CIP response.
        """
        if not self.is_connected:
            raise RuntimeError("Not connected")

        mr = mr_codec.encode_request(service_code, path_bytes, service_data)
        cd = struct.pack('<H', seq_count) + mr

        # SendUnitData payload = InterfaceHandle(4) + Timeout(2) + CPF{
        #   ConnectedAddress(0x00A1) addr_len=4 + OT_conn_id,
        #   ConnectedData(0x00B1)    data_len   + CD }
        payload = bytearray(6 + 2 + 4 + 4 + 4 + len(cd))
        struct.pack_into('<H',  payload, 6, 2)                           # item count
        struct.pack_into('<HHI', payload, 8, 0x00A1, 4, oto_t_connection_id)
        struct.pack_into('<HH',  payload, 16, 0x00B1, len(cd))
        payload[20:20 + len(cd)] = cd

        resp = await self._send_encapsulated(EncapsulationCommand.SEND_UNIT_DATA, bytes(payload))
        if len(resp) < 8:
            raise RuntimeError("SendUnitData reply too short")
        offset = 6
        item_count = struct.unpack_from('<H', resp, offset)[0]; offset += 2
        for _ in range(item_count):
            if offset + 4 > len(resp): break
            type_id, length = struct.unpack_from('<HH', resp, offset); offset += 4
            if offset + length > len(resp): break
            if type_id == 0x00B1 and length >= 2:
                inner = resp[offset + 2 : offset + length]
                parsed = mr_codec.try_parse_response(inner)
                if parsed is None:
                    raise RuntimeError("Malformed MR response")
                reply_svc, status, data = parsed
                return CipServiceResponse(service_code=reply_svc, status=status, data=data)
            offset += length
        raise RuntimeError("No ConnectedData item in SendUnitData reply")

    async def forward_close(self, conn_serial: int, orig_vendor: int, orig_serial: int) -> None:
        close_data = bytearray(12)
        close_data[0] = 0x0A; close_data[1] = 0x05
        struct.pack_into('<H', close_data, 2, conn_serial)
        struct.pack_into('<H', close_data, 4, orig_vendor)
        struct.pack_into('<I', close_data, 6, orig_serial)
        close_data[10] = 0; close_data[11] = 0

        cm_path = bytes([0x20, 0x06, 0x24, 0x01])
        await self.send_explicit(0x4E, cm_path, bytes(close_data))

    async def disconnect(self) -> None:
        if self._writer and self.session_handle != 0:
            try:
                header = EncapsulationHeader(
                    command=EncapsulationCommand.UNREGISTER_SESSION,
                    session_handle=self.session_handle,
                )
                self._writer.write(header.to_bytes())
                await self._writer.drain()
            except Exception:
                pass

        self.session_handle = 0
        if self._writer:
            self._writer.close()
        self._reader = None
        self._writer = None

    async def close(self) -> None:
        if self._udp:
            await self._udp.close()
        await self.disconnect()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

    # --- Private ---

    async def _register_session(self) -> int:
        payload = bytearray(4)
        struct.pack_into('<HH', payload, 0, 1, 0)
        await self._send_encapsulated(EncapsulationCommand.REGISTER_SESSION, bytes(payload))
        return self._last_response_header.session_handle

    async def send_explicit_raw(self, service_code: int, path_bytes: bytes,
                                 service_data: bytes) -> tuple[CipServiceResponse, list[CpfItem]]:
        """Like send_explicit but also returns the raw CPF items from the response
        (lets callers inspect sockaddr items, e.g. for FwdOpen UDP-target discovery)."""
        return await self._send_explicit_raw(service_code, path_bytes, service_data)

    async def _send_explicit_raw(self, service_code: int, path_bytes: bytes,
                                  service_data: bytes) -> tuple[CipServiceResponse, list[CpfItem]]:
        mr_data = mr_codec.encode_request(service_code, path_bytes, service_data)

        items = [
            CpfItem(CpfItemType.NULL_ADDRESS, b''),
            CpfItem(CpfItemType.UNCONNECTED_DATA, mr_data),
        ]
        cpf_data = encode_cpf(items)
        payload = bytearray(6 + len(cpf_data))
        payload[6:] = cpf_data

        resp_payload = await self._send_encapsulated(EncapsulationCommand.SEND_RR_DATA, bytes(payload))
        resp_items = parse_cpf(resp_payload[6:])

        response = None
        for item in resp_items:
            if item.type_id == CpfItemType.UNCONNECTED_DATA:
                result = mr_codec.try_parse_response(item.data)
                if result is None:
                    raise RuntimeError("Malformed MR response")
                reply_svc, status, data = result
                response = CipServiceResponse(service_code=reply_svc, status=status, data=data)

        if response is None:
            raise RuntimeError("No unconnected data in response")

        return response, resp_items

    async def _send_encapsulated(self, command: EncapsulationCommand, payload: bytes) -> bytes:
        async with self._send_lock:
            header = EncapsulationHeader(
                command=command,
                length=len(payload),
                session_handle=self.session_handle,
            )
            buf = bytearray(HEADER_SIZE + len(payload))
            header.write_to(buf)
            buf[HEADER_SIZE:] = payload
            self._writer.write(bytes(buf))
            await self._writer.drain()

            resp_header_data = await self._reader.readexactly(HEADER_SIZE)
            self._last_response_header = EncapsulationHeader.parse(resp_header_data)

            if self._last_response_header.status != EncapsulationStatus.SUCCESS:
                raise RuntimeError(
                    f"Encapsulation error: cmd={command}, status={self._last_response_header.status}")

            resp_payload = b''
            if self._last_response_header.length > 0:
                resp_payload = await self._reader.readexactly(self._last_response_header.length)

            return resp_payload
