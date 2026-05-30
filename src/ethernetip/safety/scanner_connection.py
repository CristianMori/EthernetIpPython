"""CIP Safety scanner (originator) connection.

Manages a pair of Forward Opens — server (we produce O->T) + client (target
produces T→O) — for safety I/O exchange against a single target.
"""
from __future__ import annotations
import asyncio
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable

from ..protocol.eip_scanner import EipScanner
from ..protocol.eip_udp_transport import EipUdpTransport, IO_PORT
from ..cip.cpf import CpfItemType

from .crc import SafetyCrc
from .forward_open_builder import (
    SafetyForwardOpenConfig, build_safety_forward_open, CM_PATH,
)
from .frame_codec import (
    SafetyFormat, wire_size, encode_safety_frame, decode_safety_frame,
    extract_timestamp, encode_tcoo, encode_tcoo_extended,
)
from .types import ModeByte


def _now_ns() -> int:
    return time.perf_counter_ns()


@dataclass
class SafetyAppReply:
    """Parsed safety Application Reply from a FwdOpen response."""
    consumer_number: int = 0
    target_vendor_id: int = 0
    target_device_serial: int = 0
    target_connection_serial: int = 0   # SV Instance ID
    initial_timestamp: int = 0
    initial_rollover_value: int = 0

    @staticmethod
    def parse(data: bytes) -> 'SafetyAppReply':
        if len(data) < 10:
            return SafetyAppReply()
        consumer_num, tgt_vendor = struct.unpack_from('<HH', data, 0)
        tgt_serial, = struct.unpack_from('<I', data, 4)
        tgt_conn_serial, = struct.unpack_from('<H', data, 8)
        out = SafetyAppReply(
            consumer_number=consumer_num,
            target_vendor_id=tgt_vendor,
            target_device_serial=tgt_serial,
            target_connection_serial=tgt_conn_serial,
        )
        if len(data) >= 14:
            ts, rv = struct.unpack_from('<HH', data, 10)
            out.initial_timestamp = ts
            out.initial_rollover_value = rv
        return out


class SafetyScannerConnection:
    """A live pair of safety connections (server + client) to one target."""

    def __init__(self, scanner: EipScanner, udp: EipUdpTransport,
                 fmt: SafetyFormat):
        self._scanner = scanner
        self._udp = udp
        self._format = fmt

        self._server_ot_id = 0
        self._server_to_id = 0
        self._server_conn_serial = 0
        self._client_ot_id = 0
        self._client_to_id = 0
        self._client_conn_serial = 0
        self._target_endpoint: tuple[str, int] | None = None

        self._orig_vendor = 0
        self._orig_serial = 0
        self._route_prefix = b''

        self._server_app_reply = SafetyAppReply()
        self._client_app_reply = SafetyAppReply()

        # PID seeds — for data WE produce on server connection
        self._pid_seed_s1 = 0
        self._pid_seed_s3 = 0
        self._pid_seed_s5 = 0
        # Target PID seeds — for decoding data TARGET produces on client connection
        self._tgt_pid_seed_s1 = 0
        self._tgt_pid_seed_s3 = 0
        self._tgt_pid_seed_s5 = 0
        # CID seeds for TCOO we send on client O->T
        self._cid_seed_s3 = 0
        self._cid_seed_s5 = 0

        self._run_idle = False
        self._ping_count = 0
        self._consumer_active = False
        self._timestamp = 0
        self._rollover_count = 0          # for OUR outgoing producer (server O->T)
        self._tgt_rollover_count = 0      # for TARGET's outgoing producer (client T->O)
        self._tgt_last_ts = 0
        self._tgt_rollover_initialized = False
        self._last_target_ping = 0xFF

        self._production_task: asyncio.Task | None = None
        self._server_encap_seq = 1
        self._client_encap_seq = 1
        self._output_data = bytearray()
        self._input_data_size = 0

        self.is_open = False
        self.on_data_received: list[Callable[[bytes], None]] = []
        self.log: list[Callable[[str], None]] = []

    # ------------------------------------------------------------------ open

    @staticmethod
    async def open(scanner: EipScanner, udp: EipUdpTransport,
                   server_config: SafetyForwardOpenConfig,
                   client_config: SafetyForwardOpenConfig,
                   orig_vendor: int, orig_serial: int,
                   *,
                   route_prefix: bytes = b'',
                   server_app_path: bytes | None = None,
                   client_app_path: bytes | None = None) -> 'SafetyScannerConnection':
        conn = SafetyScannerConnection(scanner, udp, server_config.format)
        conn._orig_vendor = orig_vendor
        conn._orig_serial = orig_serial
        conn._route_prefix = route_prefix
        conn._output_data = bytearray(server_config.consumed_data_size)
        conn._input_data_size = client_config.produced_data_size

        # Distinct conn serials per direction
        base = int(time.time() * 1000) & 0xFFFF
        conn._server_conn_serial = base
        conn._client_conn_serial = (base + 1) & 0xFFFF

        # ---- Server FwdOpen (we produce O->T, target sends TCOO) ----
        conn._log_msg("Opening server connection (we produce)...")
        srv_data, cm_path = build_safety_forward_open(
            server_config, conn._server_conn_serial, orig_vendor, orig_serial,
            transport_class_trigger=0xA0,
            route_prefix=route_prefix, app_path=server_app_path)
        srv_resp, srv_cpf = await scanner.send_explicit_raw(0x54, cm_path, srv_data)
        if not srv_resp.status.is_success:
            ext = srv_resp.status.additional_status[0] if srv_resp.status.additional_status else 0
            raise RuntimeError(
                f"Server Forward Open failed: GS=0x{srv_resp.status.general_status:02X} "
                f"ES=0x{ext:04X}")

        srd = srv_resp.data
        conn._server_ot_id = struct.unpack_from('<I', srd, 0)[0]
        conn._server_to_id = struct.unpack_from('<I', srd, 4)[0]
        app_reply_words = srd[24]
        if app_reply_words > 0 and len(srd) >= 26 + app_reply_words * 2:
            conn._server_app_reply = SafetyAppReply.parse(srd[26:26 + app_reply_words * 2])
            conn._log_msg(
                f"  Target: Vendor=0x{conn._server_app_reply.target_vendor_id:04X} "
                f"Serial=0x{conn._server_app_reply.target_device_serial:08X} "
                f"SVInst={conn._server_app_reply.target_connection_serial}")

        # Pull target UDP endpoint from sockaddr CPF item
        for item in srv_cpf:
            if item.type_id == CpfItemType.SOCKADDR_INFO_OT and len(item.data) >= 8:
                port = struct.unpack_from('>H', item.data, 2)[0]
                addr = socket.inet_ntoa(item.data[4:8])
                if addr == '0.0.0.0':
                    addr = scanner.remote_endpoint[0]
                conn._target_endpoint = (addr, port)
                break
        if conn._target_endpoint is None:
            conn._target_endpoint = (scanner.remote_endpoint[0], IO_PORT)
        conn._log_msg(f"  Target UDP: {conn._target_endpoint}")
        conn._log_msg(f"  Server OT=0x{conn._server_ot_id:08X} TO=0x{conn._server_to_id:08X}")

        # ---- Client FwdOpen (target produces T→O, we send TCOO) ----
        conn._log_msg("Opening client connection (target produces)...")
        cli_data, cm_path = build_safety_forward_open(
            client_config, conn._client_conn_serial, orig_vendor, orig_serial,
            transport_class_trigger=0x20,
            route_prefix=route_prefix, app_path=client_app_path)
        cli_resp, _ = await scanner.send_explicit_raw(0x54, cm_path, cli_data)
        if not cli_resp.status.is_success:
            ext = cli_resp.status.additional_status[0] if cli_resp.status.additional_status else 0
            raise RuntimeError(
                f"Client Forward Open failed: GS=0x{cli_resp.status.general_status:02X} "
                f"ES=0x{ext:04X}")

        crd = cli_resp.data
        conn._client_ot_id = struct.unpack_from('<I', crd, 0)[0]
        conn._client_to_id = struct.unpack_from('<I', crd, 4)[0]
        cli_app_words = crd[24]
        if cli_app_words > 0 and len(crd) >= 26 + cli_app_words * 2:
            conn._client_app_reply = SafetyAppReply.parse(crd[26:26 + cli_app_words * 2])
        conn._log_msg(
            f"  Client OT=0x{conn._client_ot_id:08X} TO=0x{conn._client_to_id:08X} "
            f"SVInst={conn._client_app_reply.target_connection_serial}")

        # ---- PID/CID seed computation ----
        # PID uses PRODUCER identity + PRODUCER connection serial.
        # Server O->T: WE produce → our identity + our server conn serial.
        conn._pid_seed_s1 = SafetyCrc.pid_cid_seed_s1(
            orig_vendor, orig_serial, conn._server_conn_serial)
        conn._pid_seed_s3 = SafetyCrc.pid_cid_seed_s3(
            orig_vendor, orig_serial, conn._server_conn_serial)
        conn._pid_seed_s5 = SafetyCrc.pid_cid_seed_s5(
            orig_vendor, orig_serial, conn._server_conn_serial)

        # Client T→O: TARGET produces → target identity + target SVInst.
        tgt_vendor = conn._server_app_reply.target_vendor_id
        tgt_serial = conn._server_app_reply.target_device_serial
        cli_sv = conn._client_app_reply.target_connection_serial
        conn._tgt_pid_seed_s1 = SafetyCrc.pid_cid_seed_s1(tgt_vendor, tgt_serial, cli_sv)
        conn._tgt_pid_seed_s3 = SafetyCrc.pid_cid_seed_s3(tgt_vendor, tgt_serial, cli_sv)
        conn._tgt_pid_seed_s5 = SafetyCrc.pid_cid_seed_s5(tgt_vendor, tgt_serial, cli_sv)

        # CID seeds for client O->T TCOO: our identity + our client conn serial.
        conn._cid_seed_s3 = SafetyCrc.pid_cid_seed_s3(
            orig_vendor, orig_serial, conn._client_conn_serial)
        conn._cid_seed_s5 = SafetyCrc.pid_cid_seed_s5(
            orig_vendor, orig_serial, conn._client_conn_serial)

        # ---- UDP receive hook ----
        udp.on_data_received.append(conn._on_udp_data)

        # ---- Server production task ----
        ot_rpi = server_config.ot_rpi or server_config.rpi
        conn.is_open = True
        conn._production_task = asyncio.ensure_future(
            conn._production_loop(ot_rpi / 1_000_000))
        conn._log_msg(
            f"Safety connection open. Server O->T cadence={ot_rpi/1000:.1f}ms; "
            "producing cold-start frames (run=0, ts=0).")
        return conn

    # ------------------------------------------------------------------ I/O

    def set_output_data(self, data: bytes) -> None:
        n = min(len(data), len(self._output_data))
        self._output_data[:n] = data[:n]

    async def _production_loop(self, interval_s: float) -> None:
        try:
            while self.is_open:
                await asyncio.sleep(max(interval_s, 0.001))
                if not self.is_open:
                    break
                self._produce_server_frame()
        except asyncio.CancelledError:
            pass

    def _produce_server_frame(self) -> None:
        if not self.is_open or self._target_endpoint is None:
            return
        run_idle = self._consumer_active and self._run_idle
        timestamp = self._timestamp if self._consumer_active else 0
        mode = ModeByte.create(run_idle=run_idle, ping_count=self._ping_count)

        if self._consumer_active:
            # 50ms / 128µs ≈ 390 ticks per frame — placeholder, matches C# scanner.
            self._timestamp = (self._timestamp + 390) & 0xFFFF

        buf = bytearray(len(self._output_data) * 2 + 16)
        n = encode_safety_frame(
            buf, bytes(self._output_data), self._format, mode, timestamp,
            self._pid_seed_s1, self._pid_seed_s3, self._pid_seed_s5,
            self._rollover_count)
        if n <= 0:
            return
        self._udp.send_io_data(self._target_endpoint, self._server_ot_id,
                                self._server_encap_seq, bytes(buf[:n]))
        if self._server_encap_seq <= 3:
            self._log_msg(
                f"TX server O->T #{self._server_encap_seq} "
                f"connID=0x{self._server_ot_id:08X} len={n} "
                f"run={run_idle} ts={timestamp}")
        self._server_encap_seq += 1

    def _on_udp_data(self, connection_id: int, data: bytes) -> None:
        if not self.is_open:
            return
        if connection_id == self._server_to_id:
            self._on_server_tcoo(data)
        elif connection_id == self._client_to_id:
            self._on_client_data(data)
        else:
            self._log_msg(
                f"RX unknown connID=0x{connection_id:08X} len={len(data)} "
                f"(expecting server TO=0x{self._server_to_id:08X} "
                f"client TO=0x{self._client_to_id:08X})")

    def _on_server_tcoo(self, data: bytes) -> None:
        if not self._consumer_active:
            self._consumer_active = True
            self._run_idle = True
            self._log_msg(f"Consumer active — transitioning to run=1 (TCOO {len(data)}B)")

    def _on_client_data(self, data: bytes) -> None:
        wlen = len(data)
        if wlen in (5, 6):
            return  # TCOO on a client connection is unexpected; ignore
        data_len = _estimate_data_length(wlen)
        if data_len <= 0:
            return

        # Track target's rollover count from incoming wire timestamp wraps —
        # Extended-Format CRC depends on it. Seed from 0 (the 0xFFFF "cold
        # start" sentinel some targets echo in their app reply does NOT mean
        # rollover=0xFFFF — they start their producer at rollover=0).
        incoming_ts = extract_timestamp(data, data_len, self._format)
        if not self._tgt_rollover_initialized:
            self._tgt_rollover_count = 0
            self._tgt_last_ts = incoming_ts
            self._tgt_rollover_initialized = True
        else:
            # Raw int subtraction (matches C# `int delta = ushort - ushort`)
            # — a wrap shows as a large-magnitude negative value.
            delta = incoming_ts - self._tgt_last_ts
            if delta < -0x4000:
                self._tgt_rollover_count = (self._tgt_rollover_count + 1) & 0xFFFF
            self._tgt_last_ts = incoming_ts

        result = decode_safety_frame(
            data, data_len, self._format,
            self._tgt_pid_seed_s1, self._tgt_pid_seed_s3, self._tgt_pid_seed_s5,
            self._tgt_rollover_count)

        mode_byte = data[data_len] if data_len < len(data) else 0
        target_ping = mode_byte & 0x03
        target_run = (mode_byte & 0x80) != 0

        if self._last_target_ping == 0xFF or target_ping != self._last_target_ping:
            self._last_target_ping = target_ping
            self._send_client_tcoo(target_ping)

        if result.crc_valid:
            for cb in self.on_data_received:
                cb(bytes(result.actual_data))
            self._log_msg(
                f"RX data=[{result.actual_data.hex(' ')}] mode=0x{mode_byte:02X} "
                f"run={target_run} ping={target_ping} ts={result.timestamp}")
        else:
            self._log_msg(f"RX CRC FAIL: {result.error_message}")

    def _send_client_tcoo(self, ping_count_reply: int) -> None:
        if self._target_endpoint is None:
            return
        buf = bytearray(6)
        consumer_time = (_now_ns() // 128_000) & 0xFFFF  # ns → 128µs ticks
        if self._format == SafetyFormat.EXTENDED:
            n = encode_tcoo_extended(buf, ping_count_reply, consumer_time, self._cid_seed_s5)
        else:
            n = encode_tcoo(buf, ping_count_reply, consumer_time, self._cid_seed_s3)
        self._udp.send_io_data(self._target_endpoint, self._client_ot_id,
                                self._client_encap_seq, bytes(buf[:n]))
        self._client_encap_seq += 1
        self._log_msg(f"TX TCOO ping_reply={ping_count_reply} ct={consumer_time}")

    # ------------------------------------------------------------------ close

    async def close(self) -> None:
        self.is_open = False
        if self._production_task is not None:
            self._production_task.cancel()
            try:
                await self._production_task
            except asyncio.CancelledError:
                pass
            self._production_task = None
        try:
            self._udp.on_data_received.remove(self._on_udp_data)
        except ValueError:
            pass
        try:
            await self._send_forward_close(self._server_conn_serial)
            self._log_msg("Server connection closed.")
        except Exception as ex:
            self._log_msg(f"Server close error: {ex}")
        try:
            await self._send_forward_close(self._client_conn_serial)
            self._log_msg("Client connection closed.")
        except Exception as ex:
            self._log_msg(f"Client close error: {ex}")

    async def _send_forward_close(self, conn_serial: int) -> None:
        close_data = bytearray(12 + len(self._route_prefix))
        off = 0
        close_data[off] = 0x05; off += 1
        close_data[off] = 0x9C; off += 1
        struct.pack_into('<H', close_data, off, conn_serial); off += 2
        struct.pack_into('<H', close_data, off, self._orig_vendor); off += 2
        struct.pack_into('<I', close_data, off, self._orig_serial); off += 4
        close_data[off] = len(self._route_prefix) // 2; off += 1
        close_data[off] = 0; off += 1
        close_data[off:off + len(self._route_prefix)] = self._route_prefix
        await self._scanner.send_explicit_raw(0x4E, CM_PATH, bytes(close_data))

    # ------------------------------------------------------------------ misc

    def _log_msg(self, msg: str) -> None:
        for cb in self.log:
            cb(msg)


def _estimate_data_length(wire_len: int) -> int:
    short_len = wire_len - 6
    if 1 <= short_len <= 2:
        return short_len
    long_len = (wire_len - 8) // 2
    if 3 <= long_len <= 250 and long_len * 2 + 8 == wire_len:
        return long_len
    return -1
