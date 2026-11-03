"""Scanner-side: CRC-failed client-data frames must not advance state.

Mirror of the device-side fix (F3). SafetyScannerConnection._on_client_data
advanced `_tgt_rollover_count` / `_tgt_last_ts` and acked the ping
counter BEFORE decode_safety_frame verified the CRC. A tampered or
corrupt frame would therefore drift the scanner's rollover away from
the target's — poisoning the CRC seed for subsequent legitimate
frames — and bounce a spurious TCOO back on the ping change.
"""
from __future__ import annotations

import struct

from ethernetip.safety.crc import SafetyCrc
from ethernetip.safety.frame_codec import (
    SafetyFormat, encode_safety_frame,
)
from ethernetip.safety.scanner_connection import SafetyScannerConnection
from ethernetip.safety.types import ModeByte


def _make_conn() -> SafetyScannerConnection:
    conn = SafetyScannerConnection.__new__(SafetyScannerConnection)
    conn.is_open = True
    conn._format = SafetyFormat.BASE
    conn._target_endpoint = ('192.168.1.76', 2222)
    conn._server_to_id = 0xDEADBEEF
    conn._client_to_id = 0xCAFEBABE
    conn._tgt_pid_seed_s1 = SafetyCrc.pid_cid_seed_s1(0x1234, 0xBEEF, 0x4321)
    conn._tgt_pid_seed_s3 = SafetyCrc.pid_cid_seed_s3(0x1234, 0xBEEF, 0x4321)
    conn._tgt_pid_seed_s5 = SafetyCrc.pid_cid_seed_s5(0x1234, 0xBEEF, 0x4321)
    conn._tgt_rollover_count = 7
    conn._tgt_last_ts = 0xFF00
    conn._tgt_rollover_initialized = True
    conn._last_target_ping = 0xFF
    conn._udp = None  # won't be reached — bad CRC returns early
    conn.on_data_received = []
    conn.log = []
    return conn


def test_bad_crc_client_frame_does_not_advance_rollover_or_ping():
    conn = _make_conn()

    # Build a valid frame (ts wraps past _tgt_last_ts) then corrupt a CRC byte.
    buf = bytearray(32)
    mode = ModeByte(0x81)  # run=1, ping=1
    n = encode_safety_frame(buf, b'\xAA' * 4, SafetyFormat.BASE, mode, 0x0100,
                             conn._tgt_pid_seed_s1, conn._tgt_pid_seed_s3,
                             conn._tgt_pid_seed_s5, 0)
    frame = bytearray(buf[:n])
    frame[-1] ^= 0xFF  # corrupt CRC

    received: list[bytes] = []
    conn.on_data_received.append(received.append)
    conn._on_client_data(bytes(frame))

    # State must remain unchanged.
    assert conn._tgt_rollover_count == 7
    assert conn._tgt_last_ts == 0xFF00
    assert conn._last_target_ping == 0xFF
    assert received == []
