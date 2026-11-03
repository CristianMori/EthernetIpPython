"""Scanner-side UDP sender-IP authentication.

Mirror of the device-side fix in b9f65fe. SafetyScannerConnection's UDP
hook used to ignore the sender argument (``_sender``), so any LAN peer
that guessed a sequential ot_id could inject a frame into the scanner's
TCOO or client-data path. The fix drops any UDP whose source IP does
not match the known target endpoint.
"""
from __future__ import annotations

import struct

from ethernetip.safety.crc import SafetyCrc
from ethernetip.safety.frame_codec import SafetyFormat
from ethernetip.safety.scanner_connection import SafetyScannerConnection


def _make_conn() -> SafetyScannerConnection:
    conn = SafetyScannerConnection.__new__(SafetyScannerConnection)
    # Only populate the attributes _on_udp_data / _on_server_tcoo touch.
    conn.is_open = True
    conn._format = SafetyFormat.BASE
    conn._target_endpoint = ('192.168.1.76', 2222)
    conn._server_to_id = 0xDEADBEEF
    conn._client_to_id = 0xCAFEBABE
    conn._consumer_active = False
    conn._run_idle = False
    conn._tgt_cid_seed_s3 = SafetyCrc.pid_cid_seed_s3(0x1234, 0xDEADBEEF, 0x4321)
    conn._tgt_cid_seed_s5 = SafetyCrc.pid_cid_seed_s5(0x1234, 0xDEADBEEF, 0x4321)
    conn.log = []
    return conn


def _good_base_tcoo(ping_reply: int, ctv: int, cid_seed_s3: int) -> bytes:
    ack = (ping_reply & 0x03) | 0x08
    if sum(1 for i in range(7) if ack & (1 << i)) % 2:
        ack |= 0x80
    ack2 = (((ack ^ 0xFF) & 0x55) | (ack & 0xAA)) & 0xFF
    crc = SafetyCrc.compute_s3(ack, cid_seed_s3)
    crc = SafetyCrc.compute_s3(ctv, crc)
    return bytes([ack]) + struct.pack('<H', ctv) + bytes([ack2]) + struct.pack('<H', crc)


def test_scanner_drops_udp_from_wrong_sender_ip():
    """A valid 6-byte TCOO routed to the server TO id from a different
    IP must NOT flip `_consumer_active`."""
    conn = _make_conn()
    good = _good_base_tcoo(0, 0x1234, conn._tgt_cid_seed_s3)
    conn._on_udp_data(conn._server_to_id, good, ('192.168.1.200', 2222))
    assert conn._consumer_active is False


def test_scanner_accepts_valid_tcoo_from_target_ip():
    """Baseline: a CRC-valid TCOO from the target IP flips consumer_active."""
    conn = _make_conn()
    good = _good_base_tcoo(0, 0x1234, conn._tgt_cid_seed_s3)
    conn._on_udp_data(conn._server_to_id, good, ('192.168.1.76', 2222))
    assert conn._consumer_active is True
