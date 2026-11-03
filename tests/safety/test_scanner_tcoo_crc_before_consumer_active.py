"""Scanner-side TCOO CRC must verify before `_consumer_active` is flipped.

Mirror of the device-side fix in 7482930. Before this change, any UDP
routed to the server TO id with wire length 5 or 6 flipped the
scanner's producer into "running" mode on wire length alone, without
checking the TCOO's own CRC.
"""
from __future__ import annotations

import struct

from ethernetip.safety.crc import SafetyCrc
from ethernetip.safety.frame_codec import SafetyFormat
from ethernetip.safety.scanner_connection import SafetyScannerConnection


def _make_conn() -> SafetyScannerConnection:
    conn = SafetyScannerConnection.__new__(SafetyScannerConnection)
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


def _base_tcoo(ping_reply: int, ctv: int, cid_seed_s3: int,
               *, corrupt: bool = False) -> bytes:
    ack = (ping_reply & 0x03) | 0x08
    if sum(1 for i in range(7) if ack & (1 << i)) % 2:
        ack |= 0x80
    ack2 = (((ack ^ 0xFF) & 0x55) | (ack & 0xAA)) & 0xFF
    crc = SafetyCrc.compute_s3(ack, cid_seed_s3)
    crc = SafetyCrc.compute_s3(ctv, crc)
    if corrupt:
        crc ^= 0xFFFF
    return bytes([ack]) + struct.pack('<H', ctv) + bytes([ack2]) + struct.pack('<H', crc)


def test_bad_crc_tcoo_does_not_flip_consumer_active():
    conn = _make_conn()
    bad = _base_tcoo(0, 0x1234, conn._tgt_cid_seed_s3, corrupt=True)
    assert len(bad) == 6
    conn._on_server_tcoo(bad)
    assert conn._consumer_active is False


def test_good_crc_tcoo_flips_consumer_active():
    conn = _make_conn()
    good = _base_tcoo(0, 0x1234, conn._tgt_cid_seed_s3)
    assert len(good) == 6
    conn._on_server_tcoo(good)
    assert conn._consumer_active is True
    assert conn._run_idle is True


def test_five_byte_server_tcoo_rejected():
    """TCOO is defined as 6 bytes — a 5-byte frame has no defined CRC
    coverage and must not activate the consumer."""
    conn = _make_conn()
    good = _base_tcoo(0, 0x1234, conn._tgt_cid_seed_s3)
    conn._on_server_tcoo(good[:5])
    assert conn._consumer_active is False
