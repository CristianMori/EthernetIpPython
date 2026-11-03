"""TCOO CRC must verify before safety_consumer_active is flipped.

Before the fix, any 5/6-byte UDP that reached ``handle_received_io_data``
on a safety connection flipped the producer into "running" mode on wire
length alone. Combined with the sender-IP authentication already in
place (b9f65fe), this is defense-in-depth: a frame that passes the
socket check but fails the TCOO's own CRC must not move the state
machine.

Base-format TCOO wire layout:
    [AckByte] [CTV(2)] [AckByte2] [CRC-S3(2)]
CRC-S3 computed over AckByte + CTV, seeded by the originator's S3 seed.
"""
from __future__ import annotations

import struct

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.connections.io_connection import IoConnection
from ethernetip.safety.crc import SafetyCrc
from ethernetip.safety.safety_device import SafetyDevice
from ethernetip.safety.types import SafetyNetworkNumber


def _make_safety_device() -> SafetyDevice:
    return SafetyDevice(
        identity=IdentityInfo(),
        bind_address='0.0.0.0',
        snn=SafetyNetworkNumber(b'\x01\x02\x03\x04\x05\x06'),
        node_address=0xC0A80101,
    )


def _make_safety_conn(originator_vendor_id: int = 0x1234,
                      originator_serial_number: int = 0xDEADBEEF,
                      connection_serial_number: int = 0x5678,
                      safety_format: int = 0x00) -> IoConnection:
    """Minimal safety-flagged IoConnection with originator seeds populated."""
    conn = IoConnection()
    conn.is_safety = True
    conn.safety_format = safety_format
    conn.originator_vendor_id = originator_vendor_id
    conn.originator_serial_number = originator_serial_number
    conn.connection_serial_number = connection_serial_number
    conn.safety_originator_pid_seed_s3 = SafetyCrc.pid_cid_seed_s3(
        originator_vendor_id, originator_serial_number, connection_serial_number)
    conn.safety_originator_pid_seed_s5 = SafetyCrc.pid_cid_seed_s5(
        originator_vendor_id, originator_serial_number, connection_serial_number)
    conn.safety_initial_timestamp = 0
    conn.safety_initial_rollover_value = 0
    return conn


def _build_base_tcoo(ping_count_reply: int, consumer_time: int,
                     cid_seed_s3: int, *, corrupt_crc: bool = False) -> bytes:
    """Base-format TCOO (6 bytes). Mirrors frame_codec.encode_tcoo."""
    ack = (ping_count_reply & 0x03) | 0x08
    bit_count = sum(1 for i in range(7) if ack & (1 << i))
    if bit_count % 2:
        ack |= 0x80
    ack2 = (((ack ^ 0xFF) & 0x55) | (ack & 0xAA)) & 0xFF
    crc = SafetyCrc.compute_s3(ack, cid_seed_s3)
    crc = SafetyCrc.compute_s3(consumer_time, crc)
    if corrupt_crc:
        crc ^= 0xFFFF
    return bytes([ack]) + struct.pack('<H', consumer_time) + bytes([ack2]) + struct.pack('<H', crc)


def test_tcoo_with_bad_crc_does_not_activate_consumer():
    """A 6-byte TCOO with the wrong CRC must leave safety_consumer_active
    False — no state transition on wire-length alone."""
    dev = _make_safety_device()
    conn = _make_safety_conn()
    bad = _build_base_tcoo(0, 0x1234, conn.safety_originator_pid_seed_s3,
                            corrupt_crc=True)
    assert len(bad) == 6
    assert conn.safety_consumer_active is False

    dev.handle_received_io_data(conn, bad)

    assert conn.safety_consumer_active is False


def test_tcoo_with_good_crc_activates_consumer():
    """A 6-byte TCOO whose CRC verifies against the originator seed must
    flip safety_consumer_active to True."""
    dev = _make_safety_device()
    conn = _make_safety_conn()
    good = _build_base_tcoo(0, 0x1234, conn.safety_originator_pid_seed_s3)
    assert len(good) == 6
    assert conn.safety_consumer_active is False

    dev.handle_received_io_data(conn, good)

    assert conn.safety_consumer_active is True


def test_five_byte_tcoo_rejected():
    """TCOO is defined as 6 bytes in both formats; a 5-byte frame has no
    defined CRC coverage and must not activate the consumer."""
    dev = _make_safety_device()
    conn = _make_safety_conn()
    short = _build_base_tcoo(0, 0x1234, conn.safety_originator_pid_seed_s3)[:5]
    assert len(short) == 5

    dev.handle_received_io_data(conn, short)

    assert conn.safety_consumer_active is False
