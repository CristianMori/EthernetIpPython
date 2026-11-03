"""CRC-failed data frames must not advance device-side originator state.

Before this fix, `handle_received_io_data` on the device committed
`safety_originator_rollover_count` / `safety_originator_last_ts` and
walked the `mode_byte` (ping-change TCOO, plc_running cold-start)
BEFORE `decode_safety_frame` validated the CRC. A tampered or corrupt
frame could therefore:
  * push the rollover counter forward, drifting the CRC seed away from
    the producer and poisoning subsequent legitimate frames;
  * trip the plc_running false→True transition on a connection the
    partner-conn cold-start code reacts to.

Mirror of Rust round-4 bb1b1fd.
"""
from __future__ import annotations

import struct

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.connections.io_connection import IoConnection
from ethernetip.safety.crc import SafetyCrc
from ethernetip.safety.frame_codec import (
    SafetyFormat, encode_safety_frame,
)
from ethernetip.safety.safety_device import SafetyDevice
from ethernetip.safety.types import ModeByte, SafetyNetworkNumber


def _make_safety_device() -> SafetyDevice:
    return SafetyDevice(
        identity=IdentityInfo(),
        bind_address='0.0.0.0',
        snn=SafetyNetworkNumber(b'\x01\x02\x03\x04\x05\x06'),
        node_address=0xC0A80101,
    )


def _make_conn(originator_vendor_id: int = 0x1234,
               originator_serial_number: int = 0xDEADBEEF,
               connection_serial_number: int = 0x5678) -> IoConnection:
    conn = IoConnection()
    conn.is_safety = True
    conn.safety_format = 0x00  # BASE
    conn.originator_vendor_id = originator_vendor_id
    conn.originator_serial_number = originator_serial_number
    conn.connection_serial_number = connection_serial_number
    conn.safety_originator_pid_seed_s1 = SafetyCrc.pid_cid_seed_s1(
        originator_vendor_id, originator_serial_number, connection_serial_number)
    conn.safety_originator_pid_seed_s3 = SafetyCrc.pid_cid_seed_s3(
        originator_vendor_id, originator_serial_number, connection_serial_number)
    conn.safety_originator_pid_seed_s5 = SafetyCrc.pid_cid_seed_s5(
        originator_vendor_id, originator_serial_number, connection_serial_number)
    conn.safety_initial_timestamp = 0
    conn.safety_initial_rollover_value = 0
    conn.consumed_assembly_instance = 0
    return conn


def _encode_long_base(payload: bytes, ts: int, mode_byte_val: int,
                      seeds_s1: int, seeds_s3: int) -> bytes:
    buf = bytearray(len(payload) * 2 + 16)
    mode = ModeByte(mode_byte_val)
    n = encode_safety_frame(buf, payload, SafetyFormat.BASE, mode, ts,
                             seeds_s1, seeds_s3, 0, 0)
    return bytes(buf[:n])


def test_bad_crc_frame_does_not_advance_rollover_or_commit_state():
    """A frame whose timestamp wraps past the previous ts but has a
    corrupted CRC must leave rollover + last_ts + plc_running untouched."""
    dev = _make_safety_device()
    conn = _make_conn()
    # Seed state as if we've already seen ts near end of 16-bit space.
    conn.safety_originator_rollover_initialized = True
    conn.safety_originator_rollover_count = 5
    conn.safety_originator_last_ts = 0xFF00
    conn.safety_plc_running = False
    conn.safety_last_ping_count = 0xFF

    # Build a frame with ts=0x0100 (wraps past 0xFF00), run bit set,
    # ping != 0xFF. This frame's CRC is computed for rollover=0, not 6,
    # and we corrupt it anyway — so the device must reject it.
    good = _encode_long_base(b'\xAA' * 4, 0x0100, 0x81,
                              conn.safety_originator_pid_seed_s1,
                              conn.safety_originator_pid_seed_s3)
    bad = bytearray(good)
    bad[-1] ^= 0xFF  # corrupt a CRC byte

    dev.handle_received_io_data(conn, bytes(bad))

    assert conn.safety_originator_rollover_count == 5
    assert conn.safety_originator_last_ts == 0xFF00
    assert conn.safety_plc_running is False
    assert conn.safety_last_ping_count == 0xFF
