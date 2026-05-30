"""Frame codec round-trip tests — ported from C# SafetyFrameCodecTests."""
import pytest
from ethernetip.safety.crc import SafetyCrc
from ethernetip.safety.frame_codec import (
    SafetyFormat, wire_size, encode_safety_frame, decode_safety_frame,
    encode_tcoo, encode_tcoo_extended,
)
from ethernetip.safety.types import ModeByte

CONN_SERIAL = 0x0001
ORIG_VENDOR = 0x0001
ORIG_SERIAL = 0x12345678
SEED_S1 = SafetyCrc.pid_cid_seed_s1(ORIG_VENDOR, ORIG_SERIAL, CONN_SERIAL)
SEED_S3 = SafetyCrc.pid_cid_seed_s3(ORIG_VENDOR, ORIG_SERIAL, CONN_SERIAL)
SEED_S5 = SafetyCrc.pid_cid_seed_s5(ORIG_VENDOR, ORIG_SERIAL, CONN_SERIAL)


@pytest.mark.parametrize("data_len,fmt,expected", [
    (1, SafetyFormat.BASE, 7),
    (2, SafetyFormat.BASE, 8),
    (3, SafetyFormat.BASE, 14),
    (10, SafetyFormat.BASE, 28),
    (1, SafetyFormat.EXTENDED, 7),
    (2, SafetyFormat.EXTENDED, 8),
    (3, SafetyFormat.EXTENDED, 14),
    (10, SafetyFormat.EXTENDED, 28),
])
def test_wire_size(data_len, fmt, expected):
    assert wire_size(data_len, fmt) == expected


def _round_trip(data: bytes, fmt: SafetyFormat, mode: ModeByte, timestamp: int,
                rollover: int = 0):
    wire = bytearray(wire_size(len(data), fmt))
    n = encode_safety_frame(wire, data, fmt, mode, timestamp,
                            SEED_S1, SEED_S3, SEED_S5, rollover)
    assert n == len(wire)
    return decode_safety_frame(bytes(wire), len(data), fmt,
                                SEED_S1, SEED_S3, SEED_S5, rollover)


def test_base_short_1byte():
    res = _round_trip(b'\x42', SafetyFormat.BASE, ModeByte.create(True, 0), 1234)
    assert res.crc_valid, res.error_message
    assert res.actual_data == b'\x42'
    assert res.timestamp == 1234
    assert res.mode.run_idle


def test_base_short_2byte():
    res = _round_trip(b'\xAA\x55', SafetyFormat.BASE, ModeByte.create(False, 2), 60000)
    assert res.crc_valid
    assert res.actual_data == b'\xAA\x55'
    assert res.mode.ping_count == 2
    assert not res.mode.run_idle


def test_base_long_4byte():
    res = _round_trip(b'\x01\x02\x03\x04', SafetyFormat.BASE, ModeByte.create(True, 1), 5000)
    assert res.crc_valid, res.error_message
    assert res.actual_data == b'\x01\x02\x03\x04'
    assert res.timestamp == 5000


def test_base_long_250byte():
    data = bytes(range(250))
    res = _round_trip(data, SafetyFormat.BASE, ModeByte.create(True, 3), 0xFFFF)
    assert res.crc_valid, res.error_message
    assert res.actual_data == data


def test_extended_short_1byte():
    res = _round_trip(b'\x77', SafetyFormat.EXTENDED, ModeByte.create(True, 1), 12345)
    assert res.crc_valid, res.error_message
    assert res.actual_data == b'\x77'
    assert res.mode.ping_count == 1


def test_extended_short_2byte():
    res = _round_trip(b'\xDE\xAD', SafetyFormat.EXTENDED, ModeByte.create(False, 3), 1)
    assert res.crc_valid
    assert res.actual_data == b'\xDE\xAD'


def test_extended_long_with_rollover():
    data = bytes(range(50))
    res = _round_trip(data, SafetyFormat.EXTENDED, ModeByte.create(True, 0), 8000, rollover=5)
    assert res.crc_valid, res.error_message
    assert res.actual_data == data


def test_decode_bad_data_fails():
    """Flip a single bit and confirm decode rejects."""
    data = b'\x42'
    wire = bytearray(wire_size(len(data), SafetyFormat.BASE))
    encode_safety_frame(wire, data, SafetyFormat.BASE, ModeByte.create(True, 0), 100,
                        SEED_S1, SEED_S3, SEED_S5)
    wire[0] ^= 0x01  # flip a bit
    res = decode_safety_frame(bytes(wire), 1, SafetyFormat.BASE, SEED_S1, SEED_S3, SEED_S5)
    assert not res.crc_valid
    assert res.error_message is not None


def test_tcoo_base_6bytes():
    out = bytearray(6)
    n = encode_tcoo(out, ping_count_reply=2, consumer_time_value=42, cid_seed_s3=SEED_S3)
    assert n == 6
    # AckByte: ping=2 (bits 1:0=10), Ping_Response=1 (bit 3), parity to make even.
    # ack base = 0b00001010 = 0x0A — bit count = 2 (even) — parity bit stays 0
    assert out[0] == 0x0A
    # AckByte2: ((ack ^ 0xFF) & 0x55) | (ack & 0xAA) = (~0x0A & 0x55) | (0x0A & 0xAA) = 0x55 | 0x0A = 0x5F
    assert out[3] == 0x5F


def test_tcoo_extended_6bytes():
    out = bytearray(6)
    n = encode_tcoo_extended(out, ping_count_reply=1, consumer_time_value=100, pid_seed_s5=SEED_S5)
    assert n == 6
