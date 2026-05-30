"""CIP Safety wire-format frame encoder / decoder.

Four variants supported:
    Base Short      (1-2 byte data):  [Data][Mode][CRC-S1][CRC-S2] | [TS(2)][CRC-S1]
    Base Long       (3-250 byte data):[Data][Mode][CRC-S3(2)][~Data][CRC-S3(2)] | [TS(2)][CRC-S1]
    Extended Short  (1-2 byte data):  [Data][Mode][S5_lo(2)][TS(2)][S5_hi(1)]
    Extended Long   (3-250 byte data):[Data][Mode][CRC-S3(2)][~Data][S5_lo(2)][TS(2)][S5_hi(1)]

Encoding APIs are functions; the decoded result is a small dataclass.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass

from .types import SafetyFormat, ModeByte
from .crc import SafetyCrc


@dataclass
class SafetyFrameResult:
    actual_data: bytes
    mode: ModeByte
    timestamp: int
    crc_valid: bool
    error_message: str | None = None


def wire_size(data_length: int, fmt: SafetyFormat) -> int:
    """Total wire size for a safety frame given the actual data length."""
    is_short = data_length <= 2
    if fmt == SafetyFormat.BASE:
        return data_length + 6 if is_short else 2 * data_length + 8
    if fmt == SafetyFormat.EXTENDED:
        # Per CSS k_IO_MSGLEN_SHORT_OVHD = 6 for BOTH base and extended.
        return data_length + 6 if is_short else 2 * data_length + 8
    raise ValueError(f"Invalid format: {fmt}")


def extract_timestamp(input_bytes: bytes, data_length: int, fmt: SafetyFormat) -> int:
    """Extract wire timestamp without CRC validation. Needed by consumer to
    track originator rollover BEFORE the CRC check (which depends on it)."""
    is_short = data_length <= 2
    if is_short:
        off = data_length + 3
    elif fmt == SafetyFormat.BASE:
        off = 2 * data_length + 5
    else:
        off = 2 * data_length + 6
    if off + 2 > len(input_bytes):
        return 0
    ts, = struct.unpack_from('<H', input_bytes, off)
    return ts


def encode_safety_frame(output: bytearray, actual_data: bytes,
                         fmt: SafetyFormat, mode: ModeByte, timestamp: int,
                         pid_seed_s1: int, pid_seed_s3: int, pid_seed_s5: int,
                         rollover_count: int = 0) -> int:
    """Encode a safety data frame into `output`. Returns bytes written."""
    is_short = len(actual_data) <= 2
    if fmt == SafetyFormat.BASE:
        return (_encode_base_short(output, actual_data, mode, timestamp, pid_seed_s1)
                if is_short
                else _encode_base_long(output, actual_data, mode, timestamp, pid_seed_s1, pid_seed_s3))
    return (_encode_extended_short(output, actual_data, mode, timestamp, pid_seed_s5, rollover_count)
            if is_short
            else _encode_extended_long(output, actual_data, mode, timestamp,
                                       pid_seed_s3, pid_seed_s5, rollover_count))


def decode_safety_frame(input_bytes: bytes, data_length: int,
                         fmt: SafetyFormat,
                         pid_seed_s1: int, pid_seed_s3: int, pid_seed_s5: int,
                         rollover_count: int = 0) -> SafetyFrameResult:
    is_short = data_length <= 2
    if fmt == SafetyFormat.BASE:
        return (_decode_base_short(input_bytes, data_length, pid_seed_s1)
                if is_short
                else _decode_base_long(input_bytes, data_length, pid_seed_s1, pid_seed_s3))
    return (_decode_extended_short(input_bytes, data_length, pid_seed_s5, rollover_count)
            if is_short
            else _decode_extended_long(input_bytes, data_length, pid_seed_s3, pid_seed_s5, rollover_count))


# ==================== Base Format Short ====================

def _encode_base_short(out: bytearray, data: bytes, mode: ModeByte,
                       ts: int, pid_seed_s1: int) -> int:
    off = 0
    out[off:off + len(data)] = data; off += len(data)
    out[off] = mode.value; off += 1

    # Actual CRC-S1
    a_crc = SafetyCrc.compute_s1(bytes([mode.data_crc_mask]), pid_seed_s1)
    a_crc = SafetyCrc.compute_s1(data, a_crc)
    out[off] = a_crc; off += 1

    # Complement CRC-S2 (seeded by S1 PID seed)
    c_crc = SafetyCrc.compute_s2(bytes([mode.complement_data_crc_mask]), pid_seed_s1)
    comp = bytes((b ^ 0xFF) & 0xFF for b in data)
    c_crc = SafetyCrc.compute_s2(comp, c_crc)
    out[off] = c_crc; off += 1

    # Timestamp + CRC-S1
    struct.pack_into('<H', out, off, ts); off += 2
    ts_crc = SafetyCrc.compute_s1(bytes([mode.timestamp_crc_mask]), pid_seed_s1)
    ts_crc = SafetyCrc.compute_s1(struct.pack('<H', ts), ts_crc)
    out[off] = ts_crc; off += 1
    return off


def _decode_base_short(input_bytes: bytes, data_len: int, pid_seed_s1: int) -> SafetyFrameResult:
    expected = data_len + 6
    if len(input_bytes) < expected:
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Input too short for base short frame")

    off = 0
    data = bytes(input_bytes[off:off + data_len]); off += data_len
    mode = ModeByte(input_bytes[off]); off += 1
    wire_a = input_bytes[off]; off += 1
    wire_c = input_bytes[off]; off += 1
    ts, = struct.unpack_from('<H', input_bytes, off); off += 2
    wire_ts_crc = input_bytes[off]; off += 1

    a_crc = SafetyCrc.compute_s1(bytes([mode.data_crc_mask]), pid_seed_s1)
    a_crc = SafetyCrc.compute_s1(data, a_crc)
    if a_crc != wire_a:
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Actual data CRC-S1 mismatch")

    c_crc = SafetyCrc.compute_s2(bytes([mode.complement_data_crc_mask]), pid_seed_s1)
    comp = bytes((b ^ 0xFF) & 0xFF for b in data)
    c_crc = SafetyCrc.compute_s2(comp, c_crc)
    if c_crc != wire_c:
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Complement data CRC-S2 mismatch")

    ts_crc = SafetyCrc.compute_s1(bytes([mode.timestamp_crc_mask]), pid_seed_s1)
    ts_crc = SafetyCrc.compute_s1(struct.pack('<H', ts), ts_crc)
    if ts_crc != wire_ts_crc:
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Timestamp CRC-S1 mismatch")

    return SafetyFrameResult(data, mode, ts, True, None)


# ==================== Base Format Long ====================

def _encode_base_long(out: bytearray, data: bytes, mode: ModeByte,
                       ts: int, pid_seed_s1: int, pid_seed_s3: int) -> int:
    off = 0
    out[off:off + len(data)] = data; off += len(data)
    out[off] = mode.value; off += 1

    # Actual CRC-S3
    a_crc = SafetyCrc.compute_s3(mode.data_crc_mask, pid_seed_s3)
    a_crc = SafetyCrc.compute_s3(data, a_crc)
    struct.pack_into('<H', out, off, a_crc); off += 2

    # Complement data
    comp_off = off
    for i, b in enumerate(data):
        out[comp_off + i] = (b ^ 0xFF) & 0xFF
    comp_slice = bytes(out[comp_off:comp_off + len(data)])
    off += len(data)

    # Complement CRC-S3
    c_crc = SafetyCrc.compute_s3(mode.complement_data_crc_mask, pid_seed_s3)
    c_crc = SafetyCrc.compute_s3(comp_slice, c_crc)
    struct.pack_into('<H', out, off, c_crc); off += 2

    # Timestamp + CRC-S1
    struct.pack_into('<H', out, off, ts); off += 2
    ts_crc = SafetyCrc.compute_s1(bytes([mode.timestamp_crc_mask]), pid_seed_s1)
    ts_crc = SafetyCrc.compute_s1(struct.pack('<H', ts), ts_crc)
    out[off] = ts_crc; off += 1
    return off


def _decode_base_long(input_bytes: bytes, data_len: int,
                       pid_seed_s1: int, pid_seed_s3: int) -> SafetyFrameResult:
    expected = 2 * data_len + 8
    if len(input_bytes) < expected:
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Input too short for base long frame")

    off = 0
    data = bytes(input_bytes[off:off + data_len]); off += data_len
    mode = ModeByte(input_bytes[off]); off += 1
    wire_a, = struct.unpack_from('<H', input_bytes, off); off += 2
    comp_data = bytes(input_bytes[off:off + data_len]); off += data_len
    wire_c, = struct.unpack_from('<H', input_bytes, off); off += 2
    ts, = struct.unpack_from('<H', input_bytes, off); off += 2
    wire_ts_crc = input_bytes[off]; off += 1

    for i in range(data_len):
        if ((data[i] ^ 0xFF) & 0xFF) != comp_data[i]:
            return SafetyFrameResult(b'', ModeByte(0), 0, False, "Actual vs complement data mismatch")

    a_crc = SafetyCrc.compute_s3(mode.data_crc_mask, pid_seed_s3)
    a_crc = SafetyCrc.compute_s3(data, a_crc)
    if a_crc != wire_a:
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Actual data CRC-S3 mismatch")

    c_crc = SafetyCrc.compute_s3(mode.complement_data_crc_mask, pid_seed_s3)
    c_crc = SafetyCrc.compute_s3(comp_data, c_crc)
    if c_crc != wire_c:
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Complement data CRC-S3 mismatch")

    ts_crc = SafetyCrc.compute_s1(bytes([mode.timestamp_crc_mask]), pid_seed_s1)
    ts_crc = SafetyCrc.compute_s1(struct.pack('<H', ts), ts_crc)
    if ts_crc != wire_ts_crc:
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Timestamp CRC-S1 mismatch")

    return SafetyFrameResult(data, mode, ts, True, None)


# ==================== Extended Format Short ====================

def _encode_extended_short(out: bytearray, data: bytes, mode: ModeByte,
                            ts: int, pid_seed_s5: int, rollover_count: int) -> int:
    off = 0
    # Wire: [Data] [Mode] [S5_lo(2)] [Timestamp(2)] [S5_hi(1)]
    out[off:off + len(data)] = data; off += len(data)
    out[off] = mode.value; off += 1

    rc_seed = SafetyCrc.pid_rollover_seed_s5(rollover_count, pid_seed_s5)
    crc_input = bytearray(1 + len(data) + 2)
    crc_input[0] = mode.data_crc_mask
    crc_input[1:1 + len(data)] = data
    struct.pack_into('<H', crc_input, 1 + len(data), ts)
    s5 = SafetyCrc.compute_s5_raw(bytes(crc_input), rc_seed)

    struct.pack_into('<H', out, off, s5 & 0xFFFF); off += 2
    struct.pack_into('<H', out, off, ts); off += 2
    out[off] = (s5 >> 16) & 0xFF; off += 1
    return off


def _decode_extended_short(input_bytes: bytes, data_len: int,
                            pid_seed_s5: int, rollover_count: int) -> SafetyFrameResult:
    expected = data_len + 6
    if len(input_bytes) < expected:
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Input too short for extended short frame")

    off = 0
    data = bytes(input_bytes[off:off + data_len]); off += data_len
    mode = ModeByte(input_bytes[off]); off += 1
    s5_lo, = struct.unpack_from('<H', input_bytes, off); off += 2
    ts, = struct.unpack_from('<H', input_bytes, off); off += 2
    s5_hi = input_bytes[off]; off += 1

    rc_seed = SafetyCrc.pid_rollover_seed_s5(rollover_count, pid_seed_s5)
    crc_input = bytearray(1 + data_len + 2)
    crc_input[0] = mode.data_crc_mask
    crc_input[1:1 + data_len] = data
    struct.pack_into('<H', crc_input, 1 + data_len, ts)
    expected_s5 = SafetyCrc.compute_s5_raw(bytes(crc_input), rc_seed)

    wire_s5 = s5_lo | (s5_hi << 16)
    if wire_s5 != (expected_s5 & 0x00FFFFFF):
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Extended short CRC-S5 mismatch")

    return SafetyFrameResult(data, mode, ts, True, None)


# ==================== Extended Format Long ====================

def _encode_extended_long(out: bytearray, data: bytes, mode: ModeByte,
                           ts: int, pid_seed_s3: int, pid_seed_s5: int,
                           rollover_count: int) -> int:
    off = 0
    # Wire: [Data] [Mode] [CRC-S3(2)] [~Data] [S5_lo(2)] [TS(2)] [S5_hi(1)]
    out[off:off + len(data)] = data; off += len(data)
    out[off] = mode.value; off += 1

    rc_seed_s3 = SafetyCrc.pid_rollover_seed_s3(rollover_count, pid_seed_s3)
    a_crc = SafetyCrc.compute_s3(mode.data_crc_mask, rc_seed_s3)
    a_crc = SafetyCrc.compute_s3(data, a_crc)
    struct.pack_into('<H', out, off, a_crc); off += 2

    comp_off = off
    for i, b in enumerate(data):
        out[comp_off + i] = (b ^ 0xFF) & 0xFF
    comp_slice = bytes(out[comp_off:comp_off + len(data)])
    off += len(data)

    rc_seed_s5 = SafetyCrc.pid_rollover_seed_s5(rollover_count, pid_seed_s5)
    comp_crc_input = bytearray(1 + len(data) + 2)
    comp_crc_input[0] = mode.timestamp_crc_mask  # mode & 0x1F for complement in EF
    comp_crc_input[1:1 + len(data)] = comp_slice
    struct.pack_into('<H', comp_crc_input, 1 + len(data), ts)
    s5 = SafetyCrc.compute_s5_raw(bytes(comp_crc_input), rc_seed_s5)

    struct.pack_into('<H', out, off, s5 & 0xFFFF); off += 2
    struct.pack_into('<H', out, off, ts); off += 2
    out[off] = (s5 >> 16) & 0xFF; off += 1
    return off


def _decode_extended_long(input_bytes: bytes, data_len: int,
                           pid_seed_s3: int, pid_seed_s5: int,
                           rollover_count: int) -> SafetyFrameResult:
    expected = 2 * data_len + 8
    if len(input_bytes) < expected:
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Input too short for extended long frame")

    off = 0
    data = bytes(input_bytes[off:off + data_len]); off += data_len
    mode = ModeByte(input_bytes[off]); off += 1
    wire_a, = struct.unpack_from('<H', input_bytes, off); off += 2
    comp_data = bytes(input_bytes[off:off + data_len]); off += data_len
    s5_lo, = struct.unpack_from('<H', input_bytes, off); off += 2
    ts, = struct.unpack_from('<H', input_bytes, off); off += 2
    s5_hi = input_bytes[off]; off += 1

    for i in range(data_len):
        if ((data[i] ^ 0xFF) & 0xFF) != comp_data[i]:
            return SafetyFrameResult(b'', ModeByte(0), 0, False, "Actual vs complement data mismatch")

    rc_seed_s3 = SafetyCrc.pid_rollover_seed_s3(rollover_count, pid_seed_s3)
    a_crc = SafetyCrc.compute_s3(mode.data_crc_mask, rc_seed_s3)
    a_crc = SafetyCrc.compute_s3(data, a_crc)
    if a_crc != wire_a:
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Actual data CRC-S3 mismatch")

    rc_seed_s5 = SafetyCrc.pid_rollover_seed_s5(rollover_count, pid_seed_s5)
    comp_crc_input = bytearray(1 + data_len + 2)
    comp_crc_input[0] = mode.timestamp_crc_mask
    comp_crc_input[1:1 + data_len] = comp_data
    struct.pack_into('<H', comp_crc_input, 1 + data_len, ts)
    expected_s5 = SafetyCrc.compute_s5_raw(bytes(comp_crc_input), rc_seed_s5)

    wire_s5 = s5_lo | (s5_hi << 16)
    if wire_s5 != (expected_s5 & 0x00FFFFFF):
        return SafetyFrameResult(b'', ModeByte(0), 0, False, "Complement CRC-S5 mismatch")

    return SafetyFrameResult(data, mode, ts, True, None)


# ==================== Time Coordination Messages ====================

def _build_ack_byte(ping_count_reply: int) -> int:
    """AckByte: Ping_Count_Reply (bits 1:0) + Ping_Response=1 (bit 3) + even-parity in bit 7."""
    ack = (ping_count_reply & 0x03) | 0x08
    bit_count = sum(1 for i in range(7) if ack & (1 << i))
    if bit_count % 2:
        ack |= 0x80
    return ack


def encode_tcoo(output: bytearray, ping_count_reply: int,
                consumer_time_value: int, cid_seed_s3: int) -> int:
    """Base-format Time Coordination message (6 bytes).
    Layout: [AckByte] [CTV(2)] [AckByte2] [CRC-S3(2)]."""
    off = 0
    ack = _build_ack_byte(ping_count_reply)
    output[off] = ack; off += 1
    struct.pack_into('<H', output, off, consumer_time_value); off += 2
    ack2 = (((ack ^ 0xFF) & 0x55) | (ack & 0xAA)) & 0xFF
    output[off] = ack2; off += 1
    crc = SafetyCrc.compute_s3(ack, cid_seed_s3)
    crc = SafetyCrc.compute_s3(consumer_time_value, crc)
    struct.pack_into('<H', output, off, crc); off += 2
    return off


def encode_tcoo_extended(output: bytearray, ping_count_reply: int,
                          consumer_time_value: int, pid_seed_s5: int) -> int:
    """Extended-format TCOO (6 bytes).
    Layout: [AckByte] [CTV(2)] [S5_0] [S5_1] [S5_2]."""
    off = 0
    ack = _build_ack_byte(ping_count_reply)
    output[off] = ack; off += 1
    struct.pack_into('<H', output, off, consumer_time_value); off += 2

    s5 = SafetyCrc.compute_s5_raw(bytes([ack]), pid_seed_s5)
    s5 = SafetyCrc.compute_s5_raw(struct.pack('<H', consumer_time_value), s5)

    output[off] = s5 & 0xFF; off += 1
    output[off] = (s5 >> 8) & 0xFF; off += 1
    output[off] = (s5 >> 16) & 0xFF; off += 1
    return off
