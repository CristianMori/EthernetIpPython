"""Safety Network Segment (0x50) — parser/encoder for Forward Open paths.

Wire layout:
    [0x50] [DataLengthWords] [Format] [SegmentData...]

Three formats:
    0x00 = Target Format    (56 bytes total, 27 words data)
    0x01 = Router Format    (14 bytes total,  6 words data)
    0x02 = Extended Format  (62 bytes total, 30 words data — adds Max_Fault_Number,
           Initial_Time_Stamp, Initial_Rollover_Value vs Target Format)
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import Tuple

from .types import UniqueNetworkId


SEGMENT_TYPE = 0x50


@dataclass
class SafetyNetworkSegment:
    """Mutable so callers can build incrementally on the originator side."""
    format: int = 0
    sccrc: int = 0
    scts: bytes = b'\x00' * 6
    time_correction_epi: int = 0
    time_correction_params: int = 0
    tunid: UniqueNetworkId = field(default_factory=UniqueNetworkId)
    ounid: UniqueNetworkId = field(default_factory=UniqueNetworkId)
    ping_interval_multiplier: int = 0
    time_coord_msg_min_multiplier: int = 0
    network_time_expectation_multiplier: int = 0
    timeout_multiplier: int = 0
    max_consumer_number: int = 0
    cpcrc: int = 0
    time_correction_connection_id: int = 0
    # Extended format (0x02) only:
    max_fault_number: int = 0
    initial_time_stamp: int = 0
    initial_rollover_value: int = 0

    @property
    def wire_size(self) -> int:
        return {0x00: 56, 0x01: 14, 0x02: 62}.get(self.format, 2)

    def encode(self, output: bytearray, offset: int = 0) -> int:
        """Encode Target (0x00) or Extended (0x02) format. Returns bytes written."""
        is_extended = self.format == 0x02
        data_len_words = 0x1E if is_extended else 0x1B  # 30 or 27 words

        o = offset
        output[o] = SEGMENT_TYPE; o += 1
        output[o] = data_len_words; o += 1
        output[o] = self.format; o += 1
        output[o] = 0; o += 1  # reserved pad

        struct.pack_into('<I', output, o, self.sccrc); o += 4
        if len(self.scts) != 6:
            raise ValueError("scts must be 6 bytes")
        output[o:o + 6] = self.scts; o += 6
        struct.pack_into('<I', output, o, self.time_correction_epi); o += 4
        struct.pack_into('<H', output, o, self.time_correction_params); o += 2
        self.tunid.copy_to(output, o); o += UniqueNetworkId.SIZE
        self.ounid.copy_to(output, o); o += UniqueNetworkId.SIZE
        struct.pack_into('<H', output, o, self.ping_interval_multiplier); o += 2
        struct.pack_into('<H', output, o, self.time_coord_msg_min_multiplier); o += 2
        struct.pack_into('<H', output, o, self.network_time_expectation_multiplier); o += 2
        output[o] = self.timeout_multiplier; o += 1
        output[o] = self.max_consumer_number; o += 1

        if is_extended:
            struct.pack_into('<H', output, o, self.max_fault_number); o += 2

        struct.pack_into('<I', output, o, self.cpcrc); o += 4
        struct.pack_into('<I', output, o, self.time_correction_connection_id); o += 4

        if is_extended:
            struct.pack_into('<H', output, o, self.initial_time_stamp); o += 2
            struct.pack_into('<H', output, o, self.initial_rollover_value); o += 2

        return o - offset


def parse_safety_segment(data: bytes) -> Tuple[SafetyNetworkSegment, int]:
    """Parse a safety segment starting at the 0x50 byte. Returns (segment, bytes_consumed)."""
    if len(data) < 3 or data[0] != SEGMENT_TYPE:
        raise ValueError("Not a safety network segment")

    data_len_words = data[1]
    total = 2 + data_len_words * 2
    format_ = data[2]

    if len(data) < total:
        raise ValueError(f"Safety segment requires {total} bytes, got {len(data)}")

    if format_ == 0x01:  # Router format
        tc_conn_id, = struct.unpack_from('<I', data, 4)
        tc_epi, = struct.unpack_from('<I', data, 8)
        tc_params, = struct.unpack_from('<H', data, 12)
        return SafetyNetworkSegment(
            format=0x01,
            time_correction_connection_id=tc_conn_id,
            time_correction_epi=tc_epi,
            time_correction_params=tc_params,
        ), total

    # Target (0x00) and Extended (0x02) share the base layout
    off = 4  # past type + length + format + reserved
    sccrc, = struct.unpack_from('<I', data, off); off += 4
    scts = bytes(data[off:off + 6]); off += 6
    tc_epi, = struct.unpack_from('<I', data, off); off += 4
    tc_params, = struct.unpack_from('<H', data, off); off += 2
    tunid = UniqueNetworkId.parse(data[off:off + UniqueNetworkId.SIZE]); off += UniqueNetworkId.SIZE
    ounid = UniqueNetworkId.parse(data[off:off + UniqueNetworkId.SIZE]); off += UniqueNetworkId.SIZE
    ping_mult, tc_msg_mult, nte_mult = struct.unpack_from('<HHH', data, off); off += 6
    timeout_mult = data[off]; off += 1
    max_consumer = data[off]; off += 1

    max_fault_num = 0
    if format_ == 0x02:
        max_fault_num, = struct.unpack_from('<H', data, off); off += 2

    cpcrc, tc_conn_id = struct.unpack_from('<II', data, off); off += 8

    init_ts = 0
    init_rollover = 0
    if format_ == 0x02:
        init_ts, init_rollover = struct.unpack_from('<HH', data, off); off += 4

    return SafetyNetworkSegment(
        format=format_, sccrc=sccrc, scts=scts,
        time_correction_epi=tc_epi, time_correction_params=tc_params,
        tunid=tunid, ounid=ounid,
        ping_interval_multiplier=ping_mult,
        time_coord_msg_min_multiplier=tc_msg_mult,
        network_time_expectation_multiplier=nte_mult,
        timeout_multiplier=timeout_mult, max_consumer_number=max_consumer,
        max_fault_number=max_fault_num,
        cpcrc=cpcrc, time_correction_connection_id=tc_conn_id,
        initial_time_stamp=init_ts, initial_rollover_value=init_rollover,
    ), total
