"""Connection Parameter CRC (CPCRC) — CRC-S4 over Forward Open fields.

Used by both originator (to build SafetyOpen) and target (to validate).

CPCRC covers (in order):
    Connection Serial Number, Originator Vendor ID, Originator Serial Number,
    Connection Timeout Multiplier, O→T RPI, O→T Network Connection Parameters,
    T→O RPI, T→O Network Connection Parameters, Transport Type/Trigger,
    Connection Path Size (adjusted), Connection Path (without safety/routing segments),
    Safety segment fields (SCCRC, SCTS, timing params, TUNID, OUNID, etc.)
"""
from __future__ import annotations
import struct

from .crc import SafetyCrc
from .network_segment import SafetyNetworkSegment
from .types import UniqueNetworkId


def compute_cpcrc(
    connection_serial_number: int,
    originator_vendor_id: int,
    originator_serial_number: int,
    connection_timeout_multiplier: int,
    oto_t_rpi: int,
    oto_t_network_params: int,
    tto_o_rpi: int,
    tto_o_network_params: int,
    transport_class_trigger: int,
    connection_path_size_words: int,
    connection_path: bytes,
    safety_segment: SafetyNetworkSegment,
) -> int:
    """Compute the CPCRC from Forward Open parameters and the safety segment.

    `connection_path` is the application path only (no routing or safety segments).
    `connection_path_size_words` should equal len(connection_path) // 2.
    """
    buf = bytearray(256 + len(connection_path))
    o = 0

    # Connection triad
    struct.pack_into('<HHI', buf, o,
                     connection_serial_number,
                     originator_vendor_id,
                     originator_serial_number); o += 8

    # Connection timeout multiplier
    buf[o] = connection_timeout_multiplier; o += 1

    # O→T RPI + params
    struct.pack_into('<IH', buf, o, oto_t_rpi, oto_t_network_params); o += 6

    # T→O RPI + params
    struct.pack_into('<IH', buf, o, tto_o_rpi, tto_o_network_params); o += 6

    # Transport type/trigger
    buf[o] = transport_class_trigger; o += 1

    # Connection path size (in words) — pre-adjusted to exclude routing segments
    buf[o] = connection_path_size_words; o += 1

    # Connection path (application path only)
    buf[o:o + len(connection_path)] = connection_path; o += len(connection_path)

    # Safety segment fields covered by CPCRC (everything except CPCRC itself)
    struct.pack_into('<I', buf, o, safety_segment.sccrc); o += 4
    if len(safety_segment.scts) != 6:
        raise ValueError("safety_segment.scts must be 6 bytes")
    buf[o:o + 6] = safety_segment.scts; o += 6
    struct.pack_into('<I', buf, o, safety_segment.time_correction_epi); o += 4
    struct.pack_into('<H', buf, o, safety_segment.time_correction_params); o += 2
    safety_segment.tunid.copy_to(buf, o); o += UniqueNetworkId.SIZE
    safety_segment.ounid.copy_to(buf, o); o += UniqueNetworkId.SIZE
    struct.pack_into('<HHH', buf, o,
                     safety_segment.ping_interval_multiplier,
                     safety_segment.time_coord_msg_min_multiplier,
                     safety_segment.network_time_expectation_multiplier); o += 6
    buf[o] = safety_segment.timeout_multiplier; o += 1
    buf[o] = safety_segment.max_consumer_number; o += 1
    struct.pack_into('<I', buf, o, safety_segment.time_correction_connection_id); o += 4

    return SafetyCrc.compute_s4(bytes(buf[:o]))
