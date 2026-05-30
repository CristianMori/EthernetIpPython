"""Build the Forward Open request data for a CIP Safety connection.

Includes the Safety Network Segment (0x50) in the connection path and patches
CPCRC after the rest of the bytes are laid out. The returned tuple is suitable
for passing to EipScanner.send_explicit_raw against the Connection Manager.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field

from .crc import SafetyCrc
from .frame_codec import wire_size
from .network_segment import SafetyNetworkSegment
from .types import (
    SafetyFormat, UniqueNetworkId, SafetyConfigurationId, ZERO_SNN,
)


@dataclass
class SafetyForwardOpenConfig:
    """Parameters for a single safety Forward Open."""
    consumed_assembly: int = 0       # O→T target instance
    produced_assembly: int = 0       # T→O target instance
    config_assembly: int = 0         # configuration instance

    consumed_data_size: int = 0      # bytes (before safety framing)
    produced_data_size: int = 0

    rpi: int = 10_000                # microseconds, applied if direction-specific RPI is 0
    ot_rpi: int = 0
    to_rpi: int = 0

    format: SafetyFormat = SafetyFormat.BASE

    tunid: UniqueNetworkId = field(default_factory=UniqueNetworkId)
    ounid: UniqueNetworkId = field(default_factory=UniqueNetworkId)
    scid: SafetyConfigurationId = field(default_factory=SafetyConfigurationId)

    ping_interval_multiplier: int = 100
    time_coord_msg_min_multiplier: int = 50
    network_time_expectation_multiplier: int = 200
    timeout_multiplier: int = 2
    max_fault_number: int = 2

    initial_timestamp: int = 0xFFFF
    initial_rollover_value: int = 0xFFFF

    connection_timeout_multiplier: int = 1   # *8 for the FwdOpen-level timeout
    priority_time_tick: int = 0x05
    timeout_ticks: int = 156

    # If 0, auto-computed from consumed_data_size + format
    ot_connection_size: int = 0
    to_connection_size: int = 0


CM_PATH = bytes([0x20, 0x06, 0x24, 0x01])  # Connection Manager class 0x06 instance 1


def _assembly_shortcut_path(config: SafetyForwardOpenConfig) -> bytes:
    """Standard shortcut: class 0x04 + config + 2 connection points."""
    return bytes([
        0x20, 0x04,
        0x24, config.config_assembly & 0xFF,
        0x2C, config.consumed_assembly & 0xFF,
        0x2C, config.produced_assembly & 0xFF,
    ])


def build_safety_forward_open(
        config: SafetyForwardOpenConfig,
        conn_serial: int,
        orig_vendor: int,
        orig_serial: int,
        transport_class_trigger: int,
        *,
        route_prefix: bytes = b'',
        app_path: bytes | None = None) -> tuple[bytes, bytes]:
    """Build (service_data, cm_path) for a safety Forward Open.

    transport_class_trigger: 0xA0 = server (target is the consumer),
                             0x20 = client (target is the producer).
    route_prefix is included in the wire path but NOT in CPCRC.
    app_path defaults to the assembly shortcut for the supplied config.
    """
    if app_path is None:
        app_path = _assembly_shortcut_path(config)

    is_extended = config.format == SafetyFormat.EXTENDED
    seg = SafetyNetworkSegment(
        format=0x02 if is_extended else 0x00,
        sccrc=config.scid.sccrc,
        scts=bytes(config.scid.scts.data) if config.scid.sccrc != 0 else bytes(6),
        time_correction_epi=0,
        time_correction_params=0,
        tunid=config.tunid,
        ounid=config.ounid,
        ping_interval_multiplier=config.ping_interval_multiplier,
        time_coord_msg_min_multiplier=config.time_coord_msg_min_multiplier,
        network_time_expectation_multiplier=config.network_time_expectation_multiplier,
        timeout_multiplier=config.timeout_multiplier,
        max_consumer_number=1,
        max_fault_number=config.max_fault_number,
        cpcrc=0,                                  # patched after rest of buffer is built
        time_correction_connection_id=0xFFFFFFFF,
        initial_time_stamp=config.initial_timestamp,
        initial_rollover_value=config.initial_rollover_value,
    )
    safety_seg = bytearray(seg.wire_size)
    seg.encode(safety_seg)

    conn_path = bytearray(len(route_prefix) + len(app_path) + len(safety_seg))
    p = 0
    conn_path[p:p + len(route_prefix)] = route_prefix; p += len(route_prefix)
    conn_path[p:p + len(app_path)] = app_path; p += len(app_path)
    conn_path[p:p + len(safety_seg)] = safety_seg

    # Auto-compute wire sizes if not overridden
    ot_conn_size = (config.ot_connection_size
                    or wire_size(config.consumed_data_size, config.format))
    to_conn_size = (config.to_connection_size
                    or wire_size(config.produced_data_size, config.format))

    # P2P + High priority + fixed (0x4400) + size
    ot_params = 0x4400 | (ot_conn_size & 0x01FF)
    to_params = 0x4400 | (to_conn_size & 0x01FF)

    # Originator picks T→O ID for P2P
    to_conn_id = 0x10000000 | (conn_serial & 0xFFFF)

    ot_rpi = config.ot_rpi or config.rpi
    to_rpi = config.to_rpi or config.rpi

    fwd = bytearray(36 + len(conn_path))
    off = 0
    fwd[off] = config.priority_time_tick; off += 1
    fwd[off] = config.timeout_ticks; off += 1
    struct.pack_into('<I', fwd, off, 0); off += 4         # O→T ID (target chooses)
    struct.pack_into('<I', fwd, off, to_conn_id); off += 4
    struct.pack_into('<H', fwd, off, conn_serial); off += 2
    struct.pack_into('<H', fwd, off, orig_vendor); off += 2
    struct.pack_into('<I', fwd, off, orig_serial); off += 4
    fwd[off] = config.connection_timeout_multiplier; off += 1
    off += 3                                                # reserved
    struct.pack_into('<I', fwd, off, ot_rpi); off += 4
    struct.pack_into('<H', fwd, off, ot_params); off += 2
    struct.pack_into('<I', fwd, off, to_rpi); off += 4
    struct.pack_into('<H', fwd, off, to_params); off += 2
    fwd[off] = transport_class_trigger; off += 1
    fwd[off] = len(conn_path) // 2; off += 1
    fwd[off:off + len(conn_path)] = conn_path

    # ---- CPCRC patch ----
    # CSS IXSCEmisc.c: CRC-S4 over
    #     ConnSerial(2) + OrigVendor(2)
    #   + TimeoutMult..PathSize (18 bytes from fwdOpenData[18])
    #   + ekey/app_path (NO route prefix)
    #   + 48 or 50 bytes from the 0x50 byte of the safety segment (CPCRC field still 0)
    safety_off_in_conn_path = len(route_prefix) + len(app_path)
    nsd_size = 50 if is_extended else 48
    crc_input = bytearray(4 + 18 + len(app_path) + nsd_size)
    ci = 0
    crc_input[ci:ci + 4] = fwd[10:14]; ci += 4
    crc_input[ci:ci + 18] = fwd[18:36]; ci += 18
    # Adapter computes CPCRC against the path WITHOUT the route prefix —
    # patch PathSize at the last byte of the 18-byte window to match.
    crc_input[ci - 1] = (len(app_path) + len(safety_seg)) // 2
    crc_input[ci:ci + len(app_path)] = app_path; ci += len(app_path)
    crc_input[ci:ci + nsd_size] = conn_path[safety_off_in_conn_path:safety_off_in_conn_path + nsd_size]
    ci += nsd_size

    cpcrc = SafetyCrc.compute_s4(bytes(crc_input[:ci]))

    cpcrc_abs = (36 + safety_off_in_conn_path
                 + (50 if is_extended else 48))
    struct.pack_into('<I', fwd, cpcrc_abs, cpcrc)

    return bytes(fwd), CM_PATH
