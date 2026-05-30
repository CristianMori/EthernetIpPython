"""I/O connection state — created by Forward Open, managed by VirtualDevice."""

from __future__ import annotations
from enum import IntEnum
from dataclasses import dataclass, field
from datetime import datetime, timezone


class ConnectionState(IntEnum):
    NON_EXISTENT = 0
    ESTABLISHED = 1
    TIMED_OUT = 2


class TransportClass(IntEnum):
    CLASS0 = 0
    CLASS1 = 1
    CLASS2 = 2
    CLASS3 = 3   # Connected explicit messaging (pycomm3 uses this after FwdOpen)
    CLASS4 = 4
    CLASS5 = 5
    CLASS6 = 6   # CIP Safety transport


_MULTIPLIER_TABLE = {0: 4, 1: 8, 2: 16, 3: 32, 4: 64, 5: 128, 6: 256, 7: 512}


class IoConnection:
    """A single I/O connection established via Forward Open."""

    def __init__(self):
        # Connection triad
        self.connection_serial_number: int = 0
        self.originator_vendor_id: int = 0
        self.originator_serial_number: int = 0

        # Connection IDs on the wire
        self.ot_connection_id: int = 0  # O→T (scanner sends to us with this ID)
        self.to_connection_id: int = 0  # T→O (we send to scanner with this ID)

        # Assembly references
        self.consumed_assembly_instance: int = 0
        self.produced_assembly_instance: int = 0
        self.config_assembly_instance: int = 0
        # Config data carried in the Forward Open path's Simple Data Segment
        # (0x80). For a Generic Ethernet Module this is the config-assembly
        # payload the originator pushes at FwdOpen time. Empty if absent.
        self.config_data: bytes = b''

        # Connection parameters
        self.ot_rpi: int = 0        # microseconds
        self.to_rpi: int = 0        # microseconds
        self.ot_size: int = 0       # bytes on wire
        self.to_size: int = 0       # bytes on wire
        self.transport_class: TransportClass = TransportClass.CLASS1
        self.timeout_multiplier: int = 0

        # Network
        self.remote_endpoint: tuple[str, int] | None = None

        # Sequence tracking
        self.encapsulation_sequence_number: int = 0
        self.cip_sequence_count: int = 0

        # State
        self.state: ConnectionState = ConnectionState.ESTABLISHED
        self.last_received_utc: datetime = datetime.now(timezone.utc)

        # Timers (managed externally)
        self._watchdog_task = None
        self._production_task = None

        # ---- Safety-specific runtime state (used only when is_safety=True) ----
        self.is_safety: bool = False
        self.safety_format: int = 0           # 0=Base, 2=Extended (from FwdOpen safety segment byte)
        self.safety_segment_data: bytes = b''  # raw safety segment from FwdOpen path
        # CRC seeds — precomputed once at FwdOpen time
        self.safety_pid_seed_s1: int = 0
        self.safety_pid_seed_s3: int = 0
        self.safety_pid_seed_s5: int = 0
        # Originator PID seeds — for verifying data ORIGINATOR produces on O→T
        self.safety_originator_pid_seed_s1: int = 0
        self.safety_originator_pid_seed_s3: int = 0
        self.safety_originator_pid_seed_s5: int = 0
        self.safety_cid_seed_s3: int = 0
        self.safety_cid_seed_s5: int = 0
        # Producer-side runtime state
        self.safety_consumer_active: bool = False     # set True on first TCOO from consumer
        self.safety_timestamp: int = 0
        self.safety_rollover_count: int = 0
        self.safety_initial_timestamp: int = 0
        self.safety_initial_rollover_value: int = 0
        self.safety_last_produced_timestamp: int = 0
        self.safety_last_sent_ticks: int = 0
        self.safety_last_frame_sent_ticks: int = 0
        self.safety_production_start_ticks: int = 0
        # Time-correction
        self.safety_connection_correction_constant: int = 0
        self.safety_consumer_time_correction_value: int = 0
        self.safety_consumer_time_correction_goal: int = 0
        self.safety_time_correction_initialized: bool = False
        # Ping cadence
        self.safety_ping_count: int = 0
        self.safety_last_ping_count: int = 0xFF       # 0xFF = unset (sentinel)
        self.safety_ping_interval_us: int = 0
        self.safety_last_ping_change_ticks: int = 0
        # Consumer-side runtime state
        self.safety_originator_rollover_count: int = 0
        self.safety_originator_rollover_initialized: bool = False
        self.safety_originator_last_ts: int = 0       # last incoming wire ts, for wrap detection
        self.safety_plc_running: bool = False
        # Diagnostics (set when StartupTraceSeconds > 0 at FwdOpen time)
        self.safety_startup_trace_until_ticks: int = 0  # perf_counter_ns deadline
        self.safety_need_time_coordination: bool = False
        # CIP Safety Validator instance bound to this connection
        self.safety_validator_instance_id: int = 0

    @property
    def connection_timeout_us(self) -> int:
        """Connection timeout in microseconds."""
        mult = _MULTIPLIER_TABLE.get(self.timeout_multiplier, 4)
        return self.ot_rpi * mult

    def close(self) -> None:
        self.state = ConnectionState.NON_EXISTENT
