"""CIP Safety EtherNet/IP device.

Extends VirtualDevice with safety frame encoding/decoding, time
coordination (TCOO), CRC seed computation, and safety connection lifecycle.
Implements the SafetyConnectionHandler protocol so ConnectionManager can
delegate safety-specific validation and configuration to it.
"""
from __future__ import annotations
import struct
import time

from ..cip.identity_info import IdentityInfo
from ..connections.io_connection import IoConnection, ConnectionState
from ..connections.forward_open_request import ForwardOpenRequest
from ..device.virtual_device import VirtualDevice

from .crc import SafetyCrc
from .frame_codec import (
    SafetyFormat, wire_size, encode_safety_frame, decode_safety_frame,
    extract_timestamp, encode_tcoo, encode_tcoo_extended,
)
from .network_segment import parse_safety_segment
from .supervisor_object import SafetySupervisorObject
from .types import (
    ModeByte, SafetyNetworkNumber, SafetyConfigurationId, UniqueNetworkId,
)
from .validator_object import SafetyValidatorObject, SafetyValidatorState


def _now_ns() -> int:
    """Monotonic high-res tick — equivalent to Stopwatch.GetTimestamp()."""
    return time.perf_counter_ns()


class SafetyDevice(VirtualDevice):
    """A safety-capable virtual EtherNet/IP device.

    Per-frame and per-TCOO trace logging is disabled by default; enable
    via ``SafetyDevice.enable_trace = True`` only while actively debugging,
    and use ``startup_trace_seconds`` to limit per-frame trace to the first
    N seconds of each new connection.
    """

    enable_trace: bool = False
    startup_trace_seconds: int = 0

    # Counter so successive accepted Initial_Rollover_Value choices are
    # distinct in the rare case the kernel returns the same monotonic tick.
    _initial_rc_offset: int = 0

    def __init__(self, identity: IdentityInfo, bind_address: str,
                 snn: SafetyNetworkNumber, node_address: int,
                 name: str | None = None):
        super().__init__(identity, bind_address, name)

        self._supervisor = SafetySupervisorObject(snn, node_address)
        self._validator = SafetyValidatorObject()

        self.dispatcher.register_class(self._supervisor.cip_class)
        self.dispatcher.register_class(self._validator.cip_class)

        self.connection_manager.safety_handler = self
        self.connection_manager.on_connection_removed.append(self._on_connection_removed)

        self._supervisor.start()

    # ---- SafetyConnectionHandler Protocol ----

    @property
    def vendor_id(self) -> int:
        return self.identity.vendor_id

    @property
    def serial_number(self) -> int:
        return self.identity.serial_number

    def validate_safety_open(self, safety_segment: bytes,
                              fwd_open: ForwardOpenRequest) -> int | None:
        if len(safety_segment) < 3 or safety_segment[0] != 0x50:
            return 0x080E
        seg, _ = parse_safety_segment(safety_segment)

        # 1. TUNID must match ours
        our_tunid = bytearray(UniqueNetworkId.SIZE)
        self._supervisor.tunid.copy_to(our_tunid)
        seg_tunid = bytearray(UniqueNetworkId.SIZE)
        seg.tunid.copy_to(seg_tunid)
        if bytes(our_tunid) != bytes(seg_tunid):
            return 0x080E

        # 2. CPCRC validation against the connection path layout
        conn_path = fwd_open.connection_path
        safety_off = -1
        for i in range(len(conn_path) - 1):
            if conn_path[i] == 0x50:
                safety_off = i
                break
        if safety_off < 0:
            return 0x080E

        e_key_app_path = conn_path[:safety_off]
        nsd_size = 50 if seg.format == 0x02 else 48
        nsd_bytes = conn_path[safety_off:safety_off + nsd_size]

        # CPCRC input layout (matches the PLC's computation, which uses the
        # raw bytes of the FwdOpen service data):
        #   [bytes 10..14]  → conn_serial(2) + orig_vendor(2) of FwdOpen
        #   [bytes 18..36]  → timeout_mult, reserved, OT_RPI, OT_params,
        #                     TO_RPI, TO_params, transport_class_trigger,
        #                     path_size_words (16-bit-params layout)
        #   [E-key app path bytes]
        #   [nsd_size bytes of the safety segment (48 or 50)]
        sd = fwd_open.raw_service_data
        crc_buf = bytearray(4 + 18 + len(e_key_app_path) + nsd_size)
        off = 0
        crc_buf[off:off + 4] = sd[10:14]; off += 4
        crc_buf[off:off + 18] = sd[18:36]; off += 18
        crc_buf[off:off + len(e_key_app_path)] = e_key_app_path
        off += len(e_key_app_path)
        crc_buf[off:off + nsd_size] = nsd_bytes
        off += nsd_size

        computed = SafetyCrc.compute_s4(bytes(crc_buf[:off]))
        if computed != seg.cpcrc:
            return 0x080D

        # 3. SCID check — if we have an SCID and the segment carries one, they must match.
        has_scid = self._supervisor.scid.sccrc != 0
        if not has_scid:
            return None
        if seg.sccrc != 0 and seg.sccrc != self._supervisor.scid.sccrc:
            return 0x0111
        return None

    def configure_safety_connection(self, conn: IoConnection,
                                     fwd_open: ForwardOpenRequest) -> None:
        is_server = (fwd_open.transport_class_trigger & 0x80) != 0

        seg = None
        if len(conn.safety_segment_data) >= 3 and conn.safety_segment_data[0] == 0x50:
            seg, _ = parse_safety_segment(conn.safety_segment_data)

            # Store CFUNID (= originator UNID) on supervisor attribute 25
            sv_inst = self._supervisor.cip_class.get_instance(1)
            cfunid = bytearray(UniqueNetworkId.SIZE)
            seg.ounid.copy_to(cfunid)
            if sv_inst is not None:
                a25 = sv_inst.get_attribute(25)
                if a25 is not None:
                    a25.set_data(bytes(cfunid))

                # Store SCID on attribute 6
                scid_bytes = bytearray(SafetyConfigurationId.SIZE)
                struct.pack_into('<I', scid_bytes, 0, seg.sccrc)
                scid_bytes[4:10] = seg.scts
                a6 = sv_inst.get_attribute(6)
                if a6 is not None:
                    a6.set_data(bytes(scid_bytes))

            self._supervisor.scid = SafetyConfigurationId(
                sccrc=seg.sccrc,
                scts=SafetyNetworkNumber(seg.scts) if seg.scts else SafetyNetworkNumber(),
            )

            # Initial_TS / Initial_Rollover_Value handling:
            # - Target PRODUCER (client direction): echo originator's values.
            # - Target CONSUMER (server direction): generate fresh values. The
            #   PLC caches the originator's Initial_Rollover_Value per device
            #   identity, so use a deterministic value (0) so its cache is
            #   always consistent with what we use to decode incoming frames.
            if is_server:
                conn.safety_initial_timestamp = 0
                conn.safety_initial_rollover_value = 0
            else:
                conn.safety_initial_timestamp = seg.initial_time_stamp
                conn.safety_initial_rollover_value = seg.initial_rollover_value

            conn.safety_ping_interval_us = seg.ping_interval_multiplier * conn.to_rpi

            # Connection_Correction_Constant = Time_Drift_Constant + 1 - Time_Coord_Msg_Min_Multiplier
            # Time_Drift_Constant = Roundup((Timeout_Mult+1) * EPI * PingIntMult / 320000)
            epi_us = conn.to_rpi
            time_drift = ((seg.timeout_multiplier + 1) * epi_us
                          * seg.ping_interval_multiplier + 319_999) // 320_000
            if time_drift < 1:
                time_drift = 1
            conn.safety_connection_correction_constant = (
                time_drift + 1 - seg.time_coord_msg_min_multiplier) & 0xFFFF

        if self.startup_trace_seconds > 0:
            conn.safety_startup_trace_until_ticks = (
                _now_ns() + self.startup_trace_seconds * 1_000_000_000)

        validator = self._validator.create_instance(conn)
        validator.state = SafetyValidatorState.EXECUTING
        sv_inst_id = validator.instance_id & 0xFFFF

        # Target PID — for data WE produce on T→O
        conn.safety_pid_seed_s1 = SafetyCrc.pid_cid_seed_s1(
            self.identity.vendor_id, self.identity.serial_number, sv_inst_id)
        conn.safety_pid_seed_s3 = SafetyCrc.pid_cid_seed_s3(
            self.identity.vendor_id, self.identity.serial_number, sv_inst_id)
        conn.safety_pid_seed_s5 = SafetyCrc.pid_cid_seed_s5(
            self.identity.vendor_id, self.identity.serial_number, sv_inst_id)

        # Originator PID — for verifying data ORIGINATOR produces on O→T
        conn.safety_originator_pid_seed_s1 = SafetyCrc.pid_cid_seed_s1(
            fwd_open.originator_vendor_id, fwd_open.originator_serial_number,
            fwd_open.connection_serial_number)
        conn.safety_originator_pid_seed_s3 = SafetyCrc.pid_cid_seed_s3(
            fwd_open.originator_vendor_id, fwd_open.originator_serial_number,
            fwd_open.connection_serial_number)
        conn.safety_originator_pid_seed_s5 = SafetyCrc.pid_cid_seed_s5(
            fwd_open.originator_vendor_id, fwd_open.originator_serial_number,
            fwd_open.connection_serial_number)

        # CID = CONSUMER's identity + CONSUMER's connection serial number
        if is_server:
            conn.safety_cid_seed_s3 = SafetyCrc.pid_cid_seed_s3(
                self.identity.vendor_id, self.identity.serial_number, sv_inst_id)
            conn.safety_cid_seed_s5 = SafetyCrc.pid_cid_seed_s5(
                self.identity.vendor_id, self.identity.serial_number, sv_inst_id)
        else:
            conn.safety_cid_seed_s3 = SafetyCrc.pid_cid_seed_s3(
                fwd_open.originator_vendor_id, fwd_open.originator_serial_number,
                fwd_open.connection_serial_number)
            conn.safety_cid_seed_s5 = SafetyCrc.pid_cid_seed_s5(
                fwd_open.originator_vendor_id, fwd_open.originator_serial_number,
                fwd_open.connection_serial_number)

        conn.safety_validator_instance_id = sv_inst_id
        conn.safety_last_ping_count = 0xFF

    # ---- VirtualDevice overrides ----

    def on_connection_ready(self, conn: IoConnection) -> None:
        # Default behavior — production starts on its own. SafetyDevice
        # relies on the same producer loop; the first frames go out as IDLE
        # until the first TCOO arrives.
        return

    def produce_io_data(self, conn: IoConnection) -> None:
        if not conn.is_safety:
            super().produce_io_data(conn)
            return
        if conn.state != ConnectionState.ESTABLISHED:
            return

        assembly = self.assemblies.get_assembly(conn.produced_assembly_instance)
        if assembly is None:
            return

        # TCOO-only direction (server side with 0-byte assembly): nothing to
        # produce cyclically; we only send TCOOs in response to incoming pings.
        if conn.to_size == 6 and assembly.data_size == 0:
            return

        base_size = wire_size(assembly.data_size, SafetyFormat.BASE)
        ext_size = wire_size(assembly.data_size, SafetyFormat.EXTENDED)
        if conn.to_size != base_size and conn.to_size != ext_size:
            return

        fmt = SafetyFormat.EXTENDED if conn.safety_format == 0x02 else SafetyFormat.BASE
        consumer_active = conn.safety_consumer_active
        run_idle = consumer_active

        if consumer_active:
            now_ticks = _now_ns()
            conn.safety_last_frame_sent_ticks = now_ticks
            elapsed_us = (now_ticks - conn.safety_production_start_ticks) // 1000
            raw_ticks = conn.safety_initial_timestamp + elapsed_us // 128
            raw_timestamp = raw_ticks & 0xFFFF
            conn.safety_last_produced_timestamp = raw_timestamp

            # Slew applied CTCV toward goal — large jumps take ~8 frames.
            goal = conn.safety_consumer_time_correction_goal
            applied = conn.safety_consumer_time_correction_value
            if applied != goal:
                # 16-bit signed delta
                slew_delta = ((goal - applied) & 0xFFFF)
                if slew_delta & 0x8000:
                    slew_delta -= 0x10000
                if slew_delta > 0:
                    step = max(1, slew_delta // 8)
                    if step > slew_delta:
                        step = slew_delta
                    conn.safety_consumer_time_correction_value = (applied + step) & 0xFFFF
                else:
                    # TCOO handler refuses negative deltas, so this shouldn't
                    # happen — be defensive and snap.
                    conn.safety_consumer_time_correction_value = goal

            corrected_ticks = raw_ticks + conn.safety_consumer_time_correction_value
            prev_sent_ticks = conn.safety_last_sent_ticks
            delta_ticks = corrected_ticks - prev_sent_ticks
            if prev_sent_ticks != 0 and delta_ticks < 0:
                if self.enable_trace:
                    print(f"[GUARD] conn={conn.connection_serial_number:04X} "
                          f"rawTicks={raw_ticks} correctedTicks={corrected_ticks} "
                          f"prevSentTicks={prev_sent_ticks} delta={delta_ticks} "
                          f"CTCV={conn.safety_consumer_time_correction_value} -> force prev+1")
                corrected_ticks = prev_sent_ticks + 1

            timestamp = corrected_ticks & 0xFFFF
            conn.safety_timestamp = timestamp
            conn.safety_last_sent_ticks = corrected_ticks
            conn.safety_rollover_count = (
                conn.safety_initial_rollover_value + (corrected_ticks >> 16)) & 0xFFFF

            if self.enable_trace and (conn.encapsulation_sequence_number % 1000) == 0:
                print(f"[FRAME] conn={conn.connection_serial_number:04X} "
                      f"seq={conn.encapsulation_sequence_number} raw={raw_timestamp} "
                      f"sent={timestamp} CTCV={conn.safety_consumer_time_correction_value}")

            if (conn.safety_startup_trace_until_ticks > 0
                    and _now_ns() < conn.safety_startup_trace_until_ticks):
                print(f"[SU-SEND] conn={conn.connection_serial_number:04X} "
                      f"seq={conn.encapsulation_sequence_number} raw={raw_timestamp} "
                      f"CTCV={conn.safety_consumer_time_correction_value} wire_ts={timestamp}")
        else:
            timestamp = 0

        if consumer_active:
            now = _now_ns()
            if conn.safety_last_ping_change_ticks == 0:
                conn.safety_last_ping_change_ticks = now
            ping_elapsed_us = (now - conn.safety_last_ping_change_ticks) // 1000
            if (conn.safety_ping_interval_us > 0
                    and ping_elapsed_us >= conn.safety_ping_interval_us):
                conn.safety_last_ping_change_ticks = now
                conn.safety_ping_count = (conn.safety_ping_count + 1) & 0x03

        mode = ModeByte.create(run_idle=run_idle, ping_count=conn.safety_ping_count)

        asm_data = bytearray(assembly.data_size)
        assembly.copy_data_to(asm_data)

        safety_buf = bytearray(assembly.data_size * 2 + 16)
        safety_len = encode_safety_frame(
            safety_buf, bytes(asm_data), fmt, mode, timestamp,
            conn.safety_pid_seed_s1, conn.safety_pid_seed_s3, conn.safety_pid_seed_s5,
            conn.safety_rollover_count)
        if safety_len > 0:
            self.to_send_count += 1
            self.send_udp_io_data(conn, bytes(safety_buf[:safety_len]))

    def handle_received_io_data(self, conn: IoConnection, data: bytes) -> None:
        if not conn.is_safety:
            super().handle_received_io_data(conn, data)
            return

        wire_len = len(data)

        # TCOO from PLC consumer
        if wire_len in (5, 6):
            if not conn.safety_consumer_active:
                conn.safety_consumer_active = True
                conn.safety_timestamp = conn.safety_initial_timestamp
                conn.safety_rollover_count = conn.safety_initial_rollover_value
                conn.safety_production_start_ticks = _now_ns()

            if len(data) >= 3:
                consumer_time_value, = struct.unpack_from('<H', data, 1)

                if (conn.safety_startup_trace_until_ticks > 0
                        and _now_ns() < conn.safety_startup_trace_until_ticks):
                    send_gap_us = -1
                    if conn.safety_last_frame_sent_ticks != 0:
                        send_gap_us = (_now_ns() - conn.safety_last_frame_sent_ticks) // 1000
                    print(f"[SU-RECV-TCOO] conn={conn.connection_serial_number:04X} "
                          f"ctv={consumer_time_value} ack=0x{data[0]:02X} "
                          f"lastRaw={conn.safety_last_produced_timestamp} "
                          f"CTCV={conn.safety_consumer_time_correction_value} "
                          f"sendGap={send_gap_us}us")

                # Outlier check: reject TCOOs whose send-to-arrival gap exceeds 2ms.
                if conn.safety_last_frame_sent_ticks != 0:
                    send_to_tcoo_us = (_now_ns() - conn.safety_last_frame_sent_ticks) // 1000
                    if send_to_tcoo_us > 2_000:
                        if self.enable_trace:
                            print(f"[TCOO-LATE] conn={conn.connection_serial_number:04X} "
                                  f"ctv={consumer_time_value} sendToTcoo={send_to_tcoo_us}us "
                                  f"— skipping CTCV update")
                        return

                worst_case_ctcv = (consumer_time_value
                                    - conn.safety_last_produced_timestamp
                                    - conn.safety_connection_correction_constant) & 0xFFFF

                old_ctcv = conn.safety_consumer_time_correction_value
                # 16-bit signed delta
                delta = (worst_case_ctcv - old_ctcv) & 0xFFFF
                if delta & 0x8000:
                    delta -= 0x10000

                if not conn.safety_time_correction_initialized:
                    conn.safety_time_correction_initialized = True
                    if self.enable_trace:
                        print(f"[CTCV-INIT] conn={conn.connection_serial_number:04X} "
                              f"ctv={consumer_time_value} "
                              f"lastRaw={conn.safety_last_produced_timestamp} "
                              f"CCC={conn.safety_connection_correction_constant} "
                              f"would_be_CTCV={worst_case_ctcv} (SKIPPED first TCOO)")
                else:
                    instant_apply_threshold = max(1, conn.to_rpi // 128)

                    new_applied = old_ctcv
                    new_goal = conn.safety_consumer_time_correction_goal
                    if delta <= 0:
                        note = "skipped (delta <= 0)"
                    elif old_ctcv == 0:
                        new_applied = worst_case_ctcv
                        new_goal = worst_case_ctcv
                        note = f"applied instantly (first real CTCV, delta={delta})"
                    elif delta <= instant_apply_threshold:
                        new_applied = worst_case_ctcv
                        new_goal = worst_case_ctcv
                        note = f"applied instantly (delta={delta} <= {instant_apply_threshold})"
                    else:
                        # Big jump — set goal only and let produce_io_data slew.
                        goal_delta = (worst_case_ctcv - new_goal) & 0xFFFF
                        if goal_delta & 0x8000:
                            goal_delta -= 0x10000
                        if goal_delta > 0:
                            new_goal = worst_case_ctcv
                        note = f"slewing (delta={delta} > {instant_apply_threshold}, goal={new_goal})"
                    conn.safety_consumer_time_correction_value = new_applied
                    conn.safety_consumer_time_correction_goal = new_goal
                    if self.enable_trace:
                        print(f"[CTCV] conn={conn.connection_serial_number:04X} "
                              f"ctv={consumer_time_value} "
                              f"lastRaw={conn.safety_last_produced_timestamp} "
                              f"CCC={conn.safety_connection_correction_constant} "
                              f"oldCTCV={old_ctcv} proposed={worst_case_ctcv} -> {note} "
                              f"appliedCTCV={new_applied}")
            return

        # Decode safety data frame
        fmt = SafetyFormat.EXTENDED if conn.safety_format == 0x02 else SafetyFormat.BASE
        data_len = _estimate_data_length(wire_len)
        if data_len <= 0:
            return

        # Track originator's rollover count separately from ours; the Extended
        # format CRC seed depends on it and the producer's clock can diverge
        # from ours during startup.
        incoming_ts = extract_timestamp(data, data_len, fmt)
        if not conn.safety_originator_rollover_initialized:
            conn.safety_originator_rollover_count = conn.safety_initial_rollover_value
            conn.safety_originator_last_ts = incoming_ts
            conn.safety_originator_rollover_initialized = True
        else:
            # Raw int subtraction (matches C# `int delta = ushort - ushort`) —
            # a wrap shows as a large-magnitude negative value.
            delta = incoming_ts - conn.safety_originator_last_ts
            if delta < -0x4000:
                conn.safety_originator_rollover_count = (
                    conn.safety_originator_rollover_count + 1) & 0xFFFF
            conn.safety_originator_last_ts = incoming_ts

        result = decode_safety_frame(
            data, data_len, fmt,
            conn.safety_originator_pid_seed_s1,
            conn.safety_originator_pid_seed_s3,
            conn.safety_originator_pid_seed_s5,
            conn.safety_originator_rollover_count)

        # IDLE frames before PLC processes our SafetyOpen response carry
        # rolloverCount=0 instead of our SafetyInitialRolloverValue. Retry
        # with 0 if the first attempt failed and the frame is idle.
        if (not result.crc_valid and data_len < len(data)
                and (data[data_len] & 0x80) == 0
                and conn.safety_originator_rollover_count != 0):
            result = decode_safety_frame(
                data, data_len, fmt,
                conn.safety_originator_pid_seed_s1,
                conn.safety_originator_pid_seed_s3,
                conn.safety_originator_pid_seed_s5,
                0)

        if result.crc_valid:
            asm = self.assemblies.get_assembly(conn.consumed_assembly_instance)
            if asm:
                asm.set_data(result.actual_data)

        mode_byte = data[data_len] if data_len < len(data) else 0
        current_ping = mode_byte & 0x03
        plc_running = (mode_byte & 0x80) != 0

        if (conn.safety_startup_trace_until_ticks > 0
                and _now_ns() < conn.safety_startup_trace_until_ticks):
            print(f"[SU-RECV-DATA] conn={conn.connection_serial_number:04X} "
                  f"mode=0x{mode_byte:02X} ts={result.timestamp} wireTs={incoming_ts} "
                  f"crc={'OK' if result.crc_valid else 'BAD'} "
                  f"rc=0x{conn.safety_originator_rollover_count:04X} ping={current_ping}")

        # Ping-change → send TCOO
        if current_ping != conn.safety_last_ping_count:
            conn.safety_last_ping_count = current_ping
            self._send_time_coordination(conn)

        # False→True transition of PLC run on this connection triggers
        # cold-start production on the partner client connection.
        if plc_running and not conn.safety_plc_running:
            conn.safety_plc_running = True
            for other in self.connection_manager.active_connections:
                if (other is not conn and other.is_safety
                        and other.originator_vendor_id == conn.originator_vendor_id
                        and other.originator_serial_number == conn.originator_serial_number
                        and not other.safety_consumer_active):
                    self.produce_io_data(other)

    def on_remote_endpoint_updated(self, conn: IoConnection,
                                    sender: tuple[str, int]) -> None:
        if not conn.is_safety:
            return
        for other in self.connection_manager.active_connections:
            if (other is not conn and other.is_safety
                    and other.originator_vendor_id == conn.originator_vendor_id
                    and other.originator_serial_number == conn.originator_serial_number):
                other.remote_endpoint = sender

    # ---- Internals ----

    def _send_time_coordination(self, conn: IoConnection) -> None:
        elapsed_us = (_now_ns() - conn.safety_production_start_ticks) // 1000
        consumer_time = (conn.safety_initial_timestamp + elapsed_us // 128) & 0xFFFF
        out = bytearray(6)
        if conn.safety_format == 0x02:
            n = encode_tcoo_extended(out, conn.safety_last_ping_count, consumer_time,
                                       conn.safety_cid_seed_s5)
        else:
            n = encode_tcoo(out, conn.safety_last_ping_count, consumer_time,
                              conn.safety_cid_seed_s3)
        self.send_udp_io_data(conn, bytes(out[:n]))

        if (conn.safety_startup_trace_until_ticks > 0
                and _now_ns() < conn.safety_startup_trace_until_ticks):
            print(f"[SU-SEND-TCOO] conn={conn.connection_serial_number:04X} "
                  f"ctv={consumer_time} pingReply={conn.safety_last_ping_count}")

    def _on_connection_removed(self, conn: IoConnection) -> None:
        if not conn.is_safety:
            return
        any_left = any(c.is_safety for c in self.connection_manager.active_connections)
        if not any_left:
            self._supervisor.scid = SafetyConfigurationId()
            sv_inst = self._supervisor.cip_class.get_instance(1)
            if sv_inst is not None:
                a6 = sv_inst.get_attribute(6)
                if a6 is not None:
                    a6.set_data(bytes(SafetyConfigurationId.SIZE))
                a25 = sv_inst.get_attribute(25)
                if a25 is not None:
                    a25.set_data(bytes(UniqueNetworkId.SIZE))

def _estimate_data_length(wire_size_in: int) -> int:
    """Reverse the wire_size table to derive the safety payload length."""
    short_len = wire_size_in - 6
    if 1 <= short_len <= 2:
        return short_len
    long_len = (wire_size_in - 8) // 2
    if 3 <= long_len <= 250 and long_len * 2 + 8 == wire_size_in:
        return long_len
    return -1
