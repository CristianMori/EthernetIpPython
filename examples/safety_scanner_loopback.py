"""Loopback test: SafetyDevice + SafetyScannerConnection in one process.

Starts our own Python safety adapter, then a safety scanner originator that
connects back to it. Both sides exchange safety data for ~10 seconds, then
close cleanly. Useful for validating the scanner without depending on real
hardware.
"""
from __future__ import annotations
import asyncio
import os
import sys

# Windows console defaults to cp1252; force UTF-8 so unicode log lines don't crash.
try:
    sys.stdout.reconfigure(encoding='utf-8')
except (AttributeError, OSError):
    pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.protocol.eip_scanner import EipScanner
from ethernetip.safety import (
    SafetyDevice, SafetyNetworkNumber, SafetyFormat, UniqueNetworkId,
    SafetyConfigurationId, SafetyForwardOpenConfig, SafetyScannerConnection,
)


BIND = '127.0.0.1'

ADAPTER_IDENTITY = IdentityInfo(
    vendor_id=0x0001, device_type=0, product_code=26,
    major_revision=1, minor_revision=1,
    serial_number=0xC0FFEE42,
    product_name='LoopbackSafetyAdapter',
)

# Shared SNN — both sides know each other's UNIDs.
SNN_BYTES = bytes([0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D])
ADAPTER_NODE = 0xC0A80154   # 192.168.1.84 BE-packed (cosmetic; not on wire IP-wise)
SCANNER_NODE = 0xC0A80160   # 192.168.1.96

ASM_OUTPUT = 1     # adapter consumes (PLC→Adapter)
ASM_INPUT = 199    # adapter produces (Adapter→PLC)
ASM_CONFIG = 199


async def main() -> None:
    # ---- Adapter ----
    snn = SafetyNetworkNumber(SNN_BYTES)
    adapter = SafetyDevice(ADAPTER_IDENTITY, BIND, snn, ADAPTER_NODE,
                           name='LoopbackAdapter')
    adapter.add_assembly(ASM_OUTPUT, 1, 'Safety Output')
    adapter.add_assembly(ASM_INPUT, 1, 'Safety Input')
    adapter.add_assembly(ASM_CONFIG, 0, 'Configuration')

    def _on_conn_estab(conn):
        print(f"[ADAPTER] conn established serial=0x{conn.connection_serial_number:04X} "
              f"safety={conn.is_safety} fmt={conn.safety_format} "
              f"OT-asm={conn.consumed_assembly_instance}({conn.ot_size}B@{conn.ot_rpi/1000:.0f}ms) "
              f"TO-asm={conn.produced_assembly_instance}({conn.to_size}B@{conn.to_rpi/1000:.0f}ms)")

    def _on_conn_removed(conn):
        print(f"[ADAPTER] conn closed serial=0x{conn.connection_serial_number:04X} state={conn.state.name}")

    adapter.connection_manager.on_connection_established.append(_on_conn_estab)
    adapter.connection_manager.on_connection_removed.append(_on_conn_removed)
    await adapter.start()
    print(f"[ADAPTER] listening on {BIND}:44818 / UDP 2222")

    # ---- Scanner ----
    scanner = EipScanner()
    await scanner.connect(BIND)
    print(f"[SCANNER] connected session=0x{scanner.session_handle:08X}")

    tunid = UniqueNetworkId(snn=snn, node_address=ADAPTER_NODE)
    ounid = UniqueNetworkId(snn=snn, node_address=SCANNER_NODE)
    # SCID=0 keeps adapter SCID check permissive (matches a fresh adapter).
    scid = SafetyConfigurationId()

    fmt = SafetyFormat.EXTENDED

    # Loopback uses generous timings because asyncio.sleep on Windows has
    # ~15ms granularity; tight RPIs (e.g. 10-20ms) cause watchdog timeouts
    # even when both ends are healthy.
    server_cfg = SafetyForwardOpenConfig(
        config_assembly=ASM_CONFIG,
        consumed_assembly=ASM_OUTPUT,   # adapter consumes O->T
        produced_assembly=ASM_INPUT,    # adapter produces T->O (TCOO only — produced_data_size=0 path)
        consumed_data_size=1,
        produced_data_size=0,           # forces adapter to skip cyclic prod, only TCOO
        ot_rpi=50_000, to_rpi=950_000,
        ot_connection_size=7, to_connection_size=6,
        format=fmt, tunid=tunid, ounid=ounid, scid=scid,
        ping_interval_multiplier=19, time_coord_msg_min_multiplier=0,
        network_time_expectation_multiplier=625, timeout_multiplier=2,
        connection_timeout_multiplier=3,   # *32 → ~1.6s on 50ms RPI
        initial_timestamp=0, initial_rollover_value=0,
    )
    client_cfg = SafetyForwardOpenConfig(
        config_assembly=ASM_CONFIG,
        consumed_assembly=ASM_INPUT,    # adapter consumes O->T (TCOO from us)
        produced_assembly=ASM_OUTPUT,   # adapter produces T->O (data to us)
        consumed_data_size=0,
        produced_data_size=1,
        ot_rpi=1_000_000, to_rpi=50_000,
        ot_connection_size=6, to_connection_size=7,
        format=fmt, tunid=tunid, ounid=ounid, scid=scid,
        ping_interval_multiplier=100, time_coord_msg_min_multiplier=0,
        network_time_expectation_multiplier=313, timeout_multiplier=2,
        connection_timeout_multiplier=3,
        initial_timestamp=0, initial_rollover_value=0,
    )

    rx_count = 0
    last_rx = b''

    def _on_rx(data: bytes) -> None:
        nonlocal rx_count, last_rx
        rx_count += 1
        last_rx = data

    saf = await SafetyScannerConnection.open(
        scanner, scanner.udp, server_cfg, client_cfg,
        orig_vendor=0x0001, orig_serial=0x012FE10E)
    saf.log.append(lambda m: print(f"[SCANNER] {m}"))
    saf.on_data_received.append(_on_rx)
    saf.set_output_data(bytes([0xA5]))

    # Pre-load the adapter's T->O assembly with 0x42 so the scanner sees non-zero
    adapter.assemblies.get_assembly(ASM_OUTPUT).write_bytes(0, bytes([0x42]))

    print()
    print(f"[LOOP] running 10s — adapter conns={len(adapter.connection_manager.active_connections)}")
    for i in range(10):
        await asyncio.sleep(1)
        print(f"[LOOP] t={i+1}s rx_frames={rx_count} last_rx={last_rx.hex() if last_rx else '-'} "
              f"adapter_conns={len(adapter.connection_manager.active_connections)} "
              f"adapter_T->O_sent={adapter.to_send_count}")

    print()
    print("[LOOP] closing scanner connection...")
    await saf.close()
    await scanner.close()
    await adapter.close()
    print("[LOOP] Done.")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
