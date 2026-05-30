"""CIP Safety scanner against a real 1734-IB8S behind a 1734-ENT.

Port of the C# SafetyScannerTest. Defaults target 192.168.1.76 slot 1.

Usage:
    python examples/safety_scanner_1734.py [target_ip] [backplane_slot]
"""
from __future__ import annotations
import asyncio
import os
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except (AttributeError, OSError):
    pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ethernetip.protocol.eip_scanner import EipScanner
from ethernetip.protocol.eip_udp_transport import EipUdpTransport, IO_PORT
from ethernetip.safety import (
    SafetyFormat, UniqueNetworkId, SafetyNetworkNumber, SafetyConfigurationId,
    SafetyForwardOpenConfig, SafetyScannerConnection,
)


def assembly_instance(instance: int) -> bytes:
    """Encode class 0x04 + instance using 8-bit or 16-bit logical segment."""
    if instance <= 0xFF:
        return bytes([0x20, 0x04, 0x24, instance])
    return bytes([0x20, 0x04, 0x25, 0x00, instance & 0xFF, (instance >> 8) & 0xFF])


async def main() -> None:
    target_ip = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.76'
    backplane_slot = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    fmt = SafetyFormat.EXTENDED

    print(f"=== CIP Safety Scanner -> 1734 ===")
    print(f"Target: {target_ip}, Backplane Slot: {backplane_slot}")
    print()

    # ---- Spoof PLC identity (from capture) ----
    orig_vendor = 0x0001            # Rockwell
    orig_serial = 0x012FE10E

    # Originator UNID (PLC identity)
    our_snn = SafetyNetworkNumber(bytes([0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D]))
    our_ounid = UniqueNetworkId(snn=our_snn, node_address=0xC0A80160)  # 192.168.1.96

    # Target UNID (module at slot 1)
    target_snn = SafetyNetworkNumber(bytes([0xB8, 0x0D, 0xED, 0x00, 0x8E, 0x4D]))
    target_tunid = UniqueNetworkId(snn=target_snn, node_address=0x00000001)

    # SCID from capture
    scid = SafetyConfigurationId(
        sccrc=0x781B988E,
        scts=SafetyNetworkNumber(bytes([0xB6, 0x0D, 0xED, 0x00, 0x8E, 0x4D])),
    )

    # Route prefix: backplane port 1, link address = slot
    route_prefix = bytes([0x01, backplane_slot])

    # Electronic key for 1734-IB8S (vendor=1 Rockwell, devType=0x23 Safety Discrete I/O,
    # prodCode=0x10, compat-bit set + Major 2, Minor 2)
    electronic_key = bytes([
        0x34, 0x04,
        0x01, 0x00,                 # Vendor
        0x23, 0x00,                 # Device Type
        0x10, 0x00,                 # Product Code
        0x82,                       # Compat + Major 2
        0x02,                       # Minor 2
    ])

    # Server app path: ekey + [config 0x0360] + [O->T 0x0234] + [T->O 0xC7]
    server_app_path = (electronic_key
                       + assembly_instance(0x0360)
                       + assembly_instance(0x0234)
                       + assembly_instance(0xC7))

    # Client app path: ekey + [config 0x0360] + [O->T 0xC7] + [T->O 0x0244]
    client_app_path = (electronic_key
                       + assembly_instance(0x0360)
                       + assembly_instance(0xC7)
                       + assembly_instance(0x0244))

    print(f"Server path ({len(server_app_path)}B): {server_app_path.hex(' ')}")
    print(f"Client path ({len(client_app_path)}B): {client_app_path.hex(' ')}")
    print()

    # ---- Connection configs (same as C# test) ----
    server_cfg = SafetyForwardOpenConfig(
        config_assembly=0x0360,
        consumed_assembly=0x0234,
        produced_assembly=0xC7,
        consumed_data_size=1,
        produced_data_size=1,
        ot_rpi=20_000,              # O->T: 20ms (data we send)
        to_rpi=380_000,             # T->O: 380ms (TCOO from target)
        ot_connection_size=7,
        to_connection_size=6,
        format=fmt,
        tunid=target_tunid, ounid=our_ounid, scid=scid,
        ping_interval_multiplier=19,
        time_coord_msg_min_multiplier=0,
        network_time_expectation_multiplier=625,    # 80ms
        timeout_multiplier=2,
        max_fault_number=2,
        initial_timestamp=0xFFFF,
        initial_rollover_value=0xFFFF,
        connection_timeout_multiplier=1,            # *8
        priority_time_tick=0x05,
        timeout_ticks=156,
    )
    client_cfg = SafetyForwardOpenConfig(
        config_assembly=0x0360,
        consumed_assembly=0xC7,
        produced_assembly=0x0244,
        consumed_data_size=1,
        produced_data_size=1,
        ot_rpi=1_000_000,           # O->T: 1000ms (TCOO we send)
        to_rpi=10_000,              # T->O: 10ms (data from target)
        ot_connection_size=6,
        to_connection_size=7,
        format=fmt,
        tunid=target_tunid, ounid=our_ounid, scid=scid,
        ping_interval_multiplier=100,
        time_coord_msg_min_multiplier=0,
        network_time_expectation_multiplier=313,    # ~40ms
        timeout_multiplier=2,
        max_fault_number=2,
        initial_timestamp=0xFFFF,
        initial_rollover_value=0xFFFF,
        connection_timeout_multiplier=1,
        priority_time_tick=0x05,
        timeout_ticks=156,
    )

    scanner = EipScanner()
    print(f"Connecting to {target_ip}:44818...", end='', flush=True)
    await scanner.connect(target_ip)
    print(" OK")

    # The 1734 sends safety frames to OUR_IP:2222 (EtherNet/IP IO port) by
    # spec. Scanner's own UDP socket is on an ephemeral port and would never
    # receive them — bind a separate transport on 2222 for I/O.
    udp = EipUdpTransport(bind_address='0.0.0.0', bind_port=IO_PORT)
    await udp.start()
    print(f"UDP I/O bound on port {udp.actual_port}")

    rx_count = 0
    last_rx = b''

    def _on_rx(data: bytes) -> None:
        nonlocal rx_count, last_rx
        rx_count += 1
        last_rx = data

    try:
        print("Opening safety connection pair...")
        conn = await SafetyScannerConnection.open(
            scanner, udp, server_cfg, client_cfg,
            orig_vendor=orig_vendor, orig_serial=orig_serial,
            route_prefix=route_prefix,
            server_app_path=server_app_path,
            client_app_path=client_app_path)

        conn.log.append(lambda m: print(f"[SAFETY] {m}"))
        conn.on_data_received.append(_on_rx)
        conn.set_output_data(bytes([0x00]))  # safe state output

        print("Running. Ctrl+C to stop.")
        print()

        try:
            for i in range(60):
                await asyncio.sleep(1)
                print(f"[t={i+1:2d}s] rx_frames={rx_count} "
                      f"last_rx={last_rx.hex() if last_rx else '-'}")
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass

        print("\nClosing...")
        await conn.close()
    except Exception as ex:
        print(f"ERROR: {ex}")
        import traceback
        traceback.print_exc()
    finally:
        await udp.close()
        await scanner.close()
    print("Done.")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
