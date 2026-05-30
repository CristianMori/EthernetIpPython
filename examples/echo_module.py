"""EtherNet/IP Echo Module — equivalent of the C# EthernetIPSharp.Host.

Starts a virtual EtherNet/IP device with I/O assemblies, accepts PLC connections,
and exchanges cyclic I/O data.

Usage:
    python examples/echo_module.py [bind_address] [tcp_port]
"""

import asyncio
import struct
import sys
import os

# Add src to path when running as script
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.device.virtual_device import VirtualDevice


async def main():
    bind_address = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
    tcp_port = int(sys.argv[2]) if len(sys.argv) > 2 else 44818

    identity = IdentityInfo(
        vendor_id=0x0001,
        device_type=0x000C,
        product_code=0x0001,
        major_revision=1,
        minor_revision=0,
        serial_number=0xC0FFEE42,
        product_name="EthernetIPPython Echo Module",
    )

    print("=== EthernetIPPython Echo Module ===")
    print(f"Bind address: {bind_address}")
    print(f"TCP port:     {tcp_port}")
    print(f"UDP port:     2222")
    print()

    device = VirtualDevice(identity, bind_address)

    # Assemblies: Input 100 (T→O, 125 DINTs), Output 102 (O→T, 124 DINTs), Config 105
    produced = device.add_assembly(100, 500, "T->O Input (125 DINTs)")
    consumed = device.add_assembly(102, 496, "O->T Output (124 DINTs)")
    config = device.add_assembly(105, 10, "Configuration")

    # Pre-fill produced data with ramp pattern
    for i in range(125):
        produced.write_dint(i * 4, i + 1)

    print("Assemblies configured:")
    print(f"  Instance 100: T->O  500 bytes (125 DINTs) - pre-filled with ramp 1..125")
    print(f"  Instance 102: O->T  496 bytes (124 DINTs) - waiting for PLC writes")
    print(f"  Instance 105: Config  10 bytes")
    print()

    # Track O→T packets
    ot_packet_count = 0

    def on_data_changed(instance_id, data):
        nonlocal ot_packet_count
        ot_packet_count += 1

    consumed.on_data_changed.append(on_data_changed)

    await device.start(tcp_port=tcp_port)

    print("Registered CIP objects:")
    for code, cls in device.dispatcher.registered_classes.items():
        print(f"  0x{code:04X} - {cls.name}")
    print()
    print("Ready. Waiting for PLC connection...")
    print("  Press Ctrl+C to stop")
    print()

    tick = 0
    try:
        while True:
            await asyncio.sleep(0.2)
            tick += 1

            out0   = consumed.read_dint(0)
            out45  = consumed.read_dint(45 * 4)
            out120 = consumed.read_dint(120 * 4)
            # Config assembly is 10 bytes — byte 5 is what the PLC's Generic
            # Ethernet Module pushed at Forward Open (Simple Data Segment 0x80).
            cfg5   = config.get_data()[5] if config.data_size >= 6 else 0
            produced.write_dint(0, tick)

            active_conns = len(device.connection_manager.active_connections)
            sys.stdout.write(
                f"\r[tick {tick:6d}] Out[0]={out0:10d} Out[45]={out45:10d} "
                f"Out[120]={out120:10d}  Cfg[5]=0x{cfg5:02X}  In[0]={tick:10d}  "
                f"Conns={active_conns}  O->T rx={ot_packet_count}  "
                f"T->O tx={device.to_send_count}    "
            )
            sys.stdout.flush()

            if tick % 25 == 0:
                print()

    except KeyboardInterrupt:
        print(f"\n\nShutdown. Total O->T packets: {ot_packet_count}")

    await device.close()


if __name__ == '__main__':
    asyncio.run(main())
