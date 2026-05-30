"""CIP Safety EtherNet/IP adapter — Python port of SafetyAdapterSample.

Acts as a safety target. Listens on TCP 44818 / UDP 2222, accepts safety
Forward Open from a Logix PLC (or compatible originator), and runs the
producer/consumer state machine with full CRC + TCOO time coordination.

Usage:
    python examples/safety_adapter.py                # PLC profile (192.168.1.84)
    python examples/safety_adapter.py --bind=10.0.0.5 --node=0x0A000005 --snn=4D90_0101_A35C
"""
from __future__ import annotations
import asyncio
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.safety import SafetyDevice, SafetyNetworkNumber


# ---- CLI helpers ----

def _arg(key: str, default: str) -> str:
    for a in sys.argv[1:]:
        prefix = f'--{key}='
        if a.lower().startswith(prefix.lower()):
            return a[len(prefix):]
    return default


def _parse_hex_or_dec(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s.lower().startswith('0x') else int(s)


def _format_snn(b: bytes) -> str:
    return f"{b[5]:02X}{b[4]:02X}_{b[3]:02X}{b[2]:02X}_{b[1]:02X}{b[0]:02X}"


def _parse_snn(s: str) -> bytes:
    hex_str = s.replace('_', '').replace('-', '').replace(' ', '')
    if len(hex_str) != 12:
        raise ValueError("SNN must be 12 hex chars (6 bytes)")
    # Visual high→low, wire little-endian: reverse the parse.
    out = bytearray(6)
    for i in range(6):
        out[5 - i] = int(hex_str[i * 2:i * 2 + 2], 16)
    return bytes(out)


def _log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}", flush=True)


async def main() -> None:
    profile = _arg('profile', 'plc').lower()

    if profile == 'plc':
        # Real ControlLogix PLC at 192.168.1.96, our adapter on 192.168.1.84
        d_vendor = 1
        d_snn = bytes([0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D])
        d_node = 0xC0A80154
        d_bind = '192.168.1.84'
        d_asm1, d_asm2, d_cfg = 1, 199, 199
    else:
        # Synthetic test scanner profile
        d_vendor = 12
        d_snn = bytes([0x5C, 0xA3, 0x01, 0x01, 0x90, 0x4D])
        d_node = 0xC0A8CC01
        d_bind = '192.168.204.1'
        d_asm1, d_asm2, d_cfg = 1, 2, 197

    vendor_id = int(_arg('vendor', str(d_vendor)))
    serial = _parse_hex_or_dec(_arg('serial', '0xC0FFEE42'))
    product = _arg('product', 'EthernetIPPython Safety Module')
    snn_bytes = _parse_snn(_arg('snn', _format_snn(d_snn)))
    node_addr = _parse_hex_or_dec(_arg('node', f'0x{d_node:08X}'))
    bind = _arg('bind', d_bind)
    asm1 = int(_arg('asm-data1', str(d_asm1)))
    asm2 = int(_arg('asm-data2', str(d_asm2)))
    asm_cfg = int(_arg('asm-config', str(d_cfg)))
    halt_threshold = float(_arg('halt-threshold', '60'))
    startup_trace = int(_arg('startup-trace', '0'))

    SafetyDevice.startup_trace_seconds = startup_trace
    if _arg('trace', '0') != '0':
        SafetyDevice.enable_trace = True

    identity = IdentityInfo(
        vendor_id=vendor_id, device_type=0, product_code=26,
        major_revision=1, minor_revision=1,
        serial_number=serial, product_name=product)

    _log(f"=== EthernetIPPython Safety Adapter ({profile}) ===")
    _log(f"Profile: {profile}, Bind: {bind}, Node: 0x{node_addr:08X}")
    _log(f"Identity: Vendor=0x{vendor_id:04X}, Serial=0x{serial:08X}, Name=\"{product}\"")
    _log(f"SNN: {_format_snn(snn_bytes)}")
    _log(f"Assemblies: data1={asm1}, data2={asm2}, config={asm_cfg}")

    snn = SafetyNetworkNumber(snn_bytes)
    device = SafetyDevice(identity, bind, snn, node_addr, name='SafeTest')

    safety1 = device.add_assembly(asm1, 1, "Safety Data 1")
    device.add_assembly(asm2, 1, "Safety Data 2")
    # Logix safety configs often map asm_cfg onto one of the data instances.
    # Skip the redundant registration when it would replace an existing one.
    if asm_cfg != asm1 and asm_cfg != asm2:
        device.add_assembly(asm_cfg, 0, "Configuration")

    if profile == 'test2':
        device.add_assembly(198, 1, "Safety Input 198")
        device.add_assembly(199, 1, "Safety Output 199")

    # Seed produced data with 0x42 so the consumer side sees something non-zero.
    safety1.write_bytes(0, bytes([0x42]))

    conn_count = 0
    conn_open_times: dict[int, datetime] = {}

    def on_established(conn):
        nonlocal conn_count
        conn_count += 1
        conn_open_times[conn.connection_serial_number] = datetime.now(timezone.utc)
        _log(f"[CONN #{conn_count}] Serial=0x{conn.connection_serial_number:04X} "
             f"Class={conn.transport_class.name} Safety={conn.is_safety}")
        _log(f"  O->T: Asm {conn.consumed_assembly_instance}, {conn.ot_size}B, "
             f"RPI={conn.ot_rpi / 1000:.1f}ms")
        _log(f"  T->O: Asm {conn.produced_assembly_instance}, {conn.to_size}B, "
             f"RPI={conn.to_rpi / 1000:.1f}ms")
        if conn.is_safety:
            _log(f"  Safety Fmt={conn.safety_format} "
                 f"S1=0x{conn.safety_pid_seed_s1:02X} S3=0x{conn.safety_pid_seed_s3:04X}")

    def on_removed(conn):
        _log(f"[CONN CLOSED] Serial=0x{conn.connection_serial_number:04X} State={conn.state.name}")
        opened = conn_open_times.pop(conn.connection_serial_number, None)
        if opened is not None:
            duration = (datetime.now(timezone.utc) - opened).total_seconds()
            _log(f"  Duration: {duration:.1f}s")
            if duration > halt_threshold:
                _log(f"  *** CONNECTION DROPPED AFTER {duration:.1f}s — HALTING ***")
                asyncio.get_running_loop().stop()

    device.connection_manager.on_connection_established.append(on_established)
    device.connection_manager.on_connection_removed.append(on_removed)

    await device.start()

    _log("CIP objects:")
    for code, cls in device.dispatcher.registered_classes.items():
        _log(f"  0x{code:04X} - {cls.name}")
    _log("Ready. Ctrl+C to stop.")
    _log("")

    tick = 0
    try:
        while True:
            await asyncio.sleep(0.5)
            tick += 1
            d = safety1.get_data()[0] if safety1.data_size else 0
            conns = len(device.connection_manager.active_connections)
            sys.stdout.write(
                f"\r[{datetime.now().strftime('%H:%M:%S')}] "
                f"Data=0x{d:02X} Conns={conns} T->O={device.to_send_count}    ")
            sys.stdout.flush()
            if tick % 10 == 0:
                print()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        print()
        await device.close()
        _log("Done.")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
