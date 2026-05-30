"""Connected-explicit smoke test.

Mirrors EthernetIPCpp/samples/scanner_smoke/connected_explicit_smoke.cpp:
exercises both UCMM (send_explicit) and Class 3 connected explicit
(open_explicit + send) round-trips against an adapter that supports both
(typically examples/echo_module or examples/cip_echo_server).

usage: python examples/connected_explicit_smoke.py [host] [port]

Tests, in order:
  1. UCMM GetAttributeSingle on Identity attr 7 — verifies UCMM path
  2. Class 3 Forward Open
  3. Class 3 GetAttributeSingle on Identity attr 7
  4. Class 3 catch-all custom message (svc 0xCD class 0xDE inst 2 attr 156)
     with a 7-DINT payload — verifies the unhandled-service path and that
     the response payload is returned correctly.
"""
from __future__ import annotations

import asyncio
import struct
import sys

from ethernetip.protocol.eip_scanner import EipScanner


def identity_name(data: bytes) -> str:
    if not data:
        return "<empty>"
    name_len = data[0]
    return data[1:1 + name_len].decode('ascii', errors='replace')


async def main(host: str, port: int) -> int:
    scanner = EipScanner()
    try:
        print(f"Connecting to {host}:{port} ...")
        await scanner.connect(host, port)
        print(f"  session = 0x{scanner.session_handle:08X}")

        # ---- 1. UCMM ----
        print("\n[UCMM] GetAttributeSingle(class=1, inst=1, attr=7) ...")
        id_path = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x07])
        ucmm = await scanner.send_explicit(0x0E, id_path, b'')
        print(f"  status=0x{ucmm.status.general_status:02X}  "
              f"data={len(ucmm.data)} bytes  "
              f"ProductName=\"{identity_name(ucmm.data)}\"")

        # ---- 2/3. Class 3 ----
        print("\n[Class3] Opening connection ...")
        async with await scanner.open_explicit() as conn:
            print("  open")

            c3_id = await conn.send(0x0E, 0x01, 1, 7)
            print(f"  GetAttributeSingle(class=1, inst=1, attr=7): "
                  f"status=0x{c3_id.status.general_status:02X} "
                  f"data={len(c3_id.data)} bytes  "
                  f"ProductName=\"{identity_name(c3_id.data)}\"")

            # ---- 4. Class 3 catch-all custom message ----
            print("\n[Class3] Custom svc=0xCD class=0xDE inst=2 attr=156 "
                  "with 28-byte payload ...")
            payload = b''.join(struct.pack('<I', 1000 + i) for i in range(7))
            c3_echo = await conn.send(0xCD, 0xDE, 2, 156, payload)
            print(f"  status=0x{c3_echo.status.general_status:02X}  "
                  f"reply data({len(c3_echo.data)})="
                  + ' '.join(f'{b:02X}' for b in c3_echo.data))
        print("\nDone.")
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    finally:
        await scanner.close()


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 44818
    sys.exit(asyncio.run(main(host, port)))
