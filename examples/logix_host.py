"""Logix controller simulator — mirrors C++ samples/logix_host.

Wraps LogixDispatcher (Symbol/Template/Message Router/Connection Manager/
Identity/Program Name) behind EipAdapter on TCP 44818. Class 3 explicit
messaging only — no I/O connections.

Preloads three tags so pycomm3_smoke.py can run against this directly:
  rate         (DINT)   = 534
  temperature  (REAL)   = 72.5
  counts       (INT[10]) = zeros

Usage:
  python examples/logix_host.py [host] [tcp_port]
"""
from __future__ import annotations

import asyncio
import struct
import sys

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.logix.data_types import DINT, REAL, INT
from ethernetip.logix.logix_dispatcher import LogixDispatcher
from ethernetip.logix.tag_database import TagDatabase
from ethernetip.protocol.eip_adapter import EipAdapter


async def main(host: str, tcp_port: int) -> None:
    identity = IdentityInfo(
        vendor_id=0x0001,
        device_type=0x000E,           # PLC
        product_code=55,
        major_revision=32,
        minor_revision=11,
        serial_number=0xDEAD,
        product_name="EthernetIPPython Logix",
    )

    tags = TagDatabase()
    rate = tags.add_tag("rate", DINT)
    rate.set_data(struct.pack('<i', 534))
    temp = tags.add_tag("temperature", REAL)
    temp.set_data(struct.pack('<f', 72.5))
    counts = tags.add_tag("counts", INT, element_count=10)

    dispatcher = LogixDispatcher(tags=tags, identity=identity)
    adapter = EipAdapter(dispatcher, identity)

    print(f"=== EthernetIPPython Logix Host ===")
    print(f"Bind:     {host}:{tcp_port}")
    print(f"Identity: vendor=0x{identity.vendor_id:04X} serial=0x{identity.serial_number:08X} "
          f"name={identity.product_name!r}")
    print(f"Tags: rate(DINT)=534, temperature(REAL)=72.5, counts(INT[10])")
    print(f"Ready. Ctrl+C to stop.\n")

    await adapter.listen(host, tcp_port)
    try:
        # Run until cancelled.
        await asyncio.Event().wait()
    finally:
        await adapter.close()


if __name__ == "__main__":
    bind = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 44818
    try:
        asyncio.run(main(bind, port))
    except KeyboardInterrupt:
        print("\nStopped.")
