"""Catch-all CIP echo server (Python port of EthernetIPCpp/samples/cip_echo_server).

Listens on TCP, handles RegisterSession, SendRRData (UCMM), and SendUnitData
(Class 3 connected explicit). Every inbound CIP service request that doesn't
match a registered class is printed (service code, EPATH, hex data) and the
reply carries `reply_bytes` bytes of incremental data (0, 1, 2, ...).

Useful for capturing whatever a Logix MSG instruction (or any other client)
sends at us, and for testing MSG instructions that expect a fixed-size
response.

Usage:  python examples/cip_echo_server.py [<bind>] [<tcp_port>] [<reply_bytes>]
"""
from __future__ import annotations

import asyncio
import struct
import sys

from ethernetip.cip.catch_all_dispatcher import CatchAllDispatcher, CatchAllRequest, CatchAllReply
from ethernetip.cip.attribute import CipAttribute, AttributeAccess
from ethernetip.cip.cip_class import CipClass
from ethernetip.cip.data_types import CipDataType
from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.connections.connection_manager import ConnectionManagerObject
from ethernetip.protocol.eip_adapter import EipAdapter


async def main(bind: str, port: int, reply_bytes: int) -> None:
    identity = IdentityInfo(
        vendor_id=0x0001,
        device_type=0x000C,
        product_code=0xCAFE,
        major_revision=1,
        minor_revision=0,
        serial_number=0xC1500001,
        product_name="EthernetIPPython CIP Echo Server",
    )

    dispatcher = CatchAllDispatcher()
    request_count = 0

    def handler(req: CatchAllRequest) -> CatchAllReply:
        nonlocal request_count
        request_count += 1
        p = req.path
        print(f"[#{request_count}] svc=0x{req.service_code:02X}  "
              f"class={('0x%02X' % p.class_id) if p.class_id is not None else '-'}  "
              f"instance={p.instance_id if p.instance_id is not None else '-'}  "
              f"attribute={p.attribute_id if p.attribute_id is not None else '-'}  "
              f"element={p.element_id if p.element_id is not None else '-'}  "
              f"conn_pt={p.connection_point if p.connection_point is not None else '-'}  "
              f"symbol={p.symbolic_name if p.symbolic_name is not None else '-'}  "
              f"data({len(req.data)})={' '.join(f'{b:02X}' for b in req.data[:64])}"
              + ('...' if len(req.data) > 64 else ''))
        sys.stdout.flush()
        return CatchAllReply(data=bytes(range(reply_bytes)))

    dispatcher.set_handler(handler)

    # Identity Object (Class 0x01) — for RegisterSession / ListIdentity.
    id_class = CipClass(0x01, "Identity", revision=1)
    id_class.add_standard_instance_services()
    id_inst = id_class.create_instance(1)
    aa = AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL
    id_inst.add_attribute(CipAttribute.create_uint (1, CipDataType.UINT,  aa, identity.vendor_id))
    id_inst.add_attribute(CipAttribute.create_uint (2, CipDataType.UINT,  aa, identity.device_type))
    id_inst.add_attribute(CipAttribute.create_uint (3, CipDataType.UINT,  aa, identity.product_code))
    id_inst.add_attribute(CipAttribute(4, CipDataType.USINT, aa,
                                         bytes([identity.major_revision, identity.minor_revision])))
    id_inst.add_attribute(CipAttribute.create_uint (5, CipDataType.WORD,  aa, identity.status))
    id_inst.add_attribute(CipAttribute.create_udint(6, CipDataType.UDINT, aa, identity.serial_number))
    id_inst.add_attribute(CipAttribute.create_short_string(7, aa, identity.product_name))
    dispatcher.register_class(id_class)

    # Connection Manager (Class 0x06) — required so the PLC can send
    # Unconnected Send (svc 0x52) and Forward Open (svc 0x54). The CM's
    # Unconnected Send handler unwraps the inner CIP request and calls back
    # into our dispatcher; an inner request that doesn't match any
    # registered class lands in the catch-all handler.
    conn_mgr = ConnectionManagerObject()
    conn_mgr.dispatch_request = dispatcher.dispatch
    dispatcher.register_class(conn_mgr.cip_class)

    adapter = EipAdapter(dispatcher, identity)

    # Translate OT_conn_id (in incoming SendUnitData) → TO_conn_id (for the
    # reply's ConnectedAddress item). Without this, Logix MSG ignores our
    # Class 3 explicit replies as "not for me" and times out.
    def lookup(oto_t_id: int) -> int:
        conn = conn_mgr.find_by_ot_id(oto_t_id)
        return conn.to_connection_id if conn else 0
    adapter.connection_id_lookup = lookup

    await adapter.listen(bind, port)
    print(f"=== CIP Echo Server ===")
    print(f"Listening on {bind}:{port}")
    print(f"Reply payload: {reply_bytes} byte(s)"
          f"{' of incremental data (0,1,2,...)' if reply_bytes > 0 else ' (empty)'}")
    print("Every incoming CIP request will be printed below.")
    print("Ctrl+C to stop.\n")
    sys.stdout.flush()

    try:
        await asyncio.Event().wait()
    finally:
        await adapter.close()


if __name__ == "__main__":
    bind         = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port         = int(sys.argv[2]) if len(sys.argv) > 2 else 44818
    reply_bytes  = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    try:
        asyncio.run(main(bind, port, reply_bytes))
    except KeyboardInterrupt:
        print("\nStopped.")
