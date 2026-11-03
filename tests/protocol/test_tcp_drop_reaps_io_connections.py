"""The adapter must reap IoConnections accepted on a TCP peer that drops
the socket without a Forward_Close.

Prior behavior: the UDP watchdog only armed after the first inbound frame,
so a peer that opened a Forward_Open and never produced UDP left the
IoConnection in the manager forever. Repeating that `max_connections`
times exhausted the cap (f0e5216) and locked out legitimate scanners
with extended status 0x0113.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from ethernetip.cip.cip_class import CipClass
from ethernetip.cip.attribute import CipAttribute, AttributeAccess
from ethernetip.cip.data_types import CipDataType
from ethernetip.cip.dispatcher import CipDispatcher
from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.connections.connection_manager import ConnectionManagerObject
from ethernetip.device.assembly_object import AssemblyObject
from ethernetip.protocol.eip_adapter import EipAdapter
from ethernetip.protocol.eip_scanner import EipScanner


def _make_target():
    dispatcher = CipDispatcher()
    # Identity (0x01) so RegisterSession and basic adapter plumbing round-trip.
    id_class = CipClass(0x01, "Identity")
    id_class.add_standard_instance_services()
    inst = id_class.create_instance(1)
    inst.add_attribute(CipAttribute.create_uint(1, CipDataType.UINT, AttributeAccess.ALL, 0x0001))
    dispatcher.register_class(id_class)

    assemblies = AssemblyObject()
    assemblies.add_instance(100, 4)
    assemblies.add_instance(102, 4)
    assemblies.add_instance(105, 10)
    dispatcher.register_class(assemblies.cip_class)

    cm = ConnectionManagerObject()
    cm.dispatch_request = dispatcher.dispatch
    cm.validate_assembly = lambda inst_id: (
        asm.data_size if (asm := assemblies.get_assembly(inst_id)) else -1
    )
    dispatcher.register_class(cm.cip_class)

    adapter = EipAdapter(dispatcher, IdentityInfo())
    adapter.connection_manager = cm
    return dispatcher, cm, adapter


def _build_forward_open(conn_serial: int) -> bytes:
    """Minimal P2P Class 1 Forward_Open request body (service 0x54 payload)."""
    conn_path = bytes([
        0x20, 0x04,       # Class = Assembly
        0x24, 105,        # Config instance
        0x2C, 102,        # Consumed (O->T)
        0x2C, 100,        # Produced (T->O)
    ])
    ot_params = 0x4200 | ((4 + 4) & 0x01FF)  # P2P, O->T size incl. 4-byte run/idle
    to_params = 0x4200 | (4 & 0x01FF)
    to_conn_id = 0x10000000 | conn_serial

    fwd = bytearray(36 + len(conn_path))
    off = 0
    fwd[off] = 0x0A; off += 1   # priority / time tick
    fwd[off] = 0x05; off += 1   # timeout ticks
    struct.pack_into('<I', fwd, off, 0); off += 4   # O->T connection ID (orig assigns, we overwrite)
    struct.pack_into('<I', fwd, off, to_conn_id); off += 4
    struct.pack_into('<H', fwd, off, conn_serial); off += 2
    struct.pack_into('<H', fwd, off, 0x0001); off += 2   # vendor id
    struct.pack_into('<I', fwd, off, 0xDEADBEEF); off += 4   # orig serial
    fwd[off] = 2; off += 1          # timeout multiplier
    off += 3                         # reserved
    struct.pack_into('<I', fwd, off, 10_000); off += 4   # O->T RPI
    struct.pack_into('<H', fwd, off, ot_params); off += 2
    struct.pack_into('<I', fwd, off, 10_000); off += 4   # T->O RPI
    struct.pack_into('<H', fwd, off, to_params); off += 2
    fwd[off] = 1; off += 1          # transport class trigger (Class 1)
    fwd[off] = len(conn_path) // 2; off += 1
    fwd[off:off + len(conn_path)] = conn_path
    return bytes(fwd)


@pytest.mark.asyncio
async def test_tcp_drop_reaps_orphaned_io_connections():
    _, cm, adapter = _make_target()
    await adapter.listen('127.0.0.1', 0)
    try:
        scanner = EipScanner()
        await scanner.connect('127.0.0.1', adapter.port)

        fwd_bytes = _build_forward_open(conn_serial=1234)
        cm_path = bytes([0x20, 0x06, 0x24, 0x01])
        response, _ = await scanner.send_explicit_raw(0x54, cm_path, fwd_bytes)
        assert response.status.is_success

        assert len(cm.active_connections) == 1

        # Hard-drop TCP without a Forward_Close. The IoConnection would
        # live forever before the fix.
        await scanner.close()

        # Give the adapter task a tick to run its finally block.
        for _ in range(50):
            if not cm.active_connections:
                break
            await asyncio.sleep(0.01)

        assert cm.active_connections == []
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_forward_close_does_not_double_remove_on_tcp_drop():
    """When the originator sends a Forward_Close before dropping TCP, the
    teardown must not try to remove the connection a second time."""
    _, cm, adapter = _make_target()
    await adapter.listen('127.0.0.1', 0)
    removed: list[int] = []
    cm.on_connection_removed.append(lambda c: removed.append(c.ot_connection_id))
    try:
        scanner = EipScanner()
        await scanner.connect('127.0.0.1', adapter.port)

        fwd_bytes = _build_forward_open(conn_serial=4321)
        cm_path = bytes([0x20, 0x06, 0x24, 0x01])
        response, _ = await scanner.send_explicit_raw(0x54, cm_path, fwd_bytes)
        assert response.status.is_success
        assert len(cm.active_connections) == 1

        # Forward_Close: conn_serial(2) + vendor(2) + orig_serial(4), after
        # priority_tick(1) + timeout_ticks(1).
        fc = struct.pack('<BBHHI', 0x0A, 0x05, 4321, 0x0001, 0xDEADBEEF)
        # The Forward_Close service wants a connection path trailer too.
        fc_full = fc + bytes([len(cm_path) // 2, 0x00]) + cm_path
        close_resp, _ = await scanner.send_explicit_raw(0x4E, cm_path, fc_full)
        assert close_resp.status.is_success
        assert cm.active_connections == []

        await scanner.close()
        # Still exactly one removal event, from the Forward_Close.
        for _ in range(10):
            await asyncio.sleep(0.01)
        assert len(removed) == 1
    finally:
        await adapter.close()
