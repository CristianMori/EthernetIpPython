"""The adapter must close a TCP peer that drip-feeds a partial frame.

StreamReader.read() returns on any byte available, so the per-chunk
idle_timeout resets on every byte. A peer sending one byte every
`idle_timeout - ε` seconds would otherwise park the socket forever
while `accum` grows up to the 64 KiB encapsulation limit.
"""

from __future__ import annotations

import asyncio

import pytest

from ethernetip.cip.cip_class import CipClass
from ethernetip.cip.attribute import CipAttribute, AttributeAccess
from ethernetip.cip.data_types import CipDataType
from ethernetip.cip.dispatcher import CipDispatcher
from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.protocol.eip_adapter import EipAdapter


def _dispatcher() -> CipDispatcher:
    dispatcher = CipDispatcher()
    id_class = CipClass(0x01, "Identity")
    id_class.add_standard_instance_services()
    inst = id_class.create_instance(1)
    inst.add_attribute(CipAttribute.create_uint(1, CipDataType.UINT, AttributeAccess.ALL, 0x0001))
    dispatcher.register_class(id_class)
    return dispatcher


@pytest.mark.asyncio
async def test_slow_drip_closes_socket(monkeypatch):
    # Shrink the frame-assembly budget so the test finishes quickly, but
    # keep idle_timeout above it so the per-chunk timer never fires.
    import ethernetip.protocol.eip_adapter as adapter_mod
    monkeypatch.setattr(adapter_mod, "FRAME_ASSEMBLY_TIMEOUT", 0.15)

    adapter = EipAdapter(_dispatcher(), IdentityInfo(), idle_timeout=5.0)
    await adapter.listen('127.0.0.1', 0)
    port = adapter.port
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', port)

        # Drip one byte at a time; a RegisterSession frame is 28 bytes.
        # The adapter has to see FRAME_ASSEMBLY_TIMEOUT elapse before we
        # finish sending.
        header = bytes.fromhex("65000400000000000000000000000000000000000000000000000000")
        for b in header[:4]:
            writer.write(bytes([b]))
            await writer.drain()
            await asyncio.sleep(0.08)   # slow enough that 4 * 0.08 > 0.15

        # The adapter should have closed the socket by now. A read returns
        # EOF (empty bytes) once the server-side close propagates.
        try:
            data = await asyncio.wait_for(reader.read(1), timeout=2.0)
        except asyncio.TimeoutError:
            pytest.fail("adapter did not close socket after assembly timeout")
        assert data == b''
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_fast_drip_still_accepted(monkeypatch):
    """A client that completes its frame within the budget is unaffected."""
    import ethernetip.protocol.eip_adapter as adapter_mod
    monkeypatch.setattr(adapter_mod, "FRAME_ASSEMBLY_TIMEOUT", 1.0)

    from ethernetip.protocol.eip_scanner import EipScanner

    adapter = EipAdapter(_dispatcher(), IdentityInfo())
    await adapter.listen('127.0.0.1', 0)
    try:
        scanner = EipScanner()
        await scanner.connect('127.0.0.1', adapter.port)
        assert scanner.session_handle > 0

        # A follow-up explicit request also round-trips: no spurious drops.
        path = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x01])
        resp = await scanner.send_explicit(0x0E, path)
        assert resp.status.is_success
        await scanner.close()
    finally:
        await adapter.close()
