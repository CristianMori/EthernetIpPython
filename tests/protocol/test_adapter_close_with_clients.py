"""EipAdapter.close() / VirtualDevice.close() must not wait on connected peers.

Since Python 3.12.1 ``Server.wait_closed()`` waits for every active
connection. The per-client handler idles for up to ``idle_timeout`` (60 s)
in ``reader.read()``, so close() used to take ~60 s with an idle peer and
never returned with a peer that kept sending traffic.
"""

from __future__ import annotations

import asyncio
import struct
import time

from ethernetip.cip.dispatcher import CipDispatcher
from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.device.virtual_device import VirtualDevice
from ethernetip.protocol.eip_adapter import EipAdapter
from ethernetip.protocol.eip_scanner import EipScanner

CLOSE_BUDGET = 2.0
NOP = struct.pack('<HHIIQI', 0x0000, 0, 0, 0, 0, 0)


async def _started_adapter() -> EipAdapter:
    adapter = EipAdapter(CipDispatcher(), IdentityInfo())
    await adapter.listen('127.0.0.1', 0)
    return adapter


async def _timed_close(closer) -> float:
    start = time.monotonic()
    await asyncio.wait_for(closer.close(), timeout=10)
    return time.monotonic() - start


async def test_close_with_idle_client_is_prompt():
    adapter = await _started_adapter()
    reader, writer = await asyncio.open_connection('127.0.0.1', adapter.port)
    await asyncio.sleep(0.1)  # let the handler start
    assert adapter._active_connections == 1

    elapsed = await _timed_close(adapter)

    assert elapsed < CLOSE_BUDGET
    # The peer sees the connection end (EOF or reset).
    try:
        data = await asyncio.wait_for(reader.read(1), timeout=2)
        assert data == b''
    except ConnectionError:
        pass
    assert adapter._active_connections == 0
    assert not adapter._clients
    writer.close()


async def test_close_with_chatty_client_is_prompt():
    adapter = await _started_adapter()
    reader, writer = await asyncio.open_connection('127.0.0.1', adapter.port)

    async def chatter():
        try:
            while True:
                writer.write(NOP)
                await writer.drain()
                await asyncio.sleep(0.1)
        except (ConnectionError, OSError):
            pass

    task = asyncio.create_task(chatter())
    await asyncio.sleep(0.35)

    elapsed = await _timed_close(adapter)

    assert elapsed < CLOSE_BUDGET
    try:
        assert await asyncio.wait_for(reader.read(1), timeout=2) == b''
    except ConnectionError:
        pass
    await asyncio.wait_for(task, timeout=2)
    writer.close()


async def test_close_with_several_clients_and_no_clients():
    adapter = await _started_adapter()
    conns = [await asyncio.open_connection('127.0.0.1', adapter.port) for _ in range(5)]
    await asyncio.sleep(0.1)
    assert await _timed_close(adapter) < CLOSE_BUDGET
    for _, w in conns:
        w.close()

    empty = await _started_adapter()
    assert await _timed_close(empty) < CLOSE_BUDGET


async def test_close_runs_per_connection_cleanup():
    adapter = await _started_adapter()
    reader, writer = await asyncio.open_connection('127.0.0.1', adapter.port)
    # RegisterSession
    writer.write(struct.pack('<HHIIQI', 0x0065, 4, 0, 0, 0, 0) + struct.pack('<HH', 1, 0))
    await writer.drain()
    reply = await asyncio.wait_for(reader.readexactly(28), timeout=2)
    handle = struct.unpack_from('<I', reply, 4)[0]
    assert adapter._sessions.is_valid(handle)

    await _timed_close(adapter)

    assert not adapter._sessions.is_valid(handle)
    writer.close()


async def test_virtual_device_close_with_idle_scanner_is_prompt():
    dev = VirtualDevice(IdentityInfo(), bind_address='127.0.0.1')
    await dev.start(tcp_port=0, udp_port=0)
    scanner = EipScanner()
    await scanner.connect('127.0.0.1', dev._adapter.port)
    assert scanner.is_connected

    elapsed = await _timed_close(dev)

    assert elapsed < CLOSE_BUDGET
    await asyncio.wait_for(scanner.close(), timeout=5)
