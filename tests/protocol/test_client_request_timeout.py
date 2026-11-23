"""Client-side requests time out against a peer that keeps TCP open but never replies."""
import asyncio
import struct
import time

import pytest

from ethernetip.logix.tag_client import TagClient
from ethernetip.protocol.eip_scanner import EipScanner

TIMEOUT = 0.5
REGISTER_SESSION = 0x0065


async def _silent_server():
    """Answers RegisterSession, then reads forever without replying."""
    writers = []

    async def handle(reader, writer):
        writers.append(writer)
        try:
            hdr = await reader.readexactly(24)
            cmd, length = struct.unpack_from('<HH', hdr, 0)
            await reader.readexactly(length)
            if cmd == REGISTER_SESSION:
                resp = bytearray(hdr)
                struct.pack_into('<I', resp, 4, 0x1234)   # session handle
                writer.write(bytes(resp) + struct.pack('<HH', 1, 0))
                await writer.drain()
            while await reader.read(4096):
                pass
        except (asyncio.IncompleteReadError, ConnectionError):
            pass

    server = await asyncio.start_server(handle, '127.0.0.1', 0)
    return server, server.sockets[0].getsockname()[1], writers


async def _shutdown(server, writers):
    for w in writers:
        w.close()
    server.close()
    await server.wait_closed()


async def test_scanner_request_times_out():
    server, port, writers = await _silent_server()
    try:
        sc = EipScanner(request_timeout=TIMEOUT)
        await sc.connect('127.0.0.1', port)
        t0 = time.monotonic()
        with pytest.raises(TimeoutError):
            await sc.send_explicit(0x0E, bytes([0x20, 0x01, 0x24, 0x01]))
        assert time.monotonic() - t0 < TIMEOUT + 1
        assert not sc.is_connected
        await sc.close()
    finally:
        await _shutdown(server, writers)


async def test_scanner_close_returns_promptly_against_silent_server():
    server, port, writers = await _silent_server()
    try:
        sc = EipScanner(request_timeout=TIMEOUT)
        await sc.connect('127.0.0.1', port)
        t0 = time.monotonic()
        await sc.close()
        assert time.monotonic() - t0 < TIMEOUT + 1
    finally:
        await _shutdown(server, writers)


async def test_tag_client_request_times_out():
    server, port, writers = await _silent_server()
    try:
        tc = TagClient('127.0.0.1', port, request_timeout=TIMEOUT)
        await tc.connect()
        t0 = time.monotonic()
        with pytest.raises(TimeoutError):
            await tc._send_encapsulated(0x006F, b'\x00' * 6)
        assert time.monotonic() - t0 < TIMEOUT + 1
        assert not tc.is_connected
        await tc.close()
    finally:
        await _shutdown(server, writers)


async def test_tag_client_class3_close_returns_promptly_against_silent_server():
    server, port, writers = await _silent_server()
    try:
        tc = TagClient('127.0.0.1', port, request_timeout=TIMEOUT)
        await tc.connect()
        tc._class3_open = True   # simulate an open Class 3 connection: close sends Forward_Close
        t0 = time.monotonic()
        await tc.close()
        assert time.monotonic() - t0 < TIMEOUT + 1
        assert not tc.is_connected
    finally:
        await _shutdown(server, writers)


async def test_default_timeout_is_five_seconds():
    assert EipScanner().request_timeout == 5.0
    assert TagClient('127.0.0.1').request_timeout == 5.0
