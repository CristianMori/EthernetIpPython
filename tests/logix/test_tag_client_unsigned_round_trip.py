"""End-to-end loopback round-trip for the CIP §C-6.1 unsigned + bit-string
atomic type family.

Spins up a LogixDispatcher-backed EipAdapter on an ephemeral loopback TCP
port in a background task, connects a TagClient, writes each unsigned
type's full-range value through its typed write_* helper, reads it back
through its typed read_* helper, and verifies the full value survives
the client → wire → server → wire → client loop.

Covers the gap left by the in-process test_unsigned_and_bitstring_types
unit tests: those proved the server-side storage; this proves TagClient's
typed read_udint / write_udint helpers (and the matching bit-string
helpers) agree with the server-side tag_type check over the wire.
"""
from __future__ import annotations

import asyncio
import contextlib
import socket
import struct

import pytest

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.logix import data_types as dt
from ethernetip.logix.logix_dispatcher import LogixDispatcher
from ethernetip.logix.tag_client import TagClient
from ethernetip.logix.tag_database import TagDatabase
from ethernetip.protocol.eip_adapter import EipAdapter


def _grab_free_port() -> int:
    """Grab an unused loopback TCP port. There's a classic race between
    close here and listen() in the server, but loopback contention is
    low enough that this is fine for a fast test."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _spawn_logix_host(port: int) -> tuple[EipAdapter, TagDatabase, asyncio.Task]:
    identity = IdentityInfo(
        vendor_id=42, device_type=0x0E, product_code=1,
        major_revision=1, minor_revision=0,
        serial_number=0xC0DE, product_name="UnsignedRoundTripTarget",
    )
    tags = TagDatabase()
    tags.add_tag("u8",   dt.USINT)
    tags.add_tag("u16",  dt.UINT)
    tags.add_tag("u32",  dt.UDINT)
    tags.add_tag("u64",  dt.ULINT)
    tags.add_tag("b8",   dt.BYTE)
    tags.add_tag("w16",  dt.WORD)
    tags.add_tag("dw32", dt.DWORD)
    tags.add_tag("lw64", dt.LWORD)

    dispatcher = LogixDispatcher(tags=tags, identity=identity)
    adapter = EipAdapter(dispatcher, identity)
    task = asyncio.create_task(adapter.listen("127.0.0.1", port))
    # Yield so the asyncio.start_server call completes before we try to
    # connect. 50ms is overkill on loopback but keeps the test flake-free.
    await asyncio.sleep(0.05)
    return adapter, tags, task


async def _teardown(adapter: EipAdapter, task: asyncio.Task) -> None:
    await adapter.close()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def test_usint_full_range_round_trips():
    port = _grab_free_port()
    adapter, _, task = await _spawn_logix_host(port)
    try:
        client = TagClient("127.0.0.1", port)
        await client.connect()
        try:
            await client.write_usint("u8", 0xFF)
            assert await client.read_usint("u8") == 0xFF
        finally:
            await client.close()
    finally:
        await _teardown(adapter, task)


async def test_uint_full_range_round_trips():
    port = _grab_free_port()
    adapter, _, task = await _spawn_logix_host(port)
    try:
        client = TagClient("127.0.0.1", port)
        await client.connect()
        try:
            await client.write_uint("u16", 0xFFFF)
            assert await client.read_uint("u16") == 0xFFFF
        finally:
            await client.close()
    finally:
        await _teardown(adapter, task)


async def test_udint_full_range_round_trips():
    """The specific EscaFlow crash case — full-range over real TCP."""
    port = _grab_free_port()
    adapter, _, task = await _spawn_logix_host(port)
    try:
        client = TagClient("127.0.0.1", port)
        await client.connect()
        try:
            await client.write_udint("u32", 0xFFFFFFFF)
            assert await client.read_udint("u32") == 0xFFFFFFFF
        finally:
            await client.close()
    finally:
        await _teardown(adapter, task)


async def test_ulint_full_range_round_trips():
    port = _grab_free_port()
    adapter, _, task = await _spawn_logix_host(port)
    try:
        client = TagClient("127.0.0.1", port)
        await client.connect()
        try:
            await client.write_ulint("u64", 0xFFFFFFFFFFFFFFFF)
            assert await client.read_ulint("u64") == 0xFFFFFFFFFFFFFFFF
        finally:
            await client.close()
    finally:
        await _teardown(adapter, task)


async def test_byte_word_dword_lword_round_trip():
    """Bit-string types have their own typed helpers in the Python
    client, each sending the matching tag_type on the wire."""
    port = _grab_free_port()
    adapter, _, task = await _spawn_logix_host(port)
    try:
        client = TagClient("127.0.0.1", port)
        await client.connect()
        try:
            await client.write_byte("b8",   0xAB)
            await client.write_word("w16",  0xBEEF)
            await client.write_dword("dw32", 0xDEADBEEF)
            await client.write_lword("lw64", 0xFEEDFACECAFEBABE)

            assert await client.read_byte("b8")   == 0xAB
            assert await client.read_word("w16")  == 0xBEEF
            assert await client.read_dword("dw32") == 0xDEADBEEF
            assert await client.read_lword("lw64") == 0xFEEDFACECAFEBABE
        finally:
            await client.close()
    finally:
        await _teardown(adapter, task)


async def test_all_added_types_round_trip_in_one_session():
    """Reuse one TCP session across every added type. Catches
    state-machine / connection-handle bugs that only show up on sequential
    requests against tags of different widths."""
    port = _grab_free_port()
    adapter, _, task = await _spawn_logix_host(port)
    try:
        client = TagClient("127.0.0.1", port)
        await client.connect()
        try:
            await client.write_usint("u8",  0x12)
            await client.write_uint("u16",  0x1234)
            await client.write_udint("u32", 0x12345678)
            await client.write_ulint("u64", 0x123456789ABCDEF0)
            await client.write_byte("b8",   0xAB)
            await client.write_word("w16",  0xBEEF)
            await client.write_dword("dw32", 0xDEADBEEF)
            await client.write_lword("lw64", 0xFEEDFACECAFEBABE)

            assert await client.read_usint("u8")  == 0x12
            assert await client.read_uint("u16")  == 0x1234
            assert await client.read_udint("u32") == 0x12345678
            assert await client.read_ulint("u64") == 0x123456789ABCDEF0
            assert await client.read_byte("b8")   == 0xAB
            assert await client.read_word("w16")  == 0xBEEF
            assert await client.read_dword("dw32") == 0xDEADBEEF
            assert await client.read_lword("lw64") == 0xFEEDFACECAFEBABE
        finally:
            await client.close()
    finally:
        await _teardown(adapter, task)


async def test_signed_write_against_unsigned_tag_rejected_by_server():
    """Writing SINT bytes against a USINT-registered tag must fail the
    server-side tag_type check. This is what proves the typed-helper
    round-trip works for the right reason (not accidental tolerance).
    The server returns status 0xFF with extended 0x2107."""
    port = _grab_free_port()
    adapter, _, task = await _spawn_logix_host(port)
    try:
        client = TagClient("127.0.0.1", port)
        await client.connect()
        try:
            # write_sint sends tag_type=SINT against a USINT-registered
            # "u8" tag — same width but different code.
            with pytest.raises(Exception):
                await client.write_sint("u8", 1)
        finally:
            await client.close()
    finally:
        await _teardown(adapter, task)
