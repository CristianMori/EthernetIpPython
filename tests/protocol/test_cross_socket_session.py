"""Cross-socket session-handle isolation.

A peer must not be able to kill another peer's session via
UnregisterSession with a stolen/guessed handle. Each TCP socket owns the
set of session handles registered on it, and UnregisterSession frames
whose handle is not in that set are rejected with INVALID_SESSION_HANDLE
without touching the SessionManager.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from ethernetip.cip.cip_class import CipClass
from ethernetip.cip.attribute import CipAttribute, AttributeAccess
from ethernetip.cip.data_types import CipDataType
from ethernetip.cip.dispatcher import CipDispatcher
from ethernetip.cip.encapsulation import (
    EncapsulationCommand, EncapsulationHeader, EncapsulationStatus, SIZE as HEADER_SIZE,
)
from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.protocol.eip_adapter import EipAdapter
from ethernetip.protocol.eip_scanner import EipScanner


def _make_adapter():
    dispatcher = CipDispatcher()
    id_class = CipClass(0x01, "Identity")
    id_class.add_standard_instance_services()
    inst = id_class.create_instance(1)
    inst.add_attribute(CipAttribute.create_uint(1, CipDataType.UINT, AttributeAccess.ALL, 0x0001))
    dispatcher.register_class(id_class)
    return EipAdapter(dispatcher, IdentityInfo())


def _unregister_frame(handle: int) -> bytes:
    hdr = EncapsulationHeader(
        command=EncapsulationCommand.UNREGISTER_SESSION,
        length=0,
        session_handle=handle,
    )
    return hdr.to_bytes()


@pytest.mark.asyncio
async def test_cross_socket_unregister_cannot_kill_victim():
    adapter = _make_adapter()
    await adapter.listen('127.0.0.1', 0)
    try:
        victim = EipScanner()
        await victim.connect('127.0.0.1', adapter.port)
        assert victim.is_connected
        victim_handle = victim.session_handle

        # Attacker opens its own TCP socket but tries to UnregisterSession
        # against the victim's handle. The adapter must refuse without
        # removing the victim's session from the shared SessionManager.
        reader, writer = await asyncio.open_connection('127.0.0.1', adapter.port)
        try:
            writer.write(_unregister_frame(victim_handle))
            await writer.drain()
            # Adapter must respond with INVALID_SESSION_HANDLE instead of
            # silently killing the victim.
            resp = await asyncio.wait_for(reader.readexactly(HEADER_SIZE), timeout=1.0)
            parsed = EncapsulationHeader.parse(resp)
            assert parsed.command == EncapsulationCommand.UNREGISTER_SESSION
            assert parsed.status == EncapsulationStatus.INVALID_SESSION_HANDLE
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        # Victim's session must still be usable — read Identity vendor id.
        path = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x01])
        resp = await victim.send_explicit(0x0E, path)
        assert resp.status.is_success
        assert resp.data == b'\x01\x00'

        await victim.close()
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_same_socket_unregister_still_works():
    """A peer unregistering ITS OWN session handle must still succeed
    (no response is sent, following the existing one-way semantics)."""
    adapter = _make_adapter()
    await adapter.listen('127.0.0.1', 0)
    try:
        scanner = EipScanner()
        await scanner.connect('127.0.0.1', adapter.port)
        # EipScanner.close sends UnregisterSession on the same socket,
        # then the adapter removes the session cleanly.
        handle = scanner.session_handle
        assert adapter._sessions.is_valid(handle)
        await scanner.close()
        # Give the adapter a tick to process the frame.
        for _ in range(20):
            if not adapter._sessions.is_valid(handle):
                break
            await asyncio.sleep(0.01)
        assert not adapter._sessions.is_valid(handle)
    finally:
        await adapter.close()
