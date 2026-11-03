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


def _send_rr_data_frame(handle: int, cip_data: bytes) -> bytes:
    """Minimal SendRRData frame with a NullAddress + UnconnectedData CPF."""
    # CPF: count(2) + NullAddress(type 0x0000 + len 0x0000) + UnconnectedData(0x00B2 + len + data)
    cpf = struct.pack('<HHH', 2, 0x0000, 0x0000) + struct.pack('<HH', 0x00B2, len(cip_data)) + cip_data
    # SendRRData payload = InterfaceHandle(4) + Timeout(2) + CPF
    payload = struct.pack('<IH', 0, 5) + cpf
    hdr = EncapsulationHeader(
        command=EncapsulationCommand.SEND_RR_DATA,
        length=len(payload),
        session_handle=handle,
    )
    return hdr.to_bytes() + payload


@pytest.mark.asyncio
async def test_cross_socket_send_rr_data_rejected():
    """SendRRData with a session handle registered on another TCP socket
    must be rejected with INVALID_SESSION_HANDLE — not quietly serviced
    through the shared SessionManager."""
    adapter = _make_adapter()
    await adapter.listen('127.0.0.1', 0)
    try:
        victim = EipScanner()
        await victim.connect('127.0.0.1', adapter.port)
        victim_handle = victim.session_handle

        # Attacker opens its own socket, registers its own session, then
        # swaps in the victim's handle on a SendRRData.
        attacker = EipScanner()
        await attacker.connect('127.0.0.1', adapter.port)
        reader, writer = attacker._reader, attacker._writer

        # GetAttributeSingle on Identity attr 1 — a request we know works
        # on this adapter when sent with a valid same-socket handle.
        path = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x01])
        inner_mr = bytes([0x0E, len(path) // 2]) + path
        writer.write(_send_rr_data_frame(victim_handle, inner_mr))
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(HEADER_SIZE), timeout=1.0)
        parsed = EncapsulationHeader.parse(resp)
        assert parsed.command == EncapsulationCommand.SEND_RR_DATA
        assert parsed.status == EncapsulationStatus.INVALID_SESSION_HANDLE, (
            f"expected INVALID_SESSION_HANDLE, got {parsed.status!r}"
        )

        await attacker.close()
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
