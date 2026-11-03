"""Per-socket session_handles bookkeeping on UnregisterSession.

A peer that opens multiple sessions on a single TCP socket may unregister
any of them. The adapter must drop the handle the peer actually
unregistered (msg.session_handle), not the socket's "current" one. If it
drops the current one instead, the still-live sibling session is orphaned
on this socket's bookkeeping and the just-closed id lingers as a stale
entry — the next SendRRData against the live sibling fails with
INVALID_SESSION_HANDLE even though the SessionManager still has it.
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


def _make_adapter():
    dispatcher = CipDispatcher()
    id_class = CipClass(0x01, "Identity")
    id_class.add_standard_instance_services()
    inst = id_class.create_instance(1)
    inst.add_attribute(CipAttribute.create_uint(1, CipDataType.UINT, AttributeAccess.ALL, 0x0001))
    dispatcher.register_class(id_class)
    return EipAdapter(dispatcher, IdentityInfo())


def _register_frame() -> bytes:
    payload = struct.pack('<HH', 1, 0)
    hdr = EncapsulationHeader(
        command=EncapsulationCommand.REGISTER_SESSION,
        length=4,
        session_handle=0,
    )
    return hdr.to_bytes() + payload


def _unregister_frame(handle: int) -> bytes:
    hdr = EncapsulationHeader(
        command=EncapsulationCommand.UNREGISTER_SESSION,
        length=0,
        session_handle=handle,
    )
    return hdr.to_bytes()


def _send_rr_data_frame(handle: int, cip_data: bytes) -> bytes:
    """Minimal SendRRData frame with a NullAddress + UnconnectedData CPF."""
    cpf = struct.pack('<HHH', 2, 0x0000, 0x0000) + struct.pack('<HH', 0x00B2, len(cip_data)) + cip_data
    payload = struct.pack('<IH', 0, 5) + cpf
    hdr = EncapsulationHeader(
        command=EncapsulationCommand.SEND_RR_DATA,
        length=len(payload),
        session_handle=handle,
    )
    return hdr.to_bytes() + payload


async def _read_response(reader) -> EncapsulationHeader:
    hdr_bytes = await asyncio.wait_for(reader.readexactly(HEADER_SIZE), timeout=1.0)
    parsed = EncapsulationHeader.parse(hdr_bytes)
    if parsed.length:
        await asyncio.wait_for(reader.readexactly(parsed.length), timeout=1.0)
    return parsed


@pytest.mark.asyncio
async def test_unregister_sibling_keeps_current_handle_live():
    """Open two sessions (A then B) on one socket. B is the "current"
    handle. Unregister A. The adapter must drop A from the per-socket
    list and keep B — a subsequent SendRRData with B still succeeds."""
    adapter = _make_adapter()
    await adapter.listen('127.0.0.1', 0)
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', adapter.port)
        try:
            # Register two sessions on this one socket.
            writer.write(_register_frame())
            await writer.drain()
            parsed_a = await _read_response(reader)
            assert parsed_a.status == EncapsulationStatus.SUCCESS
            handle_a = parsed_a.session_handle

            writer.write(_register_frame())
            await writer.drain()
            parsed_b = await _read_response(reader)
            assert parsed_b.status == EncapsulationStatus.SUCCESS
            handle_b = parsed_b.session_handle
            assert handle_a != handle_b

            # Unregister the non-current one (A). The current handle is B.
            writer.write(_unregister_frame(handle_a))
            await writer.drain()

            # Give the adapter a tick to process the frame.
            for _ in range(20):
                if not adapter._sessions.is_valid(handle_a):
                    break
                await asyncio.sleep(0.01)
            assert not adapter._sessions.is_valid(handle_a)
            # B must still be live in the shared session table.
            assert adapter._sessions.is_valid(handle_b)

            # And a SendRRData with B must still work — if the bookkeeping
            # bug were still present, B would have been removed from the
            # per-socket list and this would come back INVALID_SESSION_HANDLE.
            path = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x01])
            inner_mr = bytes([0x0E, len(path) // 2]) + path
            writer.write(_send_rr_data_frame(handle_b, inner_mr))
            await writer.drain()
            resp = await _read_response(reader)
            assert resp.command == EncapsulationCommand.SEND_RR_DATA
            assert resp.status == EncapsulationStatus.SUCCESS, (
                f"expected SUCCESS, got {resp.status!r}"
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    finally:
        await adapter.close()
