"""Class 3 connected-explicit messaging from the scanner side.

Backed by a Class 3 Forward Open to the target's Message Router; subsequent
send() / send_raw() calls travel over TCP via SendUnitData (encap 0x70).
"""
from __future__ import annotations

import asyncio

from ..cip.path_builder import build_path
from ..cip.service import CipServiceResponse


class ConnectedExplicit:
    def __init__(self, scanner, oto_t_connection_id: int, tto_o_connection_id: int,
                  connection_serial: int, originator_vendor: int, originator_serial: int):
        self._scanner            = scanner
        self._oto_t              = oto_t_connection_id
        self._tto_o              = tto_o_connection_id
        self._connection_serial  = connection_serial
        self._orig_vendor        = originator_vendor
        self._orig_serial        = originator_serial
        self._seq_count          = 0
        self._open               = True
        self._lock               = asyncio.Lock()

    @property
    def is_open(self) -> bool:
        return self._open

    async def send(self, service_code: int, class_id: int, instance_id: int,
                    attribute_id: int | None = None, data: bytes = b'') -> CipServiceResponse:
        """Send a request addressed by class + instance (+ optional attribute).
        Builds the EPATH via cip.path_builder.build_path."""
        path = build_path(class_id, instance_id, attribute_id)
        return await self.send_raw(service_code, path, data)

    async def send_raw(self, service_code: int, path_bytes: bytes,
                        data: bytes = b'') -> CipServiceResponse:
        """Send a request with an already-encoded EPATH (symbolic / multi-element)."""
        if not self._open:
            raise RuntimeError("ConnectedExplicit: closed")
        async with self._lock:
            self._seq_count = (self._seq_count + 1) & 0xFFFF
            seq = self._seq_count
        return await self._scanner._send_connected_mr(
            self._oto_t, seq, service_code, path_bytes, data)

    async def close(self) -> None:
        if not self._open:
            return
        self._open = False
        try:
            await self._scanner.forward_close(
                self._connection_serial, self._orig_vendor, self._orig_serial)
        except Exception:
            pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()
