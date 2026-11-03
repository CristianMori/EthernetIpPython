"""The safety scanner must not crash with IndexError when the target
returns a status-success Forward_Open reply that is shorter than the
fixed Forward_Open-reply header.

Prior behavior: SafetyScannerConnection.open() read
``conn._server_ot_id = struct.unpack_from('<I', srd, 0)[0]``, then
``app_reply_words = srd[24]``. The unpack passed with any >= 4-byte
reply, but ``srd[24]`` raised IndexError on anything < 25 bytes and
tore the open() coroutine down with a generic exception that gave
the caller no safety-protocol-specific signal.

Fix: check ``len(reply) >= 26`` before any wire-dependent read of
the fixed FwdOpen-reply header and raise ``SafetyProtocolError``
with a descriptive message instead.
"""
from __future__ import annotations

import asyncio

import pytest

from ethernetip.cip.service import CipServiceResponse
from ethernetip.cip.status import CipStatus
from ethernetip.safety.forward_open_builder import SafetyForwardOpenConfig
from ethernetip.safety.frame_codec import SafetyFormat
from ethernetip.safety.scanner_connection import (
    SafetyProtocolError, SafetyScannerConnection,
)


class _MockScanner:
    """Minimal EipScanner stand-in — SafetyScannerConnection.open only
    needs send_explicit_raw and remote_endpoint for the server path."""

    def __init__(self, reply_data: bytes):
        self._reply_data = reply_data
        self.remote_endpoint = ('127.0.0.1', 0xAF12)

    async def send_explicit_raw(self, service_code, path, data):
        # Status 0 = success. Scanner inspects .data length afterwards.
        resp = CipServiceResponse(
            service_code=service_code | 0x80,
            status=CipStatus(general_status=0),
            data=self._reply_data,
        )
        return resp, []


def _make_config() -> SafetyForwardOpenConfig:
    return SafetyForwardOpenConfig(
        consumed_assembly=0x100,
        produced_assembly=0x101,
        config_assembly=0x102,
        consumed_data_size=2,
        produced_data_size=2,
        format=SafetyFormat.BASE,
    )


def test_short_server_fwdopen_reply_raises_safety_protocol_error():
    """<26 bytes of reply data trips the header-length check and
    surfaces as a SafetyProtocolError, not an IndexError leaking from
    srd[24] or a struct.error from an incomplete unpack_from."""
    # 10-byte reply — enough for both 4-byte conn ids and more, but
    # well below the 26-byte fixed-header minimum. srd[24] would
    # IndexError.
    short_reply = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A'
    scanner = _MockScanner(short_reply)
    cfg = _make_config()

    async def run():
        await SafetyScannerConnection.open(
            scanner, udp=None, server_config=cfg, client_config=cfg,
            orig_vendor=0x1234, orig_serial=0xDEADBEEF)

    with pytest.raises(SafetyProtocolError) as exc_info:
        asyncio.run(run())
    assert 'truncated' in str(exc_info.value).lower()


def test_boundary_too_short_by_one_byte_still_raises():
    """A 25-byte reply (one byte short of the 26-byte header) must
    still raise — the check is >= 26, not > 25."""
    reply = b'\x00' * 25
    scanner = _MockScanner(reply)
    cfg = _make_config()

    async def run():
        await SafetyScannerConnection.open(
            scanner, udp=None, server_config=cfg, client_config=cfg,
            orig_vendor=0, orig_serial=0)

    with pytest.raises(SafetyProtocolError):
        asyncio.run(run())
