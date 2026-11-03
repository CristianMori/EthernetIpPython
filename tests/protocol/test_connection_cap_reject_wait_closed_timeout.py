"""Connection-cap reject path must not park the handler on wait_closed.

When ``_active_connections >= max_connections`` the adapter closes the
new writer and awaits ``writer.wait_closed()`` so the fd is released
promptly. A hostile peer that refuses to ACK the FIN would otherwise
suspend ``wait_closed()`` indefinitely and leak the handler coroutine
(the kernel still releases the socket on its own schedule, so this is
a coroutine leak, not an fd leak).

Guard: the wait is wrapped in ``asyncio.wait_for(..., timeout=5.0)``
inside the existing try/except. The regression test replaces the
writer with one whose ``wait_closed`` never completes and asserts
``_handle_client`` still returns.
"""
from __future__ import annotations

import asyncio
import pytest

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.protocol.eip_adapter import EipAdapter


class _StuckWriter:
    """Minimal StreamWriter stand-in whose wait_closed never resolves."""

    def __init__(self):
        self.closed = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        # Mimic a peer that will not ACK the FIN.
        await asyncio.Event().wait()

    def get_extra_info(self, name, default=None):
        return default


@pytest.mark.asyncio
async def test_connection_cap_reject_does_not_hang_on_wait_closed(monkeypatch):
    # Shrink the inner wait_closed budget so the test runs quickly
    # without burning the full production 5.0 s. We wrap only the 5.0 s
    # case so the test's own asyncio.wait_for (used as the outer
    # safety net) still honours its own timeout argument.
    real_wait_for = asyncio.wait_for

    async def fast_wait_for(aw, timeout):
        if timeout == 5.0:
            timeout = 0.1
        return await real_wait_for(aw, timeout=timeout)

    monkeypatch.setattr(asyncio, 'wait_for', fast_wait_for)

    adapter = EipAdapter(
        dispatch=lambda *a, **k: None,
        identity=IdentityInfo(),
        max_connections=1,
    )
    adapter._active_connections = 1  # already at the cap

    writer = _StuckWriter()
    reader = asyncio.StreamReader()

    # Direct await — if the fix regresses the stuck writer would park
    # _handle_client forever and the pytest-level timeout would fire.
    await real_wait_for(
        adapter._handle_client(reader, writer),  # type: ignore[arg-type]
        timeout=2.0,
    )
    assert writer.closed
