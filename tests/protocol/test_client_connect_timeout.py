"""TCP connect timeout. A hanging connect is forced deterministically by
replacing asyncio.open_connection with a coroutine that never completes
(a non-routable address behaves differently per OS/network: some refuse
immediately, some drop SYNs, so it cannot give a stable bound)."""
import asyncio
import inspect
import socket
import time

import pytest

from ethernetip.logix.tag_client import TagClient
from ethernetip.protocol.eip_scanner import EipScanner

TIMEOUT = 0.3
TOL = 0.05    # asyncio timers may fire up to one clock tick early (~15.6 ms on Windows)


@pytest.fixture
def hanging_connect(monkeypatch):
    state = {'started': 0, 'cancelled': 0}

    async def hang(host, port, **kw):
        state['started'] += 1
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            state['cancelled'] += 1
            raise

    monkeypatch.setattr(asyncio, 'open_connection', hang)
    return state


async def test_scanner_connect_times_out(hanging_connect):
    sc = EipScanner(connect_timeout=TIMEOUT)
    t0 = time.monotonic()
    with pytest.raises(TimeoutError, match=r"connect.*10\.0\.0\.1:44818.*0\.3"):
        await sc.connect('10.0.0.1', 44818)
    assert TIMEOUT - TOL <= time.monotonic() - t0 < TIMEOUT + 1
    assert hanging_connect == {'started': 1, 'cancelled': 1}
    assert not sc.is_connected
    assert sc._writer is None and sc.udp is None


async def test_tag_client_connect_times_out(hanging_connect):
    tc = TagClient('10.0.0.1', connect_timeout=TIMEOUT)
    t0 = time.monotonic()
    with pytest.raises(TimeoutError, match=r"connect.*10\.0\.0\.1:44818.*0\.3"):
        await tc.connect()
    assert TIMEOUT - TOL <= time.monotonic() - t0 < TIMEOUT + 1
    assert hanging_connect == {'started': 1, 'cancelled': 1}
    assert not tc.is_connected
    assert tc._writer is None


async def test_connect_timeout_none_disables(hanging_connect):
    sc = EipScanner(connect_timeout=None)
    with pytest.raises(asyncio.TimeoutError):     # outer bound only
        await asyncio.wait_for(sc.connect('10.0.0.1'), TIMEOUT)
    tc = TagClient('10.0.0.1', connect_timeout=None)
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(tc.connect(), TIMEOUT)
    assert hanging_connect['started'] == 2


def test_connect_timeout_defaults():
    assert EipScanner().connect_timeout == 5.0
    assert TagClient('127.0.0.1').connect_timeout == 5.0
    for cls in (EipScanner, TagClient):
        p = inspect.signature(cls.__init__).parameters['connect_timeout']
        assert p.default == 5.0


async def test_refused_still_fails_fast():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()                                      # nothing listens here now
    for client, call in ((EipScanner(connect_timeout=30),
                          lambda c: c.connect('127.0.0.1', port)),
                         (TagClient('127.0.0.1', port, connect_timeout=30),
                          lambda c: c.connect())):
        t0 = time.monotonic()
        with pytest.raises(OSError) as ei:
            await call(client)
        assert not isinstance(ei.value, TimeoutError)
        assert time.monotonic() - t0 < 5
        assert not client.is_connected
