"""The I/O UDP receive path must authenticate the sender's host against
the Forward_Open originator before updating `remote_endpoint`.

Prior behavior: `_on_udp_data_with_sender` only checked the sender's port.
Once an attacker on the LAN guessed our ot_id (sequential allocator) and
sent one spoofed UDP datagram, every subsequent T→O frame was redirected
to the attacker's address. The host of the sender was never compared to
the TCP peer that opened the connection.

Fix (approach a): the originator's host is pinned on the connection row
at Forward_Open accept time. Any datagram whose source IP differs from
that pinned host is dropped. The ephemeral source port is still allowed
to drift so NAT re-bind / port rotation on the originator still works.
"""

from __future__ import annotations

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.connections.io_connection import IoConnection, ConnectionState
from ethernetip.device.virtual_device import VirtualDevice


def _make_device_with_conn(originator_host: str, ot_id: int = 0x1001) -> tuple[VirtualDevice, IoConnection]:
    dev = VirtualDevice(IdentityInfo())
    conn = IoConnection()
    conn.ot_connection_id = ot_id
    conn.state = ConnectionState.ESTABLISHED
    conn.originator_host = originator_host
    conn.remote_endpoint = (originator_host, 2222)
    # Insert directly into the connection table — we're exercising the
    # UDP callback, not the Forward_Open path.
    dev.connection_manager._connections[ot_id] = conn
    return dev, conn


def test_udp_from_originator_host_updates_endpoint_port():
    """Baseline: a packet from the originator's IP but a different ephemeral
    port is still accepted — the port is allowed to drift (NAT / rebind)."""
    dev, conn = _make_device_with_conn('10.0.0.5')
    assert conn.remote_endpoint == ('10.0.0.5', 2222)

    dev._on_udp_data_with_sender(conn.ot_connection_id, ('10.0.0.5', 54321))

    assert conn.remote_endpoint == ('10.0.0.5', 54321)


def test_udp_from_different_host_does_not_hijack_endpoint():
    """An attacker on the LAN who guessed the ot_id sends one UDP datagram
    from their own IP. The server must NOT redirect the T→O stream to
    that attacker's address."""
    dev, conn = _make_device_with_conn('10.0.0.5')
    original_endpoint = conn.remote_endpoint

    dev._on_udp_data_with_sender(conn.ot_connection_id, ('10.0.0.99', 2222))

    assert conn.remote_endpoint == original_endpoint
    assert conn.remote_endpoint != ('10.0.0.99', 2222)


def test_udp_from_different_host_rejected_even_with_matching_port():
    """Pre-fix, matching the stored port was enough to pass the check (and
    the host was ignored entirely). Verify the host check now kicks in
    before the port comparison."""
    dev, conn = _make_device_with_conn('10.0.0.5')
    # Attacker spoofs the exact same source port we currently believe the
    # originator is using. The host mismatch alone must drop the packet.
    dev._on_udp_data_with_sender(conn.ot_connection_id, ('10.0.0.99', 2222))

    assert conn.remote_endpoint == ('10.0.0.5', 2222)


def test_udp_calls_on_remote_endpoint_updated_only_for_authenticated_host():
    """The subclass hook `on_remote_endpoint_updated` (used by SafetyDevice
    to propagate the endpoint across sibling safety connections) must fire
    only when the sender passes the host check."""
    dev, conn = _make_device_with_conn('10.0.0.5')
    fired: list[tuple[str, int]] = []
    dev.on_remote_endpoint_updated = lambda c, s: fired.append(s)  # type: ignore[method-assign]

    # Spoofed host — hook must not fire.
    dev._on_udp_data_with_sender(conn.ot_connection_id, ('10.0.0.99', 7777))
    assert fired == []

    # Legitimate host with a new ephemeral port — hook fires once.
    dev._on_udp_data_with_sender(conn.ot_connection_id, ('10.0.0.5', 7777))
    assert fired == [('10.0.0.5', 7777)]
