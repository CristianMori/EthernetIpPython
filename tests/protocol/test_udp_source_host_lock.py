"""The I/O UDP receive path must authenticate the sender's host against
the Forward_Open originator before updating ANY per-connection state —
``remote_endpoint`` AND the consumer assembly / first_received flag.

Prior behavior: the host-lock only gated the T→O redirect, and lived in
a separate ``_on_udp_data_with_sender`` callback that ran AFTER the data
callback had already written the consumer assembly. Once an attacker on
the LAN guessed our ot_id (sequential allocator), a single spoofed UDP
datagram got its payload written into the consumer assembly even though
the T→O endpoint stayed pinned to the real originator.

Fix: callbacks were unified onto a single sender-aware list. The virtual
device looks the connection up, drops the packet on IP mismatch, and
only then updates the endpoint port, timestamp, first_received flag,
and consumer assembly. The ephemeral source port is still allowed to
drift so NAT re-bind / port rotation on the originator still works.
"""

from __future__ import annotations

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.connections.io_connection import (
    IoConnection, ConnectionState, TransportClass,
)
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

    dev._on_udp_data_received(conn.ot_connection_id, b'', ('10.0.0.5', 54321))

    assert conn.remote_endpoint == ('10.0.0.5', 54321)


def test_udp_from_different_host_does_not_hijack_endpoint():
    """An attacker on the LAN who guessed the ot_id sends one UDP datagram
    from their own IP. The server must NOT redirect the T→O stream to
    that attacker's address."""
    dev, conn = _make_device_with_conn('10.0.0.5')
    original_endpoint = conn.remote_endpoint

    dev._on_udp_data_received(conn.ot_connection_id, b'', ('10.0.0.99', 2222))

    assert conn.remote_endpoint == original_endpoint
    assert conn.remote_endpoint != ('10.0.0.99', 2222)


def test_udp_from_different_host_rejected_even_with_matching_port():
    """Pre-fix, matching the stored port was enough to pass the check (and
    the host was ignored entirely). Verify the host check now kicks in
    before the port comparison."""
    dev, conn = _make_device_with_conn('10.0.0.5')
    # Attacker spoofs the exact same source port we currently believe the
    # originator is using. The host mismatch alone must drop the packet.
    dev._on_udp_data_received(conn.ot_connection_id, b'', ('10.0.0.99', 2222))

    assert conn.remote_endpoint == ('10.0.0.5', 2222)


def test_udp_calls_on_remote_endpoint_updated_only_for_authenticated_host():
    """The subclass hook `on_remote_endpoint_updated` (used by SafetyDevice
    to propagate the endpoint across sibling safety connections) must fire
    only when the sender passes the host check."""
    dev, conn = _make_device_with_conn('10.0.0.5')
    fired: list[tuple[str, int]] = []
    dev.on_remote_endpoint_updated = lambda c, s: fired.append(s)  # type: ignore[method-assign]

    # Spoofed host — hook must not fire.
    dev._on_udp_data_received(conn.ot_connection_id, b'', ('10.0.0.99', 7777))
    assert fired == []

    # Legitimate host with a new ephemeral port — hook fires once.
    dev._on_udp_data_received(conn.ot_connection_id, b'', ('10.0.0.5', 7777))
    assert fired == [('10.0.0.5', 7777)]


def test_udp_from_different_host_does_not_write_consumer_assembly():
    """Regression for the data-callback-ran-before-sender-check ordering:
    a datagram from a spoofed IP must not reach ``handle_received_io_data``
    and so must not touch the consumer assembly. A follow-up datagram
    from the real originator must still land, proving the drop was
    sender-specific, not a global mute."""
    dev = VirtualDevice(IdentityInfo())
    asm = dev.assemblies.add_instance(100, data_size=4)

    conn = IoConnection()
    conn.ot_connection_id = 0x2001
    conn.state = ConnectionState.ESTABLISHED
    conn.originator_host = '10.0.0.5'
    conn.remote_endpoint = ('10.0.0.5', 2222)
    conn.consumed_assembly_instance = 100
    # CLASS0: payload is written straight through — no 6-byte seq/run-idle
    # prefix to strip, so we can assert exact bytes.
    conn.transport_class = TransportClass.CLASS0
    dev.connection_manager._connections[conn.ot_connection_id] = conn

    assert asm.get_data() == b'\x00\x00\x00\x00'
    assert conn.first_received is False

    # Spoofed packet — must be dropped before touching assembly or flags.
    dev._on_udp_data_received(
        conn.ot_connection_id, b'\xDE\xAD\xBE\xEF', ('10.0.0.99', 2222))
    assert asm.get_data() == b'\x00\x00\x00\x00'
    assert conn.first_received is False

    # Real originator's packet — assembly updates and first_received flips.
    dev._on_udp_data_received(
        conn.ot_connection_id, b'\x11\x22\x33\x44', ('10.0.0.5', 2222))
    assert asm.get_data() == b'\x11\x22\x33\x44'
    assert conn.first_received is True
