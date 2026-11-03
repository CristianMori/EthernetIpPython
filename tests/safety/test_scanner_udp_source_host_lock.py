"""Scanner-side UDP sender-IP authentication.

Mirror of the device-side fix in b9f65fe. SafetyScannerConnection's UDP
hook used to ignore the sender argument (``_sender``), so any LAN peer
that guessed a sequential ot_id could inject a frame into the scanner's
TCOO or client-data path. The fix drops any UDP whose source IP does
not match the known target endpoint.
"""
from __future__ import annotations

from ethernetip.safety.scanner_connection import SafetyScannerConnection


class _StubUdp:
    pass


def _make_conn() -> SafetyScannerConnection:
    conn = SafetyScannerConnection.__new__(SafetyScannerConnection)
    # Only populate the attributes _on_udp_data touches.
    conn.is_open = True
    conn._target_endpoint = ('192.168.1.76', 2222)
    conn._server_to_id = 0xDEADBEEF
    conn._client_to_id = 0xCAFEBABE
    conn._consumer_active = False
    conn._run_idle = False
    conn.log = []
    return conn


def test_scanner_drops_udp_from_wrong_sender_ip():
    """A 6-byte UDP routed to the server TO id from a different IP must
    NOT flip `_consumer_active`."""
    conn = _make_conn()
    conn._on_udp_data(conn._server_to_id, b'\x00' * 6, ('192.168.1.200', 2222))
    assert conn._consumer_active is False


def test_scanner_accepts_udp_from_target_ip():
    """Baseline: a frame from the target IP still gets routed."""
    conn = _make_conn()
    # Any 5/6-byte payload routed to _server_to_id activates the consumer in
    # the current scanner, independent of CRC gating (F2 handles that).
    conn._on_udp_data(conn._server_to_id, b'\x00' * 6, ('192.168.1.76', 2222))
    assert conn._consumer_active is True
