"""SCID binding on the Safety Supervisor is one-time.

Before this fix, every call to `configure_safety_connection` on a
safety FwdOpen that carried a safety segment overwrote the supervisor
SCID with that segment's sccrc/scts — even when the segment carried
no SCID at all (sccrc=0). A second originator that opened an I/O-only
connection against the same device would therefore clobber the SCID
recorded by the first (configuring) originator, breaking any
third originator's SCID-match validation.

Rockwell devices treat the SCID as a one-time binding written at
first configuration and cleared only by Safety_Reset / connection
teardown. First write wins.
"""
from __future__ import annotations

import struct

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.connections.forward_open_request import ForwardOpenRequest
from ethernetip.connections.io_connection import IoConnection
from ethernetip.safety.network_segment import SafetyNetworkSegment
from ethernetip.safety.safety_device import SafetyDevice
from ethernetip.safety.types import (
    SafetyNetworkNumber, UniqueNetworkId,
)


_SNN = SafetyNetworkNumber(b'\x01\x02\x03\x04\x05\x06')
_NODE = 0xC0A80101


def _make_safety_device() -> SafetyDevice:
    return SafetyDevice(
        identity=IdentityInfo(),
        bind_address='0.0.0.0',
        snn=_SNN,
        node_address=_NODE,
    )


def _build_safety_segment(sccrc: int, scts: bytes = b'\x11' * 6) -> bytes:
    """Encode a Target-format safety segment with the supervisor's TUNID."""
    seg = SafetyNetworkSegment(
        format=0x00,
        sccrc=sccrc,
        scts=scts,
        tunid=UniqueNetworkId(snn=_SNN, node_address=_NODE),
        ounid=UniqueNetworkId(snn=_SNN, node_address=_NODE),
        ping_interval_multiplier=1,
        time_coord_msg_min_multiplier=1,
        network_time_expectation_multiplier=1,
        timeout_multiplier=1,
        max_consumer_number=1,
        cpcrc=0,
        time_correction_connection_id=0,
    )
    buf = bytearray(seg.wire_size)
    seg.encode(buf, 0)
    return bytes(buf)


def _make_conn(safety_segment: bytes) -> IoConnection:
    conn = IoConnection()
    conn.is_safety = True
    conn.safety_segment_data = safety_segment
    conn.to_rpi = 10_000  # arbitrary nonzero for correction-constant math
    return conn


def _make_fo(trigger: int = 0xA0,
             orig_vendor: int = 0x1234,
             orig_serial: int = 0xDEADBEEF,
             conn_serial: int = 0x0001) -> ForwardOpenRequest:
    return ForwardOpenRequest(
        transport_class_trigger=trigger,
        originator_vendor_id=orig_vendor,
        originator_serial_number=orig_serial,
        connection_serial_number=conn_serial,
    )


def test_second_fo_with_sccrc_zero_does_not_clobber_scid():
    """First FO carries a real SCID; second FO's safety segment has
    sccrc=0 (no configuration). The supervisor must still hold the
    first SCID."""
    dev = _make_safety_device()

    first_scid = 0xCAFEBABE
    first_seg = _build_safety_segment(first_scid)
    dev.configure_safety_connection(_make_conn(first_seg), _make_fo())

    assert dev._supervisor.scid.sccrc == first_scid

    second_seg = _build_safety_segment(0, scts=b'\x00' * 6)
    dev.configure_safety_connection(_make_conn(second_seg),
                                      _make_fo(orig_serial=0xBEEF0001))

    # First write wins — SCID must still be the first originator's.
    assert dev._supervisor.scid.sccrc == first_scid


def test_second_fo_with_different_sccrc_does_not_clobber_scid():
    """Even a second FO with a non-zero but DIFFERENT SCID must not
    replace an already-bound SCID — a different-SCID originator should
    be rejected by validate_safety_open, not permitted to rebind."""
    dev = _make_safety_device()

    first_scid = 0xCAFEBABE
    dev.configure_safety_connection(
        _make_conn(_build_safety_segment(first_scid)), _make_fo())

    other_scid = 0xDEADC0DE
    dev.configure_safety_connection(
        _make_conn(_build_safety_segment(other_scid)),
        _make_fo(orig_serial=0xBEEF0001))

    assert dev._supervisor.scid.sccrc == first_scid
