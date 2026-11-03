"""A malformed safety network segment must be rejected at the safety
CIP layer, not surface as an encapsulation-level INCORRECT_DATA.

Prior behavior: ``parse_safety_segment`` validated the segment's own
claimed length but then unpacked format-specific fields at fixed
offsets. A crafted "0x50 0x03 0x00 ..." header (data_len_words=3,
format=Target) passed the self-length check with total=8 but
``struct.unpack_from('<I', data, 4)`` for the SCCRC walked off the
end of the 8-byte buffer and raised ``struct.error``. The exception
propagated through ``_process_forward_open`` into the broad
``_handle_client`` wrapper, which returned an encapsulation-level
INCORRECT_DATA to the originator instead of a CIP Forward_Open
error carrying a safety-specific extended status.
"""
from __future__ import annotations

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.connections.forward_open_request import ForwardOpenRequest
from ethernetip.safety.network_segment import SEGMENT_TYPE
from ethernetip.safety.safety_device import SafetyDevice
from ethernetip.safety.types import SafetyNetworkNumber


def _make_safety_device() -> SafetyDevice:
    return SafetyDevice(
        identity=IdentityInfo(),
        bind_address='0.0.0.0',
        snn=SafetyNetworkNumber(b'\x01\x02\x03\x04\x05\x06'),
        node_address=0xC0A80101,
    )


def test_malformed_target_segment_returns_safety_cip_error():
    """Crafted header claims Target format with a sub-minimum length.
    Before the fix: struct.error propagated.  After: validate returns
    0x080E (safety configuration invalid) so the connection manager
    emits a Forward_Open error at the safety CIP layer."""
    dev = _make_safety_device()
    bad_segment = bytes([SEGMENT_TYPE, 0x03, 0x00, 0x00, 0, 0, 0, 0])

    status = dev.validate_safety_open(bad_segment, ForwardOpenRequest())

    assert status == 0x080E


def test_malformed_extended_segment_returns_safety_cip_error():
    dev = _make_safety_device()
    bad_segment = bytes([SEGMENT_TYPE, 0x03, 0x02, 0x00, 0, 0, 0, 0])

    status = dev.validate_safety_open(bad_segment, ForwardOpenRequest())

    assert status == 0x080E


def test_unknown_format_segment_returns_safety_cip_error():
    dev = _make_safety_device()
    # Format byte 0x7F is not one of the three valid formats.
    bad_segment = bytes([SEGMENT_TYPE, 0x1B, 0x7F] + [0] * 53)

    status = dev.validate_safety_open(bad_segment, ForwardOpenRequest())

    assert status == 0x080E
