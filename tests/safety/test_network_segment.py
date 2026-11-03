"""Safety Network Segment parser/encoder tests."""
import pytest
from ethernetip.safety.network_segment import (
    SafetyNetworkSegment, parse_safety_segment, SEGMENT_TYPE,
    SafetySegmentFormatError,
)
from ethernetip.safety.types import UniqueNetworkId, SafetyNetworkNumber


def _make_target_segment() -> SafetyNetworkSegment:
    return SafetyNetworkSegment(
        format=0x00,
        sccrc=0x12345678,
        scts=b'\x01\x02\x03\x04\x05\x06',
        time_correction_epi=10_000,
        time_correction_params=0x4001,
        tunid=UniqueNetworkId(
            snn=SafetyNetworkNumber(b'\xC9\x12\xB4\x00\x8D\x4D'),
            node_address=0xC0A80154),
        ounid=UniqueNetworkId(
            snn=SafetyNetworkNumber(b'\x01\x02\x03\x04\x05\x06'),
            node_address=0xC0A80164),
        ping_interval_multiplier=128,
        time_coord_msg_min_multiplier=160,
        network_time_expectation_multiplier=320,
        timeout_multiplier=2,
        max_consumer_number=1,
        cpcrc=0xDEADBEEF,
        time_correction_connection_id=0xFFFFFFFF,
    )


def test_target_format_round_trip():
    seg = _make_target_segment()
    assert seg.wire_size == 56
    out = bytearray(seg.wire_size)
    n = seg.encode(out)
    assert n == 56
    assert out[0] == SEGMENT_TYPE
    assert out[1] == 0x1B  # 27 words

    parsed, consumed = parse_safety_segment(bytes(out))
    assert consumed == 56
    assert parsed.format == 0
    assert parsed.sccrc == seg.sccrc
    assert bytes(parsed.scts) == seg.scts
    assert parsed.time_correction_epi == seg.time_correction_epi
    assert parsed.tunid == seg.tunid
    assert parsed.ounid == seg.ounid
    assert parsed.ping_interval_multiplier == seg.ping_interval_multiplier
    assert parsed.cpcrc == seg.cpcrc


def test_extended_format_round_trip():
    seg = _make_target_segment()
    seg.format = 0x02
    seg.max_fault_number = 7
    seg.initial_time_stamp = 0x1234
    seg.initial_rollover_value = 0x5678

    assert seg.wire_size == 62
    out = bytearray(seg.wire_size)
    n = seg.encode(out)
    assert n == 62
    assert out[1] == 0x1E  # 30 words

    parsed, consumed = parse_safety_segment(bytes(out))
    assert consumed == 62
    assert parsed.format == 0x02
    assert parsed.max_fault_number == 7
    assert parsed.initial_time_stamp == 0x1234
    assert parsed.initial_rollover_value == 0x5678


def test_invalid_segment_type():
    with pytest.raises(ValueError):
        parse_safety_segment(b'\x60\x00\x00')  # 0x60 is not safety segment


def test_truncated_input():
    out = bytearray(_make_target_segment().wire_size)
    _make_target_segment().encode(out)
    with pytest.raises(ValueError):
        parse_safety_segment(bytes(out[:20]))  # truncated


def test_short_claimed_length_for_target_format_raises_format_error():
    """A safety segment whose own length field claims a size below the
    target format's minimum must raise SafetySegmentFormatError before
    the format-dependent unpacks fire. Prior behavior let unpack_from
    walk past the end of the buffer and raised a bare struct.error,
    which the generic encapsulation handler then surfaced as
    encapsulation-level INCORRECT_DATA instead of a safety-CIP error."""
    # 0x50 0x03 0x00 ..  -> format=Target (0x00), total=8 bytes.
    # Fully present on the wire but structurally impossible: Target
    # format needs 56 bytes.
    buf = bytes([SEGMENT_TYPE, 0x03, 0x00, 0x00, 0, 0, 0, 0])
    with pytest.raises(SafetySegmentFormatError):
        parse_safety_segment(buf)


def test_short_claimed_length_for_extended_format_raises_format_error():
    # Extended (0x02) needs 62 bytes; here we claim 8.
    buf = bytes([SEGMENT_TYPE, 0x03, 0x02, 0x00, 0, 0, 0, 0])
    with pytest.raises(SafetySegmentFormatError):
        parse_safety_segment(buf)


def test_unknown_format_byte_raises_format_error():
    # Any format byte we don't recognise is rejected up front.
    buf = bytes([SEGMENT_TYPE, 0x1B, 0x7F] + [0] * 53)
    with pytest.raises(SafetySegmentFormatError):
        parse_safety_segment(buf)


def test_safety_segment_format_error_is_value_error_subclass():
    # Existing callers that catch bare ValueError must still catch the
    # new exception.
    assert issubclass(SafetySegmentFormatError, ValueError)
