"""Tests for Message Router codec."""

from ethernetip.cip.mr_codec import try_parse_request, try_parse_response, encode_request
from ethernetip.cip.path import CipPath


def test_parse_request():
    # Service 0x0E, path: class 0x01, instance 1, attr 7 (3 words = 6 bytes)
    path_bytes = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x07])
    mr = bytes([0x0E, 0x03]) + path_bytes  # svc + pathWords=3 + path
    result = try_parse_request(mr)
    assert result is not None
    svc, path, data = result
    assert svc == 0x0E
    assert path.class_id == 0x01
    assert path.instance_id == 1
    assert path.attribute_id == 7
    assert data == b''


def test_parse_request_with_data():
    path_bytes = bytes([0x20, 0x04, 0x24, 0x01])
    service_data = b'\xAA\xBB\xCC'
    mr = bytes([0x4D, 0x02]) + path_bytes + service_data
    result = try_parse_request(mr)
    assert result is not None
    svc, path, data = result
    assert svc == 0x4D
    assert data == b'\xAA\xBB\xCC'


def test_parse_request_too_short():
    assert try_parse_request(b'') is None
    assert try_parse_request(b'\x0E') is None


def test_parse_response_success():
    # Reply service 0x8E, reserved, general_status=0, add_size=0, data=0x01 0x02
    mr = bytes([0x8E, 0x00, 0x00, 0x00, 0x01, 0x02])
    result = try_parse_response(mr)
    assert result is not None
    reply_svc, status, data = result
    assert reply_svc == 0x8E
    assert status.is_success
    assert data == b'\x01\x02'


def test_parse_response_error_with_additional():
    # Reply 0xCC, reserved, general=0x08, add_size=1, add_status=0x1234
    mr = bytes([0xCC, 0x00, 0x08, 0x01, 0x34, 0x12])
    result = try_parse_response(mr)
    assert result is not None
    reply_svc, status, data = result
    assert reply_svc == 0xCC
    assert status.general_status == 0x08
    assert status.additional_status == (0x1234,)
    assert data == b''


def test_encode_request():
    path_bytes = bytes([0x20, 0x01, 0x24, 0x01])
    encoded = encode_request(0x0E, path_bytes, b'\xFF')
    assert encoded[0] == 0x0E
    assert encoded[1] == 2  # path size in words
    assert encoded[2:6] == path_bytes
    assert encoded[6] == 0xFF
