"""Message Router codec — CIP request/response wire format encoding and decoding."""

from __future__ import annotations
import struct

from .path import CipPath
from .status import CipStatus


def try_parse_request(mr_data: bytes | bytearray | memoryview
                      ) -> tuple[int, CipPath, bytes] | None:
    """Parse an MR request. Returns (service_code, path, data) or None if invalid."""
    if len(mr_data) < 2:
        return None

    service_code = mr_data[0]
    path_size_words = mr_data[1]
    path_size_bytes = path_size_words * 2

    if len(mr_data) < 2 + path_size_bytes:
        return None

    path, _ = CipPath.parse(mr_data[2:2 + path_size_bytes])
    data = bytes(mr_data[2 + path_size_bytes:])
    return service_code, path, data


def parse_request(mr_data: bytes | bytearray | memoryview
                  ) -> tuple[int, CipPath, bytes]:
    """Parse an MR request. Returns (service_code, path, data). Raises on invalid data."""
    result = try_parse_request(mr_data)
    if result is None:
        raise ValueError("Invalid MR request data")
    return result


def try_parse_response(mr_data: bytes | bytearray | memoryview
                       ) -> tuple[int, CipStatus, bytes] | None:
    """Parse an MR response. Returns (reply_service, status, data) or None if invalid.

    Wire format: reply_service(1) + reserved(1) + general_status(1) + add_size(1) + add_status(N*2) + data
    """
    if len(mr_data) < 4:
        return None

    reply_service = mr_data[0]
    general_status = mr_data[2]
    add_status_size = mr_data[3]
    add_status_bytes = add_status_size * 2

    if len(mr_data) < 4 + add_status_bytes:
        return None

    additional = tuple(
        struct.unpack_from('<H', mr_data, 4 + i * 2)[0]
        for i in range(add_status_size)
    )

    status = CipStatus(general_status=general_status, additional_status=additional)
    data_offset = 4 + add_status_bytes
    data = bytes(mr_data[data_offset:]) if len(mr_data) > data_offset else b''

    return reply_service, status, data


def encode_request(service_code: int, path_bytes: bytes, data: bytes = b'') -> bytes:
    """Encode an MR request to wire format."""
    path_size_words = len(path_bytes) // 2
    buf = bytearray(2 + len(path_bytes) + len(data))
    buf[0] = service_code
    buf[1] = path_size_words
    buf[2:2 + len(path_bytes)] = path_bytes
    buf[2 + len(path_bytes):] = data
    return bytes(buf)
