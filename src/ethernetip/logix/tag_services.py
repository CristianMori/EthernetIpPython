"""CIP service handlers for Logix tag operations."""

import struct

from ..cip.service import CipServiceResponse
from ..cip.status import CipStatus
from .tag import Tag

READ_TAG = 0x4C
WRITE_TAG = 0x4D
READ_MODIFY_WRITE = 0x4E
READ_TAG_FRAGMENTED = 0x52
WRITE_TAG_FRAGMENTED = 0x53

MAX_REPLY_DATA = 480


def handle_read_tag(tag: Tag, service_code: int, data: bytes,
                    element_offset: int = 0) -> CipServiceResponse:
    if len(data) < 2:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))

    element_count = struct.unpack_from('<H', data, 0)[0]
    byte_offset = element_offset * tag.element_size
    bytes_to_read = element_count * tag.element_size

    if byte_offset + bytes_to_read > tag.data_size:
        return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2105))

    if 2 + bytes_to_read > MAX_REPLY_DATA:
        fit = MAX_REPLY_DATA - 2
        return _build_read_response(tag, service_code, byte_offset, fit, partial=True)

    return _build_read_response(tag, service_code, byte_offset, bytes_to_read, partial=False)


def handle_write_tag(tag: Tag, service_code: int, data: bytes,
                     element_offset: int = 0) -> CipServiceResponse:
    if len(data) < 4:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))

    tag_type = struct.unpack_from('<H', data, 0)[0]
    element_count = struct.unpack_from('<H', data, 2)[0]

    # For structures, Write Tag sends TWO type words: 0x02A0 + struct_handle
    # The tag_type check needs to handle this
    if tag_type == 0x02A0:
        # Structure write — next 2 bytes are struct handle
        if len(data) < 6:
            return CipServiceResponse.error(service_code, CipStatus.error(0x13))
        struct_handle = struct.unpack_from('<H', data, 2)[0]
        element_count = struct.unpack_from('<H', data, 4)[0]
        if struct_handle != tag.tag_type:
            return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2107))
        write_data = data[6:]
    else:
        if tag_type != tag.tag_type:
            return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2107))
        write_data = data[4:]

    byte_offset = element_offset * tag.element_size
    bytes_to_write = element_count * tag.element_size
    if len(write_data) < bytes_to_write:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))

    if byte_offset + bytes_to_write > tag.data_size:
        return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2105))

    tag.set_data(write_data[:bytes_to_write], byte_offset)
    return CipServiceResponse.success(service_code)


def handle_read_tag_fragmented(tag: Tag, service_code: int, data: bytes) -> CipServiceResponse:
    if len(data) < 6:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))

    element_count = struct.unpack_from('<H', data, 0)[0]
    byte_offset = struct.unpack_from('<I', data, 2)[0]

    total = element_count * tag.element_size
    if byte_offset >= total:
        return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2105))

    remaining = total - byte_offset
    chunk = min(remaining, MAX_REPLY_DATA - 2)
    more = byte_offset + chunk < total

    return _build_read_response(tag, service_code, byte_offset, chunk, partial=more)


def handle_write_tag_fragmented(tag: Tag, service_code: int, data: bytes) -> CipServiceResponse:
    if len(data) < 8:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))

    tag_type = struct.unpack_from('<H', data, 0)[0]
    element_count = struct.unpack_from('<H', data, 2)[0]
    byte_offset = struct.unpack_from('<I', data, 4)[0]

    if tag_type != tag.tag_type:
        return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2107))

    write_data = data[8:]
    tag.set_data(write_data, byte_offset)
    return CipServiceResponse.success(service_code)


def handle_read_modify_write(tag: Tag, service_code: int, data: bytes) -> CipServiceResponse:
    if len(data) < 2:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))

    mask_size = struct.unpack_from('<H', data, 0)[0]
    if len(data) < 2 + mask_size * 2:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))

    or_mask = data[2:2 + mask_size]
    and_mask = data[2 + mask_size:2 + mask_size * 2]

    n = min(mask_size, tag.data_size)
    current = bytearray(tag.get_data(0, n))
    for i in range(n):
        current[i] = (current[i] | or_mask[i]) & and_mask[i]
    tag.set_data(current)
    return CipServiceResponse.success(service_code)


def _build_read_response(tag: Tag, service_code: int, offset: int,
                          length: int, partial: bool) -> CipServiceResponse:
    resp = bytearray(2 + length)
    struct.pack_into('<H', resp, 0, tag.tag_type)
    resp[2:] = tag.get_data(offset, length)

    if partial:
        return CipServiceResponse(
            service_code=service_code | 0x80,
            status=CipStatus.error(0x06),
            data=bytes(resp),
        )
    return CipServiceResponse.success(service_code, bytes(resp))
