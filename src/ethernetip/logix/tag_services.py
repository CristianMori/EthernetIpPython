"""CIP service handlers for Logix tag operations."""

import struct

from ..cip.service import CipServiceResponse
from ..cip.status import CipStatus
from . import data_types as dt
from .tag import Tag
from .walker import WalkResult

READ_TAG = 0x4C
WRITE_TAG = 0x4D
READ_MODIFY_WRITE = 0x4E
READ_TAG_FRAGMENTED = 0x52
WRITE_TAG_FRAGMENTED = 0x53

MAX_REPLY_DATA = 480

# Structure tag marker on the wire. CIP Vol 1 §C-4.4.5: a Read_Tag reply for
# a structured tag leads with [A0 02][structure_handle (UINT)] followed by
# the raw structure bytes; a Write_Tag request uses the same prefix ahead of
# element_count and the data. Atomic tags carry only the 2-byte type code.
STRUCT_TYPE_INDICATOR = 0x02A0


def _is_struct_tag(tag: Tag) -> bool:
    return dt.is_struct(tag.symbol_type)


def handle_read_tag(tag: Tag, service_code: int, data: bytes,
                    element_offset: int = 0) -> CipServiceResponse:
    if len(data) < 2:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))

    element_count = struct.unpack_from('<H', data, 0)[0]
    byte_offset = element_offset * tag.element_size
    bytes_to_read = element_count * tag.element_size

    if byte_offset + bytes_to_read > tag.data_size:
        return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2105))

    prefix_len = 4 if _is_struct_tag(tag) else 2
    if prefix_len + bytes_to_read > MAX_REPLY_DATA:
        fit = MAX_REPLY_DATA - prefix_len
        return _build_read_response(tag, service_code, byte_offset, fit, partial=True)

    return _build_read_response(tag, service_code, byte_offset, bytes_to_read, partial=False)


def handle_write_tag(tag: Tag, service_code: int, data: bytes,
                     element_offset: int = 0) -> CipServiceResponse:
    if len(data) < 4:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))

    tag_type = struct.unpack_from('<H', data, 0)[0]

    if _is_struct_tag(tag):
        if len(data) < 6:
            return CipServiceResponse.error(service_code, CipStatus.error(0x13))
        struct_handle = struct.unpack_from('<H', data, 2)[0]
        element_count = struct.unpack_from('<H', data, 4)[0]
        header_len = 6
        if tag_type != STRUCT_TYPE_INDICATOR or struct_handle != tag.tag_type:
            return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2107))
    else:
        element_count = struct.unpack_from('<H', data, 2)[0]
        header_len = 4
        if tag_type != tag.tag_type:
            return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2107))

    byte_offset = element_offset * tag.element_size
    bytes_to_write = element_count * tag.element_size
    if len(data) < header_len + bytes_to_write:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))

    if byte_offset + bytes_to_write > tag.data_size:
        return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2105))

    tag.set_data(data[header_len:header_len + bytes_to_write], byte_offset)
    return CipServiceResponse.success(service_code)


def handle_read_tag_fragmented(tag: Tag, service_code: int, data: bytes) -> CipServiceResponse:
    if len(data) < 6:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))

    element_count = struct.unpack_from('<H', data, 0)[0]
    byte_offset = struct.unpack_from('<I', data, 2)[0]

    total = element_count * tag.element_size
    if byte_offset >= total:
        return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2105))

    prefix_len = 4 if _is_struct_tag(tag) else 2
    remaining = total - byte_offset
    chunk = min(remaining, MAX_REPLY_DATA - prefix_len)
    more = byte_offset + chunk < total

    return _build_read_response(tag, service_code, byte_offset, chunk, partial=more)


def handle_write_tag_fragmented(tag: Tag, service_code: int, data: bytes) -> CipServiceResponse:
    if len(data) < 8:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))

    tag_type = struct.unpack_from('<H', data, 0)[0]

    if _is_struct_tag(tag):
        # Struct fragmented write: [0x02A0][struct_handle][count][offset][data...]
        if len(data) < 10:
            return CipServiceResponse.error(service_code, CipStatus.error(0x13))
        struct_handle = struct.unpack_from('<H', data, 2)[0]
        _element_count = struct.unpack_from('<H', data, 4)[0]
        byte_offset = struct.unpack_from('<I', data, 6)[0]
        header_len = 10
        if tag_type != STRUCT_TYPE_INDICATOR or struct_handle != tag.tag_type:
            return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2107))
    else:
        _element_count = struct.unpack_from('<H', data, 2)[0]
        byte_offset = struct.unpack_from('<I', data, 4)[0]
        header_len = 8
        if tag_type != tag.tag_type:
            return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2107))

    write_data = data[header_len:]
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
                          length: int, partial: bool,
                          type_code: int | None = None,
                          as_struct: bool | None = None,
                          struct_handle: int | None = None) -> CipServiceResponse:
    """Build a Read_Tag reply.

    Whole-tag callers leave type_code/as_struct unset; the helper derives the
    shape from the tag itself (struct ⇒ 4-byte prefix with tag.tag_type as
    the structure handle; atomic ⇒ 2-byte type code).

    Walker-aware callers pass as_struct explicitly: struct_handle for struct
    members (from walked.template.struct_handle), type_code for atomic.
    """
    if as_struct is None:
        as_struct = _is_struct_tag(tag)
        if as_struct and struct_handle is None:
            struct_handle = tag.tag_type

    if as_struct:
        resp = bytearray(4 + length)
        struct.pack_into('<H', resp, 0, STRUCT_TYPE_INDICATOR)
        struct.pack_into('<H', resp, 2, struct_handle or 0)
        resp[4:] = tag.get_data(offset, length)
    else:
        tc = tag.tag_type if type_code is None else type_code
        resp = bytearray(2 + length)
        struct.pack_into('<H', resp, 0, tc)
        resp[2:] = tag.get_data(offset, length)

    if partial:
        return CipServiceResponse(
            service_code=service_code | 0x80,
            status=CipStatus.error(0x06),
            data=bytes(resp),
        )
    return CipServiceResponse.success(service_code, bytes(resp))


# --- Walker-aware variants (gaps 2, 5, 6) ---

def handle_read_tag_at(tag: Tag, service_code: int, data: bytes,
                       walked: WalkResult) -> CipServiceResponse:
    if len(data) < 2:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))
    element_count = struct.unpack_from('<H', data, 0)[0]

    # BOOL bit read: single-byte 0x01 / 0x00 reply.
    if walked.bit_pos is not None:
        if element_count != 1:
            return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2105))
        host = tag.get_data(walked.offset, 1)[0]
        bit = (host >> walked.bit_pos) & 0x01
        reply = struct.pack('<H', dt.BOOL) + bytes([bit])
        return CipServiceResponse.success(service_code, reply)

    bytes_to_read = element_count * walked.element_size
    if walked.offset + bytes_to_read > tag.data_size:
        return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2105))

    # Walker that ends on a nested struct member carries a non-None template;
    # the structure handle is on the template.
    as_struct = walked.template is not None
    prefix_len = 4 if as_struct else 2
    handle = walked.template.struct_handle if as_struct else None

    if prefix_len + bytes_to_read > MAX_REPLY_DATA:
        fit = MAX_REPLY_DATA - prefix_len
        return _build_read_response(tag, service_code, walked.offset, fit,
                                    partial=True, type_code=walked.type_code,
                                    as_struct=as_struct, struct_handle=handle)
    return _build_read_response(tag, service_code, walked.offset, bytes_to_read,
                                partial=False, type_code=walked.type_code,
                                as_struct=as_struct, struct_handle=handle)


def handle_write_tag_at(tag: Tag, service_code: int, data: bytes,
                        walked: WalkResult) -> CipServiceResponse:
    if len(data) < 4:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))
    tag_type = struct.unpack_from('<H', data, 0)[0]

    as_struct = walked.template is not None

    if as_struct:
        if len(data) < 6:
            return CipServiceResponse.error(service_code, CipStatus.error(0x13))
        struct_handle = struct.unpack_from('<H', data, 2)[0]
        element_count = struct.unpack_from('<H', data, 4)[0]
        header_len = 6
        if tag_type != STRUCT_TYPE_INDICATOR or struct_handle != walked.template.struct_handle:
            return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2107))
    else:
        element_count = struct.unpack_from('<H', data, 2)[0]
        header_len = 4
        if tag_type != walked.type_code:
            return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2107))

    # BOOL bit write: read 1 byte from payload, RMW via atomic_set_bit.
    if walked.bit_pos is not None:
        if element_count != 1 or len(data) < header_len + 1:
            return CipServiceResponse.error(service_code, CipStatus.error(0x13))
        new_value = (data[header_len] & 0x01) != 0
        tag.atomic_set_bit(walked.offset, walked.bit_pos, new_value)
        return CipServiceResponse.success(service_code)

    bytes_to_write = element_count * walked.element_size
    if len(data) < header_len + bytes_to_write:
        return CipServiceResponse.error(service_code, CipStatus.error(0x13))
    if walked.offset + bytes_to_write > tag.data_size:
        return CipServiceResponse.error(service_code, CipStatus.error(0xFF, 0x2105))

    tag.set_data(data[header_len:header_len + bytes_to_write], walked.offset)
    return CipServiceResponse.success(service_code)
