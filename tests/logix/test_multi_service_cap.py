"""Multiple_Service_Packet (0x0A) must refuse an unbounded Service_Count.

Service_Count is a UINT (up to 65535). Dispatching ~32k sub-requests
synchronously stalls the asyncio event loop; a hostile peer could
repeat that per connection. The depth cap added in fb8f9cf only
limits recursion, not breadth.
"""

from __future__ import annotations

import struct

from ethernetip.cip.service import CipServiceRequest
from ethernetip.cip.status import CipStatus
from ethernetip.cip.path import CipPath
from ethernetip.logix import data_types as dt
from ethernetip.logix.logix_dispatcher import LogixDispatcher
from ethernetip.logix.multi_service import (
    MAX_SERVICE_COUNT,
    SERVICE_CODE as MULTI_SVC,
    handle_multi_service,
)
from ethernetip.logix.tag_database import TagDatabase


def _dispatcher() -> LogixDispatcher:
    tags = TagDatabase()
    tags.add_tag("ADint", dt.DINT)
    return LogixDispatcher(tags)


def _symbolic_path(name: str) -> bytes:
    name_bytes = name.encode('ascii')
    path = bytearray([0x91, len(name_bytes)])
    path += name_bytes
    if len(name_bytes) % 2 != 0:
        path += b'\x00'
    return bytes(path)


def _build_msp_payload(sub_requests: list[bytes]) -> bytes:
    """Build an MSP body for N sub-requests."""
    n = len(sub_requests)
    header_size = 2 + n * 2
    offsets = []
    cursor = header_size
    body = bytearray()
    for sub in sub_requests:
        offsets.append(cursor)
        body.extend(sub)
        cursor += len(sub)
    out = bytearray(header_size + len(body))
    struct.pack_into('<H', out, 0, n)
    for i, off in enumerate(offsets):
        struct.pack_into('<H', out, 2 + i * 2, off)
    out[header_size:] = body
    return bytes(out)


def _read_sub() -> bytes:
    sym = _symbolic_path("ADint")
    return bytes([0x4C, len(sym) // 2]) + sym + struct.pack('<H', 1)


def test_service_count_at_cap_succeeds():
    dispatcher = _dispatcher()
    body = _build_msp_payload([_read_sub()] * MAX_SERVICE_COUNT)
    req = CipServiceRequest(MULTI_SVC, CipPath(class_id=0x02, instance_id=1), body)
    resp = handle_multi_service(dispatcher, req)
    assert resp.status.is_success
    assert struct.unpack_from('<H', resp.data, 0)[0] == MAX_SERVICE_COUNT


def test_service_count_above_cap_rejected():
    dispatcher = _dispatcher()
    # Only fabricate a header: a hostile peer wouldn't bother wiring 100
    # real sub-request bodies, and the handler should reject purely on
    # the Service_Count field.
    body = struct.pack('<H', 100) + b'\x00' * 200
    req = CipServiceRequest(MULTI_SVC, CipPath(class_id=0x02, instance_id=1), body)
    resp = handle_multi_service(dispatcher, req)
    assert not resp.status.is_success
    assert resp.status.general_status == 0x15   # TOO_MUCH_DATA


def test_service_count_at_uint_max_rejected():
    dispatcher = _dispatcher()
    body = struct.pack('<H', 0xFFFF)
    req = CipServiceRequest(MULTI_SVC, CipPath(class_id=0x02, instance_id=1), body)
    resp = handle_multi_service(dispatcher, req)
    assert not resp.status.is_success
    assert resp.status.general_status == 0x15


def test_out_of_range_offset_returns_decode_error():
    dispatcher = _dispatcher()
    # Service_Count=1 but the only offset points past end-of-buffer.
    body = struct.pack('<HH', 1, 999)
    req = CipServiceRequest(MULTI_SVC, CipPath(class_id=0x02, instance_id=1), body)
    resp = handle_multi_service(dispatcher, req)
    # The envelope succeeds, but the single sub-response carries 0x04.
    assert resp.status.is_success
    sub_offset = struct.unpack_from('<H', resp.data, 2)[0]
    sub_status = resp.data[sub_offset + 2]
    assert sub_status == 0x04
