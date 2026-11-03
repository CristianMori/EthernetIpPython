"""Multiple Service Packet (0x0A) — batch multiple CIP requests."""

import asyncio
import struct
from ..cip.service import CipServiceRequest, CipServiceResponse
from ..cip.status import CipStatus
from ..cip import mr_codec
from ..cip.dispatcher import (
    MAX_SUBREQUEST_DEPTH,
    current_subrequest_depth,
    enter_subrequest,
    leave_subrequest,
)

SERVICE_CODE = 0x0A

# Service_Count is a UINT (up to 65535). Dispatching ~32k synchronous
# sub-requests per frame blocks the asyncio event loop for seconds and
# a peer can repeat it per connection; the sub-request-depth cap
# (fb8f9cf) only limits nesting, not breadth. pycomm3 batches at ~10,
# so 20 leaves ample headroom for legitimate scanners.
MAX_SERVICE_COUNT = 20


def _iter_multi_service(dispatch, request: CipServiceRequest):
    """Generator that executes the MSP body one sub-dispatch at a time.

    Yields once after each sub-dispatch so an async driver can hand the
    event loop back between calls. The aggregate CipServiceResponse is
    returned via StopIteration.value — early header errors return before
    any yield, so a sync driver that just drains next() still sees them.
    """
    if len(request.data) < 2:
        return CipServiceResponse.error(request.service_code, CipStatus.error(0x13))

    data = request.data
    service_count = struct.unpack_from('<H', data, 0)[0]

    # Reject the whole MSP if the peer asked for more sub-services than
    # we're willing to dispatch in one shot. 0x15 (TOO_MUCH_DATA) matches
    # the semantic — too many requests packed into one frame — and keeps
    # the response small enough to fit the error envelope.
    if service_count > MAX_SERVICE_COUNT:
        return CipServiceResponse.error(request.service_code, CipStatus.error(0x15))

    header_size = 2 + service_count * 2

    if len(data) < header_size:
        return CipServiceResponse.error(request.service_code, CipStatus.error(0x13))

    offsets = [struct.unpack_from('<H', data, 2 + i * 2)[0] for i in range(service_count)]

    # Process each sub-request and collect encoded responses
    encoded_responses: list[bytes] = []
    depth = current_subrequest_depth()
    for i in range(service_count):
        start = offsets[i]
        end = offsets[i + 1] if i + 1 < service_count else len(data)
        # Guard against bogus offsets. The previous code silently returned
        # an empty slice (and a benign 0x04 path-segment error) when the
        # offset ran past end-of-buffer or ran backwards; tighten this so
        # the response reflects a real decode failure instead of a
        # misleading success envelope.
        if start > len(data) or end > len(data) or end < start:
            result = None
            sub_data = b''
        else:
            sub_data = data[start:end]
            result = mr_codec.try_parse_request(sub_data)

        if result is None:
            resp = CipServiceResponse.error(0, CipStatus.error(0x04))
        else:
            svc, path, inner_data = result
            # Reject attacker-crafted nested Multiple_Service_Packet /
            # Unconnected_Send chains that would recurse without bound.
            # 0x20 (Invalid Parameter) is the closest CIP code — the
            # sub-request can't be dispatched because the gateway's
            # nesting budget is exhausted.
            if depth >= MAX_SUBREQUEST_DEPTH:
                resp = CipServiceResponse.error(svc, CipStatus.error(0x20))
            else:
                token = enter_subrequest()
                try:
                    resp = dispatch.dispatch(svc, path, inner_data)
                finally:
                    leave_subrequest(token)

        # Encode the response
        buf = bytearray(4096)
        n = resp.encode(buf)
        encoded_responses.append(bytes(buf[:n]))

        # Hand control back to the async driver (if any) so another
        # connection task can make progress even inside the breadth cap.
        yield

    # Build aggregate response
    resp_header_size = 2 + service_count * 2
    total_size = resp_header_size + sum(len(r) for r in encoded_responses)
    resp_buf = bytearray(total_size)

    struct.pack_into('<H', resp_buf, 0, service_count)
    resp_offset = resp_header_size
    for i, encoded in enumerate(encoded_responses):
        struct.pack_into('<H', resp_buf, 2 + i * 2, resp_offset)
        resp_buf[resp_offset:resp_offset + len(encoded)] = encoded
        resp_offset += len(encoded)

    return CipServiceResponse.success(request.service_code, bytes(resp_buf))


def handle_multi_service(dispatch, request: CipServiceRequest) -> CipServiceResponse:
    """Sync driver — processes every sub-dispatch back-to-back.

    Retained so the CipServiceDefinition registered on the Message Router
    stays a plain callable; the service-dispatch chain is synchronous and
    making it async would ripple into every class handler.
    """
    gen = _iter_multi_service(dispatch, request)
    try:
        while True:
            next(gen)
    except StopIteration as stop:
        return stop.value


async def handle_multi_service_async(
        dispatch, request: CipServiceRequest) -> CipServiceResponse:
    """Async driver — awaits ``asyncio.sleep(0)`` between each sub-dispatch.

    The breadth cap (MAX_SERVICE_COUNT) already bounds how long a single
    MSP can monopolise the event loop, but a 20-call burst of synchronous
    tag reads still starves peer connections for the duration. Yielding
    between sub-dispatches lets concurrent clients interleave requests
    without raising the cap. Callers reach this path through
    ``CipDispatcher.dispatch_async`` so non-MSP services keep running
    through the plain sync dispatch.
    """
    gen = _iter_multi_service(dispatch, request)
    try:
        while True:
            next(gen)
            await asyncio.sleep(0)
    except StopIteration as stop:
        return stop.value
