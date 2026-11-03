"""Multiple_Service_Packet async driver must yield between sub-dispatches.

The breadth cap keeps a batch bounded, but 20 synchronous tag reads
still starve concurrent connections while the gateway chews through
them. ``handle_multi_service_async`` is expected to hand the event
loop back after every sub-dispatch so another coroutine can make
progress inside the batch — this test proves that invariant.
"""

from __future__ import annotations

import asyncio
import struct

from ethernetip.cip.path import CipPath
from ethernetip.cip.service import CipServiceRequest
from ethernetip.logix import data_types as dt
from ethernetip.logix.logix_dispatcher import LogixDispatcher
from ethernetip.logix.multi_service import (
    MAX_SERVICE_COUNT,
    SERVICE_CODE as MULTI_SVC,
    handle_multi_service_async,
)
from ethernetip.logix.tag_database import TagDatabase


def _symbolic_path(name: str) -> bytes:
    name_bytes = name.encode('ascii')
    path = bytearray([0x91, len(name_bytes)])
    path += name_bytes
    if len(name_bytes) % 2 != 0:
        path += b'\x00'
    return bytes(path)


def _build_msp_payload(sub_requests: list[bytes]) -> bytes:
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


def _dispatcher() -> LogixDispatcher:
    tags = TagDatabase()
    tags.add_tag("ADint", dt.DINT)
    return LogixDispatcher(tags)


async def test_async_batch_yields_between_sub_dispatches():
    dispatcher = _dispatcher()
    body = _build_msp_payload([_read_sub()] * MAX_SERVICE_COUNT)
    req = CipServiceRequest(MULTI_SVC, CipPath(class_id=0x02, instance_id=1), body)

    # Count how many times a sibling coroutine runs during the batch.
    # A sync driver would starve this task until the whole batch finishes,
    # so ticks would still be 0 or 1 by the time the MSP returns.
    ticks = 0

    async def watcher() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0)
            ticks += 1

    watcher_task = asyncio.create_task(watcher())
    # Hand the watcher one scheduling slot before the batch starts so
    # the first increment isn't mistaken for a yield inside the batch.
    await asyncio.sleep(0)
    baseline = ticks

    resp = await handle_multi_service_async(dispatcher, req)

    watcher_task.cancel()
    try:
        await watcher_task
    except asyncio.CancelledError:
        pass

    assert resp.status.is_success
    assert struct.unpack_from('<H', resp.data, 0)[0] == MAX_SERVICE_COUNT

    # Each sub-dispatch yields once; the watcher must tick at least
    # MAX_SERVICE_COUNT times above its pre-batch baseline.
    assert ticks - baseline >= MAX_SERVICE_COUNT, \
        f"watcher only ticked {ticks - baseline} times during a batch of {MAX_SERVICE_COUNT}"


async def test_async_driver_matches_sync_result():
    """Refactor must not change the aggregate response — compare bytes."""
    from ethernetip.logix.multi_service import handle_multi_service

    dispatcher = _dispatcher()
    body = _build_msp_payload([_read_sub()] * 5)
    req = CipServiceRequest(MULTI_SVC, CipPath(class_id=0x02, instance_id=1), body)

    sync_resp = handle_multi_service(dispatcher, req)
    async_resp = await handle_multi_service_async(dispatcher, req)

    assert sync_resp.status.general_status == async_resp.status.general_status
    assert sync_resp.data == async_resp.data


async def test_async_driver_rejects_breadth_overflow():
    """Early header-level rejection must still fire through the async driver."""
    dispatcher = _dispatcher()
    body = struct.pack('<H', 0xFFFF)
    req = CipServiceRequest(MULTI_SVC, CipPath(class_id=0x02, instance_id=1), body)
    resp = await handle_multi_service_async(dispatcher, req)
    assert not resp.status.is_success
    assert resp.status.general_status == 0x15
