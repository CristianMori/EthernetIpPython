"""CatchAllDispatcher — CipDispatcher subclass with a callback-based fall-through.

Use when you want a single handler for every request that doesn't match a
registered class (echo servers, sniffers, generic adapters) without
subclassing CipDispatcher.

    disp = CatchAllDispatcher()
    def my_handler(req: CatchAllRequest) -> CatchAllReply:
        log(req)
        return CatchAllReply(data=bytes(20))   # empty bytes = no payload
    disp.set_handler(my_handler)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .dispatcher import CipDispatcher
from .path import CipPath
from .service import CipServiceResponse
from .status import CipStatus, PATH_DESTINATION_UNKNOWN


@dataclass
class CatchAllRequest:
    """View of an incoming CIP request that didn't match any registered class."""
    service_code: int
    path: CipPath
    data: bytes


@dataclass
class CatchAllReply:
    """What a CatchAllDispatcher handler returns.

    `data` empty → reply with no payload. `status` non-zero → CIP error
    response with that general status.
    """
    data: bytes = b''
    status: int = 0


Handler = Callable[[CatchAllRequest], CatchAllReply]


class CatchAllDispatcher(CipDispatcher):
    """CipDispatcher that routes every unhandled request through a handler.

    Classes registered via register_class() still go through the standard
    class → instance → service routing; only requests that fall through to
    on_unhandled hit the handler.
    """

    def __init__(self) -> None:
        super().__init__()
        self._handler: Handler | None = None

    def set_handler(self, h: Handler) -> None:
        """Install (or replace) the catch-all handler. Without a handler the
        dispatcher behaves like the base CipDispatcher and returns the
        would-have-been error status."""
        self._handler = h

    def on_unhandled(self, service_code: int, path: CipPath, data: bytes,
                     default_status: int = PATH_DESTINATION_UNKNOWN) -> CipServiceResponse:
        if self._handler is None:
            return super().on_unhandled(service_code, path, data, default_status)
        req = CatchAllRequest(service_code=service_code, path=path, data=data)
        reply = self._handler(req)
        if reply.status != 0:
            return CipServiceResponse.error(service_code, CipStatus.error(reply.status))
        return CipServiceResponse.success(service_code, reply.data)
