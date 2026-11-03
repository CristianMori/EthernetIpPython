"""CIP dispatcher — routes requests through the CIP class/instance/service tree."""

from __future__ import annotations
import contextvars
from typing import Protocol, runtime_checkable

from .cip_class import CipClass
from .path import CipPath
from .service import CipServiceRequest, CipServiceResponse
from .status import CipStatus, PATH_DESTINATION_UNKNOWN, OBJECT_DOES_NOT_EXIST, SERVICE_NOT_SUPPORTED


# Guards server-side request dispatch against malicious nesting of
# Multiple_Service_Packet / Unconnected_Send. A benign request has depth 0;
# one legitimate layer of nesting is depth 1. Real clients never go deeper,
# but an attacker-crafted request can recurse without bound and raise
# RecursionError, killing the connection task (effectively a DoS). Both
# sub-dispatch call sites check this before re-entering dispatch.
MAX_SUBREQUEST_DEPTH = 3

_subrequest_depth: contextvars.ContextVar[int] = contextvars.ContextVar(
    '_cip_subrequest_depth', default=0)


def current_subrequest_depth() -> int:
    return _subrequest_depth.get()


def enter_subrequest():
    """Context-manager-ish helper: returns a token to pass back to reset()."""
    return _subrequest_depth.set(_subrequest_depth.get() + 1)


def leave_subrequest(token) -> None:
    _subrequest_depth.reset(token)


@runtime_checkable
class CipDispatch(Protocol):
    """Protocol for CIP request dispatching — implemented by both adapter and scanner sides."""
    def dispatch(self, service_code: int, path: CipPath, data: bytes) -> CipServiceResponse: ...


class CipDispatcher:
    """Routes CIP requests through the class/instance/service tree.

    If path has no class_id (e.g. symbolic segment), calls on_unhandled()
    which subclasses can override (e.g. LogixDispatcher for symbolic tags).
    """

    def __init__(self):
        self._classes: dict[int, CipClass] = {}

    def register_class(self, cip_class: CipClass) -> None:
        self._classes[cip_class.class_code] = cip_class

    def get_class(self, class_code: int) -> CipClass | None:
        return self._classes.get(class_code)

    @property
    def registered_classes(self) -> dict[int, CipClass]:
        return self._classes

    async def dispatch_async(self, service_code: int, path: CipPath,
                             data: bytes) -> CipServiceResponse:
        """Async entry point for the TCP server. The base implementation
        just defers to the sync dispatch so every non-MSP service keeps
        its existing synchronous handler. Multiple_Service_Packet (0x0A)
        reaches the yielding driver here so a well-formed batch at the
        MAX_SERVICE_COUNT cap doesn't block concurrent peers while the
        gateway chews through 20 synchronous sub-dispatches. Any other
        service — including MSP on an unregistered path — falls through
        to the sync path, where the normal service-table lookup produces
        the right error."""
        if service_code == 0x0A:
            cip_class = self._classes.get(path.class_id) if path.class_id is not None else None
            instance_id = path.instance_id if path.instance_id is not None else 0
            if cip_class is not None and cip_class.get_service(0x0A, instance_id == 0) is not None \
                    and cip_class.get_instance(instance_id) is not None:
                from ..logix.multi_service import handle_multi_service_async
                request = CipServiceRequest(
                    service_code=service_code, path=path, data=data)
                return await handle_multi_service_async(self, request)
        return self.dispatch(service_code, path, data)

    def dispatch(self, service_code: int, path: CipPath, data: bytes) -> CipServiceResponse:
        # No class in path — delegate to subclass (symbolic tag dispatch).
        if path.class_id is None:
            return self.on_unhandled(service_code, path, data, PATH_DESTINATION_UNKNOWN)

        cip_class = self._classes.get(path.class_id)
        if cip_class is None:
            return self.on_unhandled(service_code, path, data, PATH_DESTINATION_UNKNOWN)

        instance_id = path.instance_id if path.instance_id is not None else 0
        is_class_level = instance_id == 0

        instance = cip_class.get_instance(instance_id)
        if instance is None:
            return self.on_unhandled(service_code, path, data, OBJECT_DOES_NOT_EXIST)

        service = cip_class.get_service(service_code, is_class_level)
        if service is None:
            return self.on_unhandled(service_code, path, data, SERVICE_NOT_SUPPORTED)

        request = CipServiceRequest(
            service_code=service_code,
            path=path,
            data=data,
        )
        return service.handler(instance, request)

    def on_unhandled(self, service_code: int, path: CipPath, data: bytes,
                     default_status: int = PATH_DESTINATION_UNKNOWN) -> CipServiceResponse:
        """Called when a request cannot be resolved through the standard class /
        instance / service routing. Override in subclasses to provide custom
        routing (e.g. symbolic tag dispatch, logging echo servers).

        `default_status` is the CIP error code the dispatcher would have
        returned for this failure — the default implementation returns it
        unchanged, so callers that don't override see no behavior change.
        """
        return CipServiceResponse.error(service_code, CipStatus.error(default_status))
