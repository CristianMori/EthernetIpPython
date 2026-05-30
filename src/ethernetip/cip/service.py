"""CIP service request/response structures and handler types."""

from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from .path import CipPath
from .status import CipStatus, SUCCESS

if TYPE_CHECKING:
    from .instance import CipInstance


@dataclass(frozen=True)
class CipServiceRequest:
    service_code: int
    path: CipPath
    data: bytes = b''


@dataclass(frozen=True)
class CipServiceResponse:
    service_code: int  # reply service (original | 0x80)
    status: CipStatus = field(default_factory=lambda: SUCCESS)
    data: bytes = b''

    @staticmethod
    def success(service_code: int, data: bytes = b'') -> CipServiceResponse:
        return CipServiceResponse(
            service_code=service_code | 0x80,
            status=SUCCESS,
            data=data,
        )

    @staticmethod
    def error(service_code: int, status: CipStatus) -> CipServiceResponse:
        return CipServiceResponse(
            service_code=service_code | 0x80,
            status=status,
        )

    def encode(self, dst: bytearray, offset: int = 0) -> int:
        """Encode to MR response wire format. Returns bytes written."""
        pos = offset
        dst[pos] = self.service_code
        pos += 1
        dst[pos] = 0  # reserved
        pos += 1
        pos += self.status.encode(dst, pos)
        if self.data:
            dst[pos:pos + len(self.data)] = self.data
            pos += len(self.data)
        return pos - offset


# Type alias for service handler functions
CipServiceHandler = Callable[['CipInstance', CipServiceRequest], CipServiceResponse]


class CipServiceDefinition:
    """Binds a service code and name to a handler function."""

    def __init__(self, service_code: int, name: str, handler: CipServiceHandler):
        self.service_code = service_code
        self.name = name
        self.handler = handler
