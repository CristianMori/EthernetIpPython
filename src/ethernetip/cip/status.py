"""CIP service response status — general status byte plus optional additional status words."""

from __future__ import annotations
import struct
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CipStatus:
    general_status: int = 0
    additional_status: tuple[int, ...] = ()

    @property
    def is_success(self) -> bool:
        return self.general_status == 0

    def encode(self, dst: bytearray, offset: int = 0) -> int:
        """Encode to wire: general_status(1) + add_size(1) + add_status(N*2). Returns bytes written."""
        dst[offset] = self.general_status
        dst[offset + 1] = len(self.additional_status)
        pos = offset + 2
        for s in self.additional_status:
            struct.pack_into('<H', dst, pos, s)
            pos += 2
        return pos - offset

    @staticmethod
    def error(general: int, *additional: int) -> CipStatus:
        return CipStatus(general_status=general, additional_status=tuple(additional))


# Pre-built success status
SUCCESS = CipStatus()

# Common CIP general status codes
PATH_SEGMENT_ERROR = 0x04
PATH_DESTINATION_UNKNOWN = 0x05
SERVICE_NOT_SUPPORTED = 0x08
INVALID_ATTRIBUTE_VALUE = 0x09
ATTRIBUTE_NOT_SETTABLE = 0x0E
NOT_ENOUGH_DATA = 0x13
ATTRIBUTE_NOT_SUPPORTED = 0x14
TOO_MUCH_DATA = 0x15
OBJECT_DOES_NOT_EXIST = 0x16
INVALID_PARAMETER = 0x20
