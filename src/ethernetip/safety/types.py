"""Basic CIP Safety types: SafetyFormat, ModeByte, SafetyNetworkNumber,
SafetyConfigurationId, UniqueNetworkId."""
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from enum import IntEnum


class SafetyFormat(IntEnum):
    """Wire format selection."""
    BASE = 0       # Separate data, complement, and timestamp sections with CRC-S1/S2/S3.
    EXTENDED = 1   # Includes rollover counter, uses CRC-S5. Required for RPI > 100ms.


class ModeByte:
    """CIP Safety Mode Byte.

    Bit layout (verified against real 1734 PointIO captures):
        7:    Run_Idle
        6-5:  TBD_2_Bit (reserved, 0)
        4:    N_Run_Idle (complement of bit 7)
        3:    TBD_Bit (reserved, 0)
        2:    N_TBD_Bit (complement of bit 3, always 1)
        1-0:  Ping_Count

    Examples from real device:
        0x14 = run=0, ping=0 (cold start)
        0x84 = run=1, ping=0
        0x85 = run=1, ping=1
        0x86 = run=1, ping=2
        0x87 = run=1, ping=3
    """
    __slots__ = ('_raw',)

    def __init__(self, raw: int):
        self._raw = raw & 0xFF

    @property
    def run_idle(self) -> bool:
        return (self._raw & 0x80) != 0

    @property
    def ping_count(self) -> int:
        """0-3."""
        return self._raw & 0x03

    @property
    def value(self) -> int:
        """Raw byte."""
        return self._raw

    @property
    def data_crc_mask(self) -> int:
        """Bits used in actual/complement data CRC: ModeByte AND 0xE0."""
        return self._raw & 0xE0

    @property
    def complement_data_crc_mask(self) -> int:
        """Bits used in complement data CRC (base format): (ModeByte XOR 0xFF) AND 0xE0."""
        return (self._raw ^ 0xFF) & 0xE0

    @property
    def timestamp_crc_mask(self) -> int:
        """Bits used in timestamp CRC: ModeByte AND 0x1F."""
        return self._raw & 0x1F

    @staticmethod
    def create(run_idle: bool, ping_count: int) -> 'ModeByte':
        """Build a mode byte with auto-computed redundant bits."""
        raw = 0
        if run_idle:
            raw |= 0x80
        raw |= ping_count & 0x03
        return ModeByte(ModeByte.compute_redundant_bits(raw))

    @staticmethod
    def compute_redundant_bits(raw: int) -> int:
        """Bit 4 = NOT(bit 7); bit 2 = NOT(bit 3)."""
        if (raw & 0x80) == 0:
            raw |= 0x10
        else:
            raw &= ~0x10 & 0xFF
        if (raw & 0x08) == 0:
            raw |= 0x04
        else:
            raw &= ~0x04 & 0xFF
        return raw & 0xFF

    def validate(self) -> bool:
        """Returns True if redundant bits are consistent (complement of their pair)."""
        run = (self._raw & 0x80) != 0
        n_run = (self._raw & 0x10) != 0
        if run == n_run:
            return False
        tbd = (self._raw & 0x08) != 0
        n_tbd = (self._raw & 0x04) != 0
        if tbd == n_tbd:
            return False
        return True

    def __repr__(self) -> str:
        return f"ModeByte(0x{self._raw:02X} run={self.run_idle} ping={self.ping_count})"

    def __eq__(self, other) -> bool:
        return isinstance(other, ModeByte) and self._raw == other._raw

    def __hash__(self) -> int:
        return hash(self._raw)


@dataclass(frozen=True)
class SafetyNetworkNumber:
    """6-byte unique identifier for a safety network."""
    data: bytes = b'\x00' * 6

    def __post_init__(self):
        if len(self.data) != 6:
            raise ValueError(f"SNN must be exactly 6 bytes, got {len(self.data)}")

    def copy_to(self, dst: bytearray, offset: int = 0) -> None:
        dst[offset:offset + 6] = self.data


ZERO_SNN = SafetyNetworkNumber()


@dataclass(frozen=True)
class SafetyConfigurationId:
    """SCCRC (4 bytes) + SCTS (6 bytes) = 10 bytes."""
    sccrc: int = 0
    scts: SafetyNetworkNumber = field(default_factory=SafetyNetworkNumber)

    SIZE = 10

    def copy_to(self, dst: bytearray, offset: int = 0) -> None:
        struct.pack_into('<I', dst, offset, self.sccrc)
        self.scts.copy_to(dst, offset + 4)

    @staticmethod
    def parse(data: bytes) -> 'SafetyConfigurationId':
        if len(data) < SafetyConfigurationId.SIZE:
            raise ValueError(f"SCID needs {SafetyConfigurationId.SIZE} bytes")
        sccrc, = struct.unpack_from('<I', data, 0)
        return SafetyConfigurationId(
            sccrc=sccrc,
            scts=SafetyNetworkNumber(bytes(data[4:10])),
        )


@dataclass(frozen=True)
class UniqueNetworkId:
    """SNN(6) + NodeAddress(4) = 10 bytes."""
    snn: SafetyNetworkNumber = field(default_factory=SafetyNetworkNumber)
    node_address: int = 0

    SIZE = 10

    def copy_to(self, dst: bytearray, offset: int = 0) -> None:
        self.snn.copy_to(dst, offset)
        struct.pack_into('<I', dst, offset + 6, self.node_address)

    @staticmethod
    def parse(data: bytes) -> 'UniqueNetworkId':
        if len(data) < UniqueNetworkId.SIZE:
            raise ValueError(f"UNID needs {UniqueNetworkId.SIZE} bytes")
        node, = struct.unpack_from('<I', data, 6)
        return UniqueNetworkId(
            snn=SafetyNetworkNumber(bytes(data[0:6])),
            node_address=node,
        )
