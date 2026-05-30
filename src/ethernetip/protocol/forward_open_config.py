"""Configuration for establishing an I/O connection via Forward Open."""

from dataclasses import dataclass


@dataclass
class ForwardOpenConfig:
    consumed_assembly: int = 0       # O→T assembly instance
    produced_assembly: int = 0       # T→O assembly instance
    config_assembly: int = 0         # Config assembly instance
    consumed_size: int = 0           # O→T data size (app data, no headers)
    produced_size: int = 0           # T→O data size (app data, no headers)
    rpi: int = 10_000                # Requested Packet Interval in microseconds
    transport_class: int = 1         # 0=Class0, 1=Class1
    timeout_multiplier: int = 2      # 0=x4, 1=x8, 2=x16

    @property
    def is_class1(self) -> bool:
        return self.transport_class == 1
