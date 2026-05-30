"""CIP Safety Validator Object (Class 0x3A).

One instance per active safety connection. Manages CRC seed bindings,
timestamp/rollover/ping counters, and per-connection state.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum

from ..cip.cip_class import CipClass
from ..cip.instance import CipInstance
from ..cip.attribute import CipAttribute, AttributeAccess
from ..cip.data_types import CipDataType
from ..connections.io_connection import IoConnection


CLASS_CODE = 0x3A


class SafetyValidatorState(IntEnum):
    IDLE = 0
    EXECUTING = 1
    FAULTED = 2


@dataclass
class SafetyValidatorInstance:
    instance_id: int = 0
    cip_instance: CipInstance | None = None
    connection: IoConnection | None = None
    state: SafetyValidatorState = SafetyValidatorState.IDLE

    # CRC seeds (precomputed from PID)
    pid_seed_s1: int = 0
    pid_seed_s3: int = 0
    pid_seed_s5: int = 0

    # Runtime counters
    rollover_count: int = 0
    timestamp: int = 0
    ping_count: int = 0
    packets_produced: int = 0
    packets_consumed: int = 0
    crc_errors: int = 0

    def advance_timestamp(self, increment: int) -> None:
        """Advance the 128µs timestamp. Wraps at 0xFFFF and bumps rollover."""
        nxt = self.timestamp + increment
        if nxt > 0xFFFF:
            self.rollover_count = (self.rollover_count + 1) & 0xFFFF
            self.timestamp = nxt & 0xFFFF
        else:
            self.timestamp = nxt


class SafetyValidatorObject:
    """CIP Safety Validator class (0x3A)."""

    def __init__(self):
        self._cip_class = CipClass(CLASS_CODE, "Safety Validator", revision=1)
        self._cip_class.add_standard_instance_services()
        self._next_instance_id = 0

    @property
    def cip_class(self) -> CipClass:
        return self._cip_class

    def create_instance(self, connection: IoConnection) -> SafetyValidatorInstance:
        self._next_instance_id += 1
        cip_inst = self._cip_class.create_instance(self._next_instance_id)

        validator = SafetyValidatorInstance(
            instance_id=self._next_instance_id,
            cip_instance=cip_inst,
            connection=connection,
            state=SafetyValidatorState.IDLE,
            pid_seed_s1=connection.safety_pid_seed_s1,
            pid_seed_s3=connection.safety_pid_seed_s3,
            pid_seed_s5=connection.safety_pid_seed_s5,
        )
        cip_inst.user_data = validator

        cip_inst.add_attribute(CipAttribute.create_byte(
            1, CipDataType.USINT,
            AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL,
            int(validator.state)))
        cip_inst.add_attribute(CipAttribute.create_byte(
            2, CipDataType.USINT,
            AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, 0))

        return validator
