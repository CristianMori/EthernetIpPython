"""CIP Safety Supervisor Object (Class 0x39).

One per device. Holds overall device safety state, SNN/TUNID, SCID,
and the Propose/Apply TUNID services.
"""
from __future__ import annotations
import struct
from enum import IntEnum

from ..cip.cip_class import CipClass
from ..cip.instance import CipInstance
from ..cip.attribute import CipAttribute, AttributeAccess
from ..cip.data_types import CipDataType
from ..cip.service import CipServiceDefinition, CipServiceRequest, CipServiceResponse
from ..cip.status import CipStatus, NOT_ENOUGH_DATA, INVALID_PARAMETER

from .types import (
    UniqueNetworkId, SafetyNetworkNumber, SafetyConfigurationId, ZERO_SNN,
)


CLASS_CODE = 0x39

PROPOSE_TUNID_SERVICE = 0x56
APPLY_TUNID_SERVICE = 0x57
SAFETY_RESET_SERVICE = 0x54


class SafetySupervisorState(IntEnum):
    IDLE = 0
    SELF_TESTING = 1
    EXECUTING = 2
    ABORT = 3
    EXCEPTION = 4
    WAIT_FOR_LOCK = 5


class SafetySupervisorMode(IntEnum):
    IDLE = 0
    CONFIGURATION = 1
    RUN = 2


class SafetySupervisorObject:
    """CIP Safety Supervisor (0x39). Single instance per device."""

    def __init__(self, snn: SafetyNetworkNumber, node_address: int):
        self.state = SafetySupervisorState.IDLE
        self.mode = SafetySupervisorMode.IDLE
        self.snn = snn
        self.tunid = UniqueNetworkId(snn=snn, node_address=node_address)
        self.scid = SafetyConfigurationId()
        self.tunid_assigned = False
        self._proposed_tunid: UniqueNetworkId | None = None

        self._cip_class = CipClass(CLASS_CODE, "Safety Supervisor", revision=1)
        self._cip_class.add_standard_instance_services()

        inst = self._cip_class.create_instance(1)

        # Attribute 1: State (USINT)
        inst.add_attribute(CipAttribute.create_byte(
            1, CipDataType.USINT,
            AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, int(self.state)))

        # Attribute 2: Mode (USINT)
        inst.add_attribute(CipAttribute.create_byte(
            2, CipDataType.USINT,
            AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, int(self.mode)))

        # Attribute 3: Safety Network Number (6 bytes)
        snn_data = bytearray(6)
        snn.copy_to(snn_data)
        inst.add_attribute(CipAttribute(
            3, CipDataType.BYTE,
            AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, bytes(snn_data)))

        # Attribute 4: Configuration Lock (USINT) — 0 = unlocked
        inst.add_attribute(CipAttribute.create_byte(
            4, CipDataType.USINT,
            AttributeAccess.GET_SINGLE | AttributeAccess.SET_SINGLE | AttributeAccess.GET_ALL, 0))

        # Attribute 6: Safety Configuration Identifier (10 bytes, zeros = unconfigured)
        inst.add_attribute(CipAttribute(
            6, CipDataType.BYTE,
            AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL,
            bytes(SafetyConfigurationId.SIZE)))

        # Attribute 25 (0x19): Configuration UNID (10 bytes, zeros = unowned)
        inst.add_attribute(CipAttribute(
            25, CipDataType.BYTE,
            AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL,
            bytes(UniqueNetworkId.SIZE)))

        # Attribute 27 (0x1B): Target UNID (10 bytes)
        tunid_data = bytearray(UniqueNetworkId.SIZE)
        self.tunid.copy_to(tunid_data)
        inst.add_attribute(CipAttribute(
            27, CipDataType.BYTE,
            AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, bytes(tunid_data)))

        # Attribute 28 (0x1C): Output Connection Point Owners — 0 entries
        inst.add_attribute(CipAttribute(
            28, CipDataType.UINT,
            AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, b'\x00\x00'))

        self._cip_class.add_instance_service(CipServiceDefinition(
            SAFETY_RESET_SERVICE, "Safety_Reset", self._handle_safety_reset))
        self._cip_class.add_instance_service(CipServiceDefinition(
            PROPOSE_TUNID_SERVICE, "Propose_TUNID", self._handle_propose_tunid))
        self._cip_class.add_instance_service(CipServiceDefinition(
            APPLY_TUNID_SERVICE, "Apply_TUNID", self._handle_apply_tunid))

    @property
    def cip_class(self) -> CipClass:
        return self._cip_class

    def start(self) -> None:
        """Transition to Executing (ready for safety connections)."""
        self.state = SafetySupervisorState.EXECUTING
        self.mode = SafetySupervisorMode.RUN
        self._update_state_attribute()

    def abort(self) -> None:
        self.state = SafetySupervisorState.ABORT
        self._update_state_attribute()

    def reset(self) -> None:
        self.state = SafetySupervisorState.IDLE
        self.mode = SafetySupervisorMode.IDLE
        self._update_state_attribute()

    def _update_state_attribute(self) -> None:
        inst = self._cip_class.get_instance(1)
        if inst is None:
            return
        a1 = inst.get_attribute(1)
        a2 = inst.get_attribute(2)
        if a1 is not None:
            a1.set_data(bytes([int(self.state)]))
        if a2 is not None:
            a2.set_data(bytes([int(self.mode)]))

    def _handle_safety_reset(self, instance: CipInstance,
                              request: CipServiceRequest) -> CipServiceResponse:
        if len(request.data) < 1:
            return CipServiceResponse.error(request.service_code,
                                             CipStatus.error(NOT_ENOUGH_DATA))
        reset_type = request.data[0]
        if reset_type in (0, 1):
            self.reset()
            return CipServiceResponse.success(request.service_code)
        if reset_type == 2:
            # Reset ownership: clear CFUNID, owner list, SCID, TUNID assignment.
            attr25 = instance.get_attribute(25)
            if attr25 is not None:
                attr25.set_data(bytes(UniqueNetworkId.SIZE))
            attr28 = instance.get_attribute(28)
            if attr28 is not None:
                attr28.set_data(b'\x00\x00')
            self.scid = SafetyConfigurationId()
            self.tunid_assigned = False
            self._proposed_tunid = None
            return CipServiceResponse.success(request.service_code)
        return CipServiceResponse.error(request.service_code,
                                         CipStatus.error(INVALID_PARAMETER))

    def _handle_propose_tunid(self, instance: CipInstance,
                                request: CipServiceRequest) -> CipServiceResponse:
        if len(request.data) < UniqueNetworkId.SIZE:
            return CipServiceResponse.error(request.service_code,
                                             CipStatus.error(NOT_ENOUGH_DATA))
        # All-0xFF cancels any pending proposal.
        if all(b == 0xFF for b in request.data[:UniqueNetworkId.SIZE]):
            self._proposed_tunid = None
            return CipServiceResponse.success(request.service_code)
        self._proposed_tunid = UniqueNetworkId.parse(request.data[:UniqueNetworkId.SIZE])
        return CipServiceResponse.success(request.service_code)

    def _handle_apply_tunid(self, instance: CipInstance,
                              request: CipServiceRequest) -> CipServiceResponse:
        if len(request.data) < UniqueNetworkId.SIZE:
            return CipServiceResponse.error(request.service_code,
                                             CipStatus.error(NOT_ENOUGH_DATA))
        if self._proposed_tunid is None:
            return CipServiceResponse.error(request.service_code,
                                             CipStatus.error(0x0C))  # Object state conflict
        applied = UniqueNetworkId.parse(request.data[:UniqueNetworkId.SIZE])
        prop_buf = bytearray(UniqueNetworkId.SIZE)
        self._proposed_tunid.copy_to(prop_buf)
        apply_buf = bytearray(UniqueNetworkId.SIZE)
        applied.copy_to(apply_buf)
        if bytes(prop_buf) != bytes(apply_buf):
            return CipServiceResponse.error(request.service_code,
                                             CipStatus.error(INVALID_PARAMETER))

        self.tunid = applied
        self.snn = applied.snn
        self.tunid_assigned = True
        self._proposed_tunid = None

        tunid_bytes = bytearray(UniqueNetworkId.SIZE)
        self.tunid.copy_to(tunid_bytes)
        a27 = instance.get_attribute(27)
        if a27 is not None:
            a27.set_data(bytes(tunid_bytes))
        snn_bytes = bytearray(6)
        self.snn.copy_to(snn_bytes)
        a3 = instance.get_attribute(3)
        if a3 is not None:
            a3.set_data(bytes(snn_bytes))

        return CipServiceResponse.success(request.service_code)
