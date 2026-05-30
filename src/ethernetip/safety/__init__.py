"""CIP Safety — adapter-side implementation.

Wire format, CRCs, time coordination, Safety Supervisor/Validator CIP
objects, and SafetyDevice (extends VirtualDevice with safety framing).
Originator-side (scanner) is not included in this layer.
"""
from .types import (
    SafetyFormat, ModeByte, SafetyNetworkNumber, SafetyConfigurationId, UniqueNetworkId,
)
from .crc import SafetyCrc
from .cpcrc import compute_cpcrc
from .frame_codec import (
    SafetyFrameResult,
    wire_size,
    encode_safety_frame, decode_safety_frame,
    encode_tcoo, encode_tcoo_extended,
    extract_timestamp,
)
from .network_segment import SafetyNetworkSegment, parse_safety_segment, SEGMENT_TYPE
from .supervisor_object import (
    SafetySupervisorObject, SafetySupervisorState, SafetySupervisorMode,
)
from .validator_object import (
    SafetyValidatorObject, SafetyValidatorInstance, SafetyValidatorState,
)
from .safety_device import SafetyDevice
from .forward_open_builder import (
    SafetyForwardOpenConfig, build_safety_forward_open, CM_PATH,
)
from .scanner_connection import SafetyScannerConnection, SafetyAppReply

__all__ = [
    'SafetyFormat', 'ModeByte', 'SafetyNetworkNumber', 'SafetyConfigurationId', 'UniqueNetworkId',
    'SafetyCrc',
    'compute_cpcrc',
    'SafetyFrameResult', 'wire_size',
    'encode_safety_frame', 'decode_safety_frame',
    'encode_tcoo', 'encode_tcoo_extended', 'extract_timestamp',
    'SafetyNetworkSegment', 'parse_safety_segment', 'SEGMENT_TYPE',
    'SafetySupervisorObject', 'SafetySupervisorState', 'SafetySupervisorMode',
    'SafetyValidatorObject', 'SafetyValidatorInstance', 'SafetyValidatorState',
    'SafetyDevice',
    'SafetyForwardOpenConfig', 'build_safety_forward_open', 'CM_PATH',
    'SafetyScannerConnection', 'SafetyAppReply',
]
