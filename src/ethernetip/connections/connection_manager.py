"""CIP Connection Manager Object (Class 0x06) — Forward Open/Close and Unconnected Send."""

from __future__ import annotations
import struct
import threading
from typing import Callable

from ..cip.cip_class import CipClass
from ..cip.instance import CipInstance
from ..cip.attribute import CipAttribute, AttributeAccess
from ..cip.data_types import CipDataType
from ..cip.service import CipServiceDefinition, CipServiceRequest, CipServiceResponse
from ..cip.status import CipStatus, NOT_ENOUGH_DATA, SERVICE_NOT_SUPPORTED, PATH_SEGMENT_ERROR
from ..cip.path import CipPath
from ..cip import mr_codec

from .io_connection import IoConnection, ConnectionState
from .forward_open_request import ForwardOpenRequest
from .connection_path_parser import parse_connection_path
from .safety_handler import SafetyConnectionHandler

CLASS_CODE = 0x06
FORWARD_OPEN_SERVICE = 0x54
FORWARD_CLOSE_SERVICE = 0x4E
LARGE_FORWARD_OPEN_SERVICE = 0x5B
UNCONNECTED_SEND_SERVICE = 0x52


class ConnectionManagerObject:
    """CIP Connection Manager — handles Forward Open/Close and Unconnected Send."""

    def __init__(self):
        self._cip_class = CipClass(CLASS_CODE, "Connection Manager", revision=1)
        self._cip_class.add_standard_instance_services()

        inst = self._cip_class.create_instance(1)
        for i in range(1, 9):
            inst.add_attribute(CipAttribute.create_uint(i, CipDataType.UINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, 0))

        self._cip_class.add_instance_service(CipServiceDefinition(FORWARD_OPEN_SERVICE, "Forward_Open", self._handle_forward_open))
        self._cip_class.add_instance_service(CipServiceDefinition(FORWARD_CLOSE_SERVICE, "Forward_Close", self._handle_forward_close))
        self._cip_class.add_instance_service(CipServiceDefinition(LARGE_FORWARD_OPEN_SERVICE, "Large_Forward_Open", self._handle_large_forward_open))
        self._cip_class.add_instance_service(CipServiceDefinition(UNCONNECTED_SEND_SERVICE, "Unconnected_Send", self._handle_unconnected_send))

        self._connections: dict[int, IoConnection] = {}
        self._next_connection_id = 0
        self._lock = threading.Lock()

        # Callbacks
        self.on_connection_established: list[Callable[[IoConnection], None]] = []
        self.on_connection_removed: list[Callable[[IoConnection], None]] = []
        self.validate_assembly: Callable[[int], int] | None = None
        self.dispatch_request: Callable[[int, CipPath, bytes], CipServiceResponse] | None = None

        # Optional safety handler — set by SafetyDevice. When None, safety
        # connections are accepted only as normal connections (no safety reply).
        self.safety_handler: SafetyConnectionHandler | None = None

    @property
    def cip_class(self) -> CipClass:
        return self._cip_class

    @property
    def active_connections(self) -> list[IoConnection]:
        return list(self._connections.values())

    def find_by_ot_id(self, connection_id: int) -> IoConnection | None:
        return self._connections.get(connection_id)

    def remove_connection(self, conn: IoConnection) -> None:
        self._connections.pop(conn.ot_connection_id, None)
        conn.close()
        for cb in self.on_connection_removed:
            cb(conn)

    def timeout_connection(self, conn: IoConnection) -> None:
        conn.state = ConnectionState.TIMED_OUT
        self.remove_connection(conn)

    def _handle_forward_open(self, instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
        return self._process_forward_open(request, is_large=False)

    def _handle_large_forward_open(self, instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
        return self._process_forward_open(request, is_large=True)

    def _process_forward_open(self, request: CipServiceRequest, is_large: bool) -> CipServiceResponse:
        fwd_open = ForwardOpenRequest.parse(request.data, is_large)
        path_result = parse_connection_path(fwd_open.connection_path, fwd_open)

        # Safety validation: TUNID match, SCID check, CPCRC
        if path_result.safety_segment is not None and self.safety_handler is not None:
            reject = self.safety_handler.validate_safety_open(path_result.safety_segment, fwd_open)
            if reject is not None:
                return _forward_open_error(request.service_code, reject)

        # Validate assemblies
        if self.validate_assembly is not None:
            if path_result.consumed_assembly_instance is not None:
                if self.validate_assembly(path_result.consumed_assembly_instance) < 0:
                    return _forward_open_error(request.service_code, 0x0116)
            if path_result.produced_assembly_instance is not None:
                if self.validate_assembly(path_result.produced_assembly_instance) < 0:
                    return _forward_open_error(request.service_code, 0x0116)

        # Refuse if O->T and T->O reference the same assembly instance.
        # Logix safety configs do legitimately overlap the config instance with
        # one of the data instances, so we only reject the data/data clash here.
        if (path_result.consumed_assembly_instance is not None
                and path_result.produced_assembly_instance is not None
                and path_result.consumed_assembly_instance == path_result.produced_assembly_instance):
            return _forward_open_error(request.service_code, 0x0116)

        # Check for duplicate triad
        for existing in self._connections.values():
            if (existing.connection_serial_number == fwd_open.connection_serial_number and
                    existing.originator_vendor_id == fwd_open.originator_vendor_id and
                    existing.originator_serial_number == fwd_open.originator_serial_number):
                return _forward_open_error(request.service_code, 0x0100)

        with self._lock:
            self._next_connection_id += 1
            ot_id = self._next_connection_id

        conn = IoConnection()
        conn.connection_serial_number = fwd_open.connection_serial_number
        conn.originator_vendor_id = fwd_open.originator_vendor_id
        conn.originator_serial_number = fwd_open.originator_serial_number
        conn.ot_connection_id = ot_id
        conn.to_connection_id = fwd_open.to_connection_id
        conn.consumed_assembly_instance = path_result.consumed_assembly_instance or 0
        conn.produced_assembly_instance = path_result.produced_assembly_instance or 0
        conn.config_assembly_instance = path_result.config_assembly_instance or 0
        conn.config_data = path_result.config_data
        conn.ot_rpi = fwd_open.ot_rpi
        conn.to_rpi = fwd_open.to_rpi
        conn.ot_size = fwd_open.ot_params.connection_size
        conn.to_size = fwd_open.to_params.connection_size
        conn.transport_class = fwd_open.transport_class
        conn.timeout_multiplier = fwd_open.connection_timeout_multiplier
        conn.state = ConnectionState.ESTABLISHED

        # Detect safety by presence of 0x50 segment (not by transport class —
        # safety over EtherNet/IP uses Class 0, not Class 6).
        if path_result.safety_segment is not None:
            conn.is_safety = True
            conn.safety_segment_data = path_result.safety_segment
            if len(path_result.safety_segment) >= 3:
                conn.safety_format = path_result.safety_segment[2]
            if self.safety_handler is not None:
                self.safety_handler.configure_safety_connection(conn, fwd_open)

        self._connections[ot_id] = conn
        for cb in self.on_connection_established:
            cb(conn)

        # Build success response. Safety connections add Application Reply Data.
        # Base Format (0x00): 5 words; Extended Format (0x02): 7 words.
        is_extended = conn.safety_format == 0x02
        app_reply_words = (7 if is_extended else 5) if conn.is_safety else 0
        resp = bytearray(26 + app_reply_words * 2)
        struct.pack_into('<I', resp, 0, ot_id)
        struct.pack_into('<I', resp, 4, fwd_open.to_connection_id)
        struct.pack_into('<H', resp, 8, fwd_open.connection_serial_number)
        struct.pack_into('<H', resp, 10, fwd_open.originator_vendor_id)
        struct.pack_into('<I', resp, 12, fwd_open.originator_serial_number)
        struct.pack_into('<I', resp, 16, fwd_open.ot_rpi)
        struct.pack_into('<I', resp, 20, fwd_open.to_rpi)
        resp[24] = app_reply_words
        resp[25] = 0  # reserved

        if conn.is_safety:
            off = 26
            # Safety Application Reply:
            # Consumer_Number(UINT) + TargetVendorId(UINT) + TargetDevSerialNum(UDINT) + TargetConnSerialNum(UINT)
            struct.pack_into('<H', resp, off, 0xFFFF); off += 2
            tgt_vendor = self.safety_handler.vendor_id if self.safety_handler else 0x0001
            tgt_serial = self.safety_handler.serial_number if self.safety_handler else 0xC0FFEE42
            struct.pack_into('<H', resp, off, tgt_vendor); off += 2
            struct.pack_into('<I', resp, off, tgt_serial); off += 4
            struct.pack_into('<H', resp, off, conn.safety_validator_instance_id); off += 2
            if is_extended:
                struct.pack_into('<H', resp, off, conn.safety_initial_timestamp); off += 2
                struct.pack_into('<H', resp, off, conn.safety_initial_rollover_value); off += 2

        return CipServiceResponse.success(request.service_code, bytes(resp))

    def _handle_forward_close(self, instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
        if len(request.data) < 10:
            return CipServiceResponse.error(request.service_code, CipStatus.error(NOT_ENOUGH_DATA))

        data = request.data
        conn_serial = struct.unpack_from('<H', data, 2)[0]
        orig_vendor = struct.unpack_from('<H', data, 4)[0]
        orig_serial = struct.unpack_from('<I', data, 6)[0]

        found = None
        for conn in self._connections.values():
            if (conn.connection_serial_number == conn_serial and
                    conn.originator_vendor_id == orig_vendor and
                    conn.originator_serial_number == orig_serial):
                found = conn
                break

        if found is None:
            return CipServiceResponse.error(request.service_code, CipStatus.error(0x01, 0x0107))

        self.remove_connection(found)

        resp = bytearray(10)
        struct.pack_into('<H', resp, 0, conn_serial)
        struct.pack_into('<H', resp, 2, orig_vendor)
        struct.pack_into('<I', resp, 4, orig_serial)
        resp[8] = 0
        resp[9] = 0
        return CipServiceResponse.success(request.service_code, bytes(resp))

    def _handle_unconnected_send(self, instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
        if self.dispatch_request is None:
            return CipServiceResponse.error(request.service_code, CipStatus.error(SERVICE_NOT_SUPPORTED))

        if len(request.data) < 4:
            return CipServiceResponse.error(request.service_code, CipStatus.error(NOT_ENOUGH_DATA))

        data = request.data
        msg_length = struct.unpack_from('<H', data, 2)[0]
        offset = 4

        if offset + msg_length > len(data):
            return CipServiceResponse.error(request.service_code, CipStatus.error(NOT_ENOUGH_DATA))

        embedded = data[offset:offset + msg_length]
        result = mr_codec.try_parse_request(embedded)
        if result is None:
            return CipServiceResponse.error(request.service_code, CipStatus.error(PATH_SEGMENT_ERROR))

        svc, path, inner_data = result
        return self.dispatch_request(svc, path, inner_data)


def _forward_open_error(service_code: int, extended_status: int) -> CipServiceResponse:
    return CipServiceResponse.error(service_code, CipStatus.error(0x01, extended_status))
