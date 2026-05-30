"""EtherNet/IP Adapter (server/target) — TCP listener on port 44818."""

from __future__ import annotations
import asyncio
import struct
import socket
from typing import Callable

from ..cip.encapsulation import (
    EncapsulationHeader, EncapsulationCommand, EncapsulationStatus, SIZE as HEADER_SIZE,
)
from ..cip.cpf import CpfItem, CpfItemType, encode_cpf
from ..cip import mr_codec
from ..cip.path import CipPath
from ..cip.service import CipServiceResponse
from ..cip.identity_info import IdentityInfo
from ..cip import standard_services as std

from .session_manager import SessionManager
from .eip_udp_transport import IO_PORT
from .messages import (
    IMessage, EncapsulationMessage, EncapsulationMessageManager,
    NopMessage, RegisterSessionMessage, UnregisterSessionMessage,
    ListIdentityMessage, ListServicesMessage, SendRRDataMessage,
    SendUnitDataMessage,
)

DEFAULT_PORT = 44818


class EipAdapter:
    """EtherNet/IP TCP server — accepts connections, routes CIP messages through dispatch.

    Class-3-clean by default: Forward Open replies carry only the standard
    NullAddress + UnconnectedData CPF items. Use the IoEipAdapter subclass
    when serving Class 0/1 I/O connections that need Sockaddr Info O→T /
    T→O items on the reply.
    """

    def __init__(self, dispatch, identity: IdentityInfo, sessions=None, identity_source=None):
        self._dispatch = dispatch
        self._identity = identity
        self._sessions = sessions or SessionManager()
        self._identity_source = identity_source or dispatch
        self._manager = EncapsulationMessageManager()
        self._server: asyncio.Server | None = None
        self.port: int = DEFAULT_PORT
        # SendUnitData reply requires the reverse of the connection ID the
        # PLC sent in: PLC ships with OT_conn_id (we assigned), we must reply
        # with TO_conn_id (PLC assigned). Wire this to ConnectionManager's
        # find_by_ot_id lookup. If unset, the reply echoes the request's
        # connection_id — fine for loopback tests but rejected by Logix MSG
        # instructions (which see "not for me" and time out).
        self.connection_id_lookup: Callable[[int], int] | None = None

    async def listen(self, host: str = '0.0.0.0', port: int = DEFAULT_PORT) -> None:
        self.port = port
        self._server = await asyncio.start_server(
            self._handle_client, host, port,
            family=socket.AF_INET,
        )
        for sock in self._server.sockets:
            addr = sock.getsockname()
            self.port = addr[1]
            break

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        session_handle = 0
        peername = writer.get_extra_info('peername', ('0.0.0.0', 0))
        sockname = writer.get_extra_info('sockname', ('0.0.0.0', 0))
        local_addr = sockname[0]
        accum = bytearray()

        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                accum.extend(chunk)

                # Drain as many complete frames as we have buffered.
                while True:
                    msg, consumed = self._manager.try_parse(bytes(accum), peername)
                    if msg is None:
                        break
                    del accum[:consumed]

                    response = self._dispatch_message(msg, session_handle, local_addr)

                    if isinstance(msg, RegisterSessionMessage) and response and \
                            EncapsulationHeader.parse(response).status == EncapsulationStatus.SUCCESS:
                        # Pick up the freshly-allocated handle for subsequent frames
                        session_handle = EncapsulationHeader.parse(response).session_handle
                    elif isinstance(msg, UnregisterSessionMessage):
                        session_handle = 0

                    if response is not None:
                        writer.write(response)
                        await writer.drain()

        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            if session_handle != 0:
                self._sessions.unregister(session_handle)
            writer.close()

    def _dispatch_message(self, msg: IMessage, session_handle: int, local_addr: str) -> bytes | None:
        """Route a parsed message to its handler. Returns response bytes or None."""
        if isinstance(msg, NopMessage):
            return None
        if isinstance(msg, ListIdentityMessage):
            return self._handle_list_identity(msg, local_addr)
        if isinstance(msg, ListServicesMessage):
            return self._handle_list_services(msg)
        if isinstance(msg, RegisterSessionMessage):
            return self._handle_register_session(msg)
        if isinstance(msg, UnregisterSessionMessage):
            self._sessions.unregister(msg.session_handle)
            return None
        if isinstance(msg, SendRRDataMessage):
            return self._handle_send_rr_data(msg, session_handle, local_addr)
        if isinstance(msg, SendUnitDataMessage):
            return self._handle_send_unit_data(msg, session_handle)
        if isinstance(msg, EncapsulationMessage):
            return _build_error_response(msg.header.command, msg.header.session_handle,
                                         msg.header.sender_context,
                                         EncapsulationStatus.INVALID_COMMAND)
        return None

    def _handle_list_identity(self, msg: ListIdentityMessage, local_addr: str) -> bytes:
        identity_data = bytearray(512)
        offset = 0

        # Encapsulation protocol version
        struct.pack_into('<H', identity_data, offset, 1); offset += 2
        # Socket address (big-endian)
        struct.pack_into('>hH', identity_data, offset, 2, self.port); offset += 4
        addr_bytes = socket.inet_aton(local_addr)
        identity_data[offset:offset + 4] = addr_bytes; offset += 4
        offset += 8  # sin_zero

        # Identity attributes from GetAttributeAll
        id_path = CipPath(class_id=0x01, instance_id=1)
        get_all = self._identity_source.dispatch(std.GET_ATTRIBUTE_ALL, id_path, b'')
        if get_all.status.is_success and get_all.data:
            identity_data[offset:offset + len(get_all.data)] = get_all.data
            offset += len(get_all.data)

        identity_data[offset] = 0xFF; offset += 1  # State

        items = [CpfItem(CpfItemType.CIP_IDENTITY, bytes(identity_data[:offset]))]
        cpf_data = encode_cpf(items)
        return _build_response(EncapsulationCommand.LIST_IDENTITY,
                               msg.session_handle, msg.sender_context, cpf_data)

    def _handle_list_services(self, msg: ListServicesMessage) -> bytes:
        service_data = bytearray(20)
        struct.pack_into('<HH', service_data, 0, 1, 0x0120)  # version, capability
        name = b'Communications\x00\x00'
        service_data[4:4 + 16] = name[:16]

        items = [CpfItem(CpfItemType.LIST_SERVICES_RESPONSE, bytes(service_data))]
        cpf_data = encode_cpf(items)
        return _build_response(EncapsulationCommand.LIST_SERVICES,
                               msg.session_handle, msg.sender_context, cpf_data)

    def _handle_register_session(self, msg: RegisterSessionMessage) -> bytes:
        handle = self._sessions.register()
        # Build the response as another RegisterSessionMessage (proves the typed
        # paradigm round-trips cleanly through to-bytes).
        reply = RegisterSessionMessage(
            session_handle=handle,
            status=EncapsulationStatus.SUCCESS,
            sender_context=msg.sender_context,
            protocol_version=1,
            options_flags=0,
            remote_addr=msg.remote_addr,
        )
        return reply.to_bytes()

    def _handle_send_rr_data(self, msg: SendRRDataMessage, session_handle: int,
                              local_addr: str) -> bytes:
        if session_handle == 0 or not self._sessions.is_valid(msg.session_handle):
            return _build_error_response(EncapsulationCommand.SEND_RR_DATA,
                                         msg.session_handle, msg.sender_context,
                                         EncapsulationStatus.INVALID_SESSION_HANDLE)

        result = mr_codec.try_parse_request(msg.cip_data)
        if result is None:
            return _build_error_response(EncapsulationCommand.SEND_RR_DATA,
                                         msg.session_handle, msg.sender_context,
                                         EncapsulationStatus.INCORRECT_DATA)

        service_code, path, data = result
        cip_response = self._dispatch.dispatch(service_code, path, data)

        # Encode MR response
        mr_buf = bytearray(4096)
        mr_len = cip_response.encode(mr_buf)
        mr_data = bytes(mr_buf[:mr_len])

        # Build reply CPF
        reply_items = [
            CpfItem(CpfItemType.NULL_ADDRESS, b''),
            CpfItem(CpfItemType.UNCONNECTED_DATA, mr_data),
        ]

        # Successful Forward Open → let subclasses (IoEipAdapter) attach
        # Sockaddr Info items and fire their on_connection_opened callbacks.
        is_forward_open = (cip_response.status.is_success and service_code in (0x54, 0x5B))
        if is_forward_open:
            self._on_forward_open_reply(reply_items, service_code, data,
                                         cip_response, local_addr, msg.remote_addr)

        reply_cpf = encode_cpf(reply_items)

        # SendRRData payload = InterfaceHandle(4) + Timeout(2) + CPF items
        response_payload = bytearray(6 + len(reply_cpf))
        response_payload[6:] = reply_cpf

        return _build_response(EncapsulationCommand.SEND_RR_DATA,
                               session_handle, msg.sender_context, bytes(response_payload))

    def _handle_send_unit_data(self, msg: SendUnitDataMessage, session_handle: int) -> bytes:
        """Connected explicit messaging (Class 3). After a Forward Open opens
        a Class 3 connection, the scanner uses SendUnitData (0x70) — not
        SendRRData — for every subsequent CIP request. Without this handler
        those requests get silently dropped and the client times out.

        ConnectedData payload: sequence_count(2) + MR request. Echo the seq
        in the reply.
        """
        if session_handle == 0 or not self._sessions.is_valid(msg.session_handle):
            return _build_error_response(EncapsulationCommand.SEND_UNIT_DATA,
                                         msg.session_handle, msg.sender_context,
                                         EncapsulationStatus.INVALID_SESSION_HANDLE)
        if len(msg.cip_data) < 2:
            return _build_error_response(EncapsulationCommand.SEND_UNIT_DATA,
                                         msg.session_handle, msg.sender_context,
                                         EncapsulationStatus.INCORRECT_DATA)
        (seq_count,) = struct.unpack_from('<H', msg.cip_data, 0)
        result = mr_codec.try_parse_request(msg.cip_data[2:])
        if result is None:
            return _build_error_response(EncapsulationCommand.SEND_UNIT_DATA,
                                         msg.session_handle, msg.sender_context,
                                         EncapsulationStatus.INCORRECT_DATA)
        service_code, path, data = result
        cip_response = self._dispatch.dispatch(service_code, path, data)

        mr_buf = bytearray(4096)
        mr_len = cip_response.encode(mr_buf)
        mr_data = bytes(mr_buf[:mr_len])

        # The reply's connection_id must be the TO_conn_id (the ID PLC
        # assigned for us-to-PLC traffic) — not the OT_conn_id the PLC put
        # in the request (which identifies our endpoint). Use the
        # connection-id lookup; fall back to echoing if no lookup is wired
        # (loopback tests).
        reply_conn_id = msg.connection_id
        if self.connection_id_lookup is not None:
            tto_o = self.connection_id_lookup(msg.connection_id)
            if tto_o:
                reply_conn_id = tto_o

        reply = SendUnitDataMessage(
            session_handle=session_handle,
            status=EncapsulationStatus.SUCCESS,
            sender_context=msg.sender_context,
            connection_id=reply_conn_id,
            cip_data=struct.pack('<H', seq_count) + mr_data,
        )
        return reply.to_bytes()

    def _on_forward_open_reply(self, cpf_items: list, service_code: int,
                                request_data: bytes,
                                response: CipServiceResponse,
                                local_addr: str,
                                remote_addr: tuple[str, int]) -> None:
        """Hook invoked on every successful Forward Open just before the
        reply CPF is built. Base implementation is a no-op; subclasses
        (IoEipAdapter) may append extra CPF items (e.g. Sockaddr Info) and
        fire callbacks."""
        pass


class IoEipAdapter(EipAdapter):
    """EipAdapter variant for Class 0/1 I/O serving — attaches Sockaddr Info
    O→T / T→O items to Forward Open replies so the originator knows which
    UDP endpoint to use, and fires `on_connection_opened` callbacks so the
    host can associate the new IoConnection with its PLC's UDP endpoint.
    Skips the Sockaddr items for Class 3 explicit FwdOpens (those don't use
    UDP, and Logix MSG rejects the reply with extended status 0x0205)."""

    def __init__(self, dispatch, identity: IdentityInfo, sessions=None, identity_source=None):
        super().__init__(dispatch, identity, sessions, identity_source)
        self.udp_port: int = IO_PORT
        # Callbacks fired on successful FwdOpen: (CipServiceResponse, (host, port)).
        self.on_connection_opened: list[Callable[[CipServiceResponse, tuple[str, int]], None]] = []

    def _on_forward_open_reply(self, cpf_items: list, service_code: int,
                                request_data: bytes,
                                response: CipServiceResponse,
                                local_addr: str,
                                remote_addr: tuple[str, int]) -> None:
        # Class 3 explicit-messaging FwdOpens don't use UDP; including
        # Sockaddr Info items in the reply makes Logix's MSG instruction
        # reject the connection (extended status 0x0205). Peek the
        # transport_class_trigger byte to skip Class 3.
        tct_off = 36 if service_code == 0x5B else 34
        if len(request_data) > tct_off and (request_data[tct_off] & 0x0F) == 3:
            return
        cpf_items.append(CpfItem(CpfItemType.SOCKADDR_INFO_OT,
                                  _build_sockaddr_info(local_addr, self.udp_port)))
        cpf_items.append(CpfItem(CpfItemType.SOCKADDR_INFO_TO,
                                  _build_sockaddr_info('0.0.0.0', self.udp_port)))
        plc_udp_endpoint = (remote_addr[0], IO_PORT)
        for cb in self.on_connection_opened:
            cb(response, plc_udp_endpoint)


def _build_sockaddr_info(address: str, port: int) -> bytes:
    data = bytearray(16)
    struct.pack_into('>hH', data, 0, 2, port)  # sin_family=AF_INET, sin_port
    data[4:8] = socket.inet_aton(address)
    return bytes(data)


def _build_response(command: EncapsulationCommand, session_handle: int,
                    sender_context: int, payload: bytes) -> bytes:
    reply = EncapsulationHeader(
        command=command,
        length=len(payload),
        session_handle=session_handle,
        sender_context=sender_context,
    )
    buf = bytearray(HEADER_SIZE + len(payload))
    reply.write_to(buf)
    buf[HEADER_SIZE:] = payload
    return bytes(buf)


def _build_error_response(command: EncapsulationCommand, session_handle: int,
                          sender_context: int, status: EncapsulationStatus) -> bytes:
    reply = EncapsulationHeader(
        command=command,
        session_handle=session_handle,
        status=status,
        sender_context=sender_context,
    )
    buf = bytearray(HEADER_SIZE)
    reply.write_to(buf)
    return bytes(buf)
