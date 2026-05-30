"""Virtual EtherNet/IP device — composes all layers into a running device."""

from __future__ import annotations
import asyncio
import struct
from datetime import datetime, timezone

from ..cip.dispatcher import CipDispatcher
from ..cip.identity_info import IdentityInfo
from ..connections.connection_manager import ConnectionManagerObject
from ..connections.io_connection import IoConnection, ConnectionState, TransportClass
from ..protocol.eip_adapter import EipAdapter, IoEipAdapter, DEFAULT_PORT
from ..protocol.eip_udp_transport import EipUdpTransport, IO_PORT

from .assembly_object import AssemblyObject, AssemblyInstance
from .identity_object import create_identity_class
from .tcpip_interface import create_tcpip_interface_class
from .ethernet_link import create_ethernet_link_class


class VirtualDevice:
    """A fully composed simulated EtherNet/IP device."""

    def __init__(self, identity: IdentityInfo, bind_address: str = '0.0.0.0', name: str | None = None):
        self.identity = identity
        self.bind_address = bind_address
        self.name = name or identity.product_name
        self.dispatcher = CipDispatcher()
        self.assemblies = AssemblyObject()
        self.connection_manager = ConnectionManagerObject()
        self.to_send_count = 0

        self._adapter: IoEipAdapter | None = None
        self._udp: EipUdpTransport | None = None
        self._production_tasks: dict[int, asyncio.Task] = {}
        self._watchdog_tasks: dict[int, asyncio.Task] = {}

        # Wire up assembly validation
        self.connection_manager.validate_assembly = lambda inst_id: (
            asm.data_size if (asm := self.assemblies.get_assembly(inst_id)) else -1
        )
        self.connection_manager.dispatch_request = self.dispatcher.dispatch

        # Register standard CIP objects
        self.dispatcher.register_class(create_identity_class(identity))
        self.dispatcher.register_class(create_tcpip_interface_class(bind_address))
        self.dispatcher.register_class(create_ethernet_link_class())
        self.dispatcher.register_class(self.assemblies.cip_class)
        self.dispatcher.register_class(self.connection_manager.cip_class)

        self.connection_manager.on_connection_established.append(self._on_connection_established)

    def add_assembly(self, instance_id: int, data_size: int, name: str | None = None) -> AssemblyInstance:
        return self.assemblies.add_instance(instance_id, data_size, name)

    async def start(self, tcp_port: int = DEFAULT_PORT, udp_port: int = IO_PORT) -> None:
        self._adapter = IoEipAdapter(self.dispatcher, self.identity)
        self._adapter.udp_port = udp_port

        self._adapter.on_connection_opened.append(self._on_adapter_connection_opened)

        await self._adapter.listen(self.bind_address, tcp_port)

        self._udp = EipUdpTransport(bind_address=self.bind_address, bind_port=udp_port)
        self._udp.on_data_received.append(self._on_udp_data_received)
        self._udp.on_data_received_with_sender.append(self._on_udp_data_with_sender)
        await self._udp.start()

    async def close(self) -> None:
        for task in list(self._production_tasks.values()) + list(self._watchdog_tasks.values()):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        for conn in list(self.connection_manager.active_connections):
            self.connection_manager.remove_connection(conn)

        if self._udp:
            await self._udp.close()
        if self._adapter:
            await self._adapter.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

    def _on_adapter_connection_opened(self, response, plc_endpoint: tuple[str, int]) -> None:
        for conn in self.connection_manager.active_connections:
            if conn.remote_endpoint is None:
                conn.remote_endpoint = plc_endpoint
                break

    def _on_connection_established(self, conn: IoConnection) -> None:
        # Apply the Forward Open Connection Data (Simple Data Segment, 0x80)
        # into the matching config assembly so the originator's config bytes
        # are visible to the device.
        if conn.config_data and conn.config_assembly_instance != 0:
            asm = self.assemblies.get_assembly(conn.config_assembly_instance)
            if asm is not None:
                asm.set_data(conn.config_data)

        # Hook for subclasses (e.g. SafetyDevice) to run setup just before
        # production starts. Default is no-op.
        self.on_connection_ready(conn)

        if conn.produced_assembly_instance != 0 and conn.to_rpi > 0:
            task = asyncio.ensure_future(self._production_loop(conn))
            self._production_tasks[conn.ot_connection_id] = task

        if conn.ot_rpi > 0:
            task = asyncio.ensure_future(self._watchdog_loop(conn))
            self._watchdog_tasks[conn.ot_connection_id] = task

    def on_connection_ready(self, conn: IoConnection) -> None:
        """Override in subclasses to run code right after a new connection
        is established (before production/watchdog start)."""

    async def _production_loop(self, conn: IoConnection) -> None:
        interval = max(conn.to_rpi / 1_000_000.0, 0.001)
        try:
            while conn.state == ConnectionState.ESTABLISHED:
                await asyncio.sleep(interval)
                if conn.state != ConnectionState.ESTABLISHED:
                    break
                self.produce_io_data(conn)
        except asyncio.CancelledError:
            pass

    def produce_io_data(self, conn: IoConnection) -> None:
        """Build and send the cyclic T→O data frame. Subclasses override
        to inject safety framing (call super for the non-safety case)."""
        if self._udp is None or conn.remote_endpoint is None:
            return

        assembly = self.assemblies.get_assembly(conn.produced_assembly_instance)
        if assembly is None:
            return

        self.to_send_count += 1
        conn.encapsulation_sequence_number += 1

        if conn.transport_class == TransportClass.CLASS1:
            conn.cip_sequence_count = (conn.cip_sequence_count + 1) & 0xFFFF
            io_data = bytearray(2 + assembly.data_size)
            struct.pack_into('<H', io_data, 0, conn.cip_sequence_count)
            assembly.copy_data_to(io_data, 2)
        else:
            io_data = bytearray(assembly.data_size)
            assembly.copy_data_to(io_data)

        self._udp.send_io_data(conn.remote_endpoint, conn.to_connection_id,
                               conn.encapsulation_sequence_number, bytes(io_data))

    def send_udp_io_data(self, conn: IoConnection, payload: bytes) -> None:
        """Send a raw I/O payload (already encoded by the subclass) over UDP."""
        if self._udp is None or conn.remote_endpoint is None:
            return
        conn.encapsulation_sequence_number += 1
        self._udp.send_io_data(conn.remote_endpoint, conn.to_connection_id,
                               conn.encapsulation_sequence_number, payload)

    async def _watchdog_loop(self, conn: IoConnection) -> None:
        timeout_s = conn.connection_timeout_us / 1_000_000.0
        try:
            while conn.state == ConnectionState.ESTABLISHED:
                await asyncio.sleep(timeout_s)
                if conn.state != ConnectionState.ESTABLISHED:
                    break
                elapsed = (datetime.now(timezone.utc) - conn.last_received_utc).total_seconds()
                if elapsed > timeout_s:
                    self.connection_manager.timeout_connection(conn)
        except asyncio.CancelledError:
            pass

    def _on_udp_data_received(self, connection_id: int, data: bytes) -> None:
        conn = self.connection_manager.find_by_ot_id(connection_id)
        if conn is None or conn.state != ConnectionState.ESTABLISHED:
            return

        conn.last_received_utc = datetime.now(timezone.utc)
        self.handle_received_io_data(conn, data)

    def handle_received_io_data(self, conn: IoConnection, data: bytes) -> None:
        """Process raw O→T payload bytes. Subclasses override to inject
        safety frame decoding / TCOO handling."""
        # O→T Class 1: skip 2 seq + 4 run/idle
        if conn.transport_class == TransportClass.CLASS1 and len(data) >= 6:
            io_data = data[6:]
        else:
            io_data = data

        asm = self.assemblies.get_assembly(conn.consumed_assembly_instance)
        if asm:
            asm.set_data(io_data)

    def _on_udp_data_with_sender(self, connection_id: int, sender: tuple[str, int]) -> None:
        conn = self.connection_manager.find_by_ot_id(connection_id)
        if conn and conn.state == ConnectionState.ESTABLISHED:
            if conn.remote_endpoint is None or conn.remote_endpoint[1] != sender[1]:
                conn.remote_endpoint = sender
                self.on_remote_endpoint_updated(conn, sender)

    def on_remote_endpoint_updated(self, conn: IoConnection, sender: tuple[str, int]) -> None:
        """Override in subclasses to propagate the originator's UDP endpoint
        across related connections (used by SafetyDevice to share endpoint
        between client and server safety connections from the same scanner)."""
