"""Integration tests for EIP adapter + scanner over TCP loopback."""

import asyncio
import pytest

from ethernetip.cip.dispatcher import CipDispatcher
from ethernetip.cip.cip_class import CipClass
from ethernetip.cip.attribute import CipAttribute, AttributeAccess
from ethernetip.cip.data_types import CipDataType
from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.protocol.eip_adapter import EipAdapter
from ethernetip.protocol.eip_scanner import EipScanner
from ethernetip.connections.connection_manager import ConnectionManagerObject


def _make_dispatcher():
    """Create a dispatcher with Identity and Connection Manager."""
    dispatcher = CipDispatcher()

    # Identity class (0x01)
    id_class = CipClass(0x01, "Identity")
    id_class.add_standard_instance_services()
    inst = id_class.create_instance(1)
    inst.add_attribute(CipAttribute.create_uint(1, CipDataType.UINT, AttributeAccess.ALL, 0x0001))
    inst.add_attribute(CipAttribute.create_uint(2, CipDataType.UINT, AttributeAccess.ALL, 0x000C))
    inst.add_attribute(CipAttribute.create_uint(3, CipDataType.UINT, AttributeAccess.ALL, 0x0001))
    inst.add_attribute(CipAttribute(4, CipDataType.USINT, AttributeAccess.ALL, bytes([1, 0])))
    inst.add_attribute(CipAttribute.create_uint(5, CipDataType.WORD, AttributeAccess.ALL, 0x0000))
    inst.add_attribute(CipAttribute.create_udint(6, CipDataType.UDINT, AttributeAccess.ALL, 0xC0FFEE42))
    inst.add_attribute(CipAttribute.create_short_string(7, AttributeAccess.ALL, "PyEIP Test"))
    dispatcher.register_class(id_class)

    # Connection Manager (0x06)
    cm = ConnectionManagerObject()
    cm.dispatch_request = dispatcher.dispatch
    dispatcher.register_class(cm.cip_class)

    return dispatcher


@pytest.mark.asyncio
async def test_register_session_and_read_identity():
    dispatcher = _make_dispatcher()
    identity = IdentityInfo(product_name="PyEIP Test")
    adapter = EipAdapter(dispatcher, identity)

    await adapter.listen('127.0.0.1', 0)  # ephemeral port
    port = adapter.port

    try:
        scanner = EipScanner()
        await scanner.connect('127.0.0.1', port)

        assert scanner.is_connected
        assert scanner.session_handle > 0

        # Read Identity vendor ID (attr 1)
        path = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x01])
        resp = await scanner.send_explicit(0x0E, path)
        assert resp.status.is_success
        assert resp.data == b'\x01\x00'  # vendor ID = 0x0001

        # Read Identity product name (attr 7)
        path7 = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x07])
        resp7 = await scanner.send_explicit(0x0E, path7)
        assert resp7.status.is_success
        assert b'PyEIP Test' in resp7.data

        await scanner.close()
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_get_attribute_all():
    dispatcher = _make_dispatcher()
    identity = IdentityInfo()
    adapter = EipAdapter(dispatcher, identity)

    await adapter.listen('127.0.0.1', 0)
    port = adapter.port

    try:
        scanner = EipScanner()
        await scanner.connect('127.0.0.1', port)

        path = bytes([0x20, 0x01, 0x24, 0x01])
        resp = await scanner.send_explicit(0x01, path)
        assert resp.status.is_success
        assert len(resp.data) > 0

        await scanner.close()
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_invalid_class():
    dispatcher = _make_dispatcher()
    identity = IdentityInfo()
    adapter = EipAdapter(dispatcher, identity)

    await adapter.listen('127.0.0.1', 0)
    port = adapter.port

    try:
        scanner = EipScanner()
        await scanner.connect('127.0.0.1', port)

        path = bytes([0x20, 0xFF, 0x24, 0x01, 0x30, 0x01])
        resp = await scanner.send_explicit(0x0E, path)
        assert not resp.status.is_success
        assert resp.status.general_status == 0x05  # PATH_DESTINATION_UNKNOWN

        await scanner.close()
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_set_and_read_back():
    dispatcher = _make_dispatcher()
    identity = IdentityInfo()
    adapter = EipAdapter(dispatcher, identity)

    await adapter.listen('127.0.0.1', 0)
    port = adapter.port

    try:
        scanner = EipScanner()
        await scanner.connect('127.0.0.1', port)

        # Write vendor ID to 0x42
        path = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x01])
        resp = await scanner.send_explicit(0x10, path, b'\x42\x00')
        assert resp.status.is_success

        # Read back
        resp2 = await scanner.send_explicit(0x0E, path)
        assert resp2.data == b'\x42\x00'

        await scanner.close()
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_unconnected_send():
    dispatcher = _make_dispatcher()
    identity = IdentityInfo()
    adapter = EipAdapter(dispatcher, identity)

    await adapter.listen('127.0.0.1', 0)
    port = adapter.port

    try:
        scanner = EipScanner()
        await scanner.connect('127.0.0.1', port)

        # Build an Unconnected Send that wraps GetAttributeSingle on Identity attr 1
        inner_path = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x01])
        inner_mr = bytes([0x0E, len(inner_path) // 2]) + inner_path

        # Unconnected Send data: priority(1) + timeout(1) + msg_length(2) + embedded MR + pad + route
        import struct
        uc_data = bytearray(4 + len(inner_mr) + 2)
        uc_data[0] = 0x0A  # priority
        uc_data[1] = 0x05  # timeout
        struct.pack_into('<H', uc_data, 2, len(inner_mr))
        uc_data[4:4 + len(inner_mr)] = inner_mr
        # pad + route_path_size=0 + reserved
        uc_data[4 + len(inner_mr)] = 0
        uc_data[4 + len(inner_mr) + 1] = 0

        cm_path = bytes([0x20, 0x06, 0x24, 0x01])
        resp = await scanner.send_explicit(0x52, cm_path, bytes(uc_data))
        assert resp.status.is_success
        assert resp.data == b'\x01\x00'  # vendor ID

        await scanner.close()
    finally:
        await adapter.close()
