"""Integration tests for Logix dispatcher + tag services over TCP loopback."""

import struct
import pytest

from ethernetip.cip.identity_info import IdentityInfo
from ethernetip.logix.logix_dispatcher import LogixDispatcher
from ethernetip.logix.tag_database import TagDatabase
from ethernetip.logix import data_types as dt
from ethernetip.protocol.eip_adapter import EipAdapter
from ethernetip.protocol.eip_scanner import EipScanner


def _make_dispatcher():
    tags = TagDatabase()
    tags.add_tag("ADint", dt.DINT)
    tags.add_tag("AReal", dt.REAL)
    tags.add_tag("MyArray", dt.DINT, element_count=10)
    identity = IdentityInfo(product_name="PyLogix Test")
    dispatcher = LogixDispatcher(tags, identity)
    return dispatcher, tags


def _symbolic_path(name: str) -> bytes:
    """Build a symbolic EPATH for a tag name."""
    name_bytes = name.encode('ascii')
    path = bytearray([0x91, len(name_bytes)])
    path += name_bytes
    if len(name_bytes) % 2 != 0:
        path += b'\x00'
    return bytes(path)


# --- Direct dispatch tests (no TCP) ---

def test_read_write_dint_direct():
    dispatcher, tags = _make_dispatcher()
    tag = tags.find_by_name("ADint")
    tag.set_data(struct.pack('<i', 42))

    from ethernetip.cip.path import CipPath
    path = CipPath(symbolic_name="ADint")
    resp = dispatcher.dispatch(0x4C, path, struct.pack('<H', 1))  # Read 1 element
    assert resp.status.is_success
    assert struct.unpack_from('<H', resp.data, 0)[0] == dt.DINT  # tag type
    assert struct.unpack_from('<i', resp.data, 2)[0] == 42


def test_write_tag_direct():
    dispatcher, tags = _make_dispatcher()

    from ethernetip.cip.path import CipPath
    path = CipPath(symbolic_name="ADint")
    write_data = struct.pack('<HH', dt.DINT, 1) + struct.pack('<i', 99)
    resp = dispatcher.dispatch(0x4D, path, write_data)
    assert resp.status.is_success

    tag = tags.find_by_name("ADint")
    assert tag.read_dint() == 99


def test_read_real_direct():
    dispatcher, tags = _make_dispatcher()
    tag = tags.find_by_name("AReal")
    tag.set_data(struct.pack('<f', 3.14))

    from ethernetip.cip.path import CipPath
    path = CipPath(symbolic_name="AReal")
    resp = dispatcher.dispatch(0x4C, path, struct.pack('<H', 1))
    assert resp.status.is_success
    val = struct.unpack_from('<f', resp.data, 2)[0]
    assert abs(val - 3.14) < 0.001


def test_unknown_tag():
    dispatcher, _ = _make_dispatcher()
    from ethernetip.cip.path import CipPath
    path = CipPath(symbolic_name="NonExistent")
    resp = dispatcher.dispatch(0x4C, path, struct.pack('<H', 1))
    assert resp.status.general_status == 0x05


# --- TCP loopback tests ---

@pytest.mark.asyncio
async def test_read_write_over_tcp():
    dispatcher, tags = _make_dispatcher()
    tags.find_by_name("ADint").set_data(struct.pack('<i', 123))

    adapter = EipAdapter(dispatcher, IdentityInfo())
    await adapter.listen('127.0.0.1', 0)

    try:
        scanner = EipScanner()
        await scanner.connect('127.0.0.1', adapter.port)

        # Read via Unconnected Send wrapping symbolic Read Tag
        sym_path = _symbolic_path("ADint")
        read_data = struct.pack('<H', 1)  # 1 element

        # Build Unconnected Send (0x52) to Connection Manager
        inner_mr = bytes([0x4C, len(sym_path) // 2]) + sym_path + read_data
        uc_data = bytearray(4 + len(inner_mr) + 2)
        uc_data[0] = 0x0A; uc_data[1] = 0x05
        struct.pack_into('<H', uc_data, 2, len(inner_mr))
        uc_data[4:4 + len(inner_mr)] = inner_mr

        cm_path = bytes([0x20, 0x06, 0x24, 0x01])
        resp = await scanner.send_explicit(0x52, cm_path, bytes(uc_data))
        assert resp.status.is_success
        assert struct.unpack_from('<i', resp.data, 2)[0] == 123

        # Write via Unconnected Send
        write_payload = struct.pack('<HHi', dt.DINT, 1, 456)
        inner_mr_w = bytes([0x4D, len(sym_path) // 2]) + sym_path + write_payload
        uc_data_w = bytearray(4 + len(inner_mr_w) + 2)
        uc_data_w[0] = 0x0A; uc_data_w[1] = 0x05
        struct.pack_into('<H', uc_data_w, 2, len(inner_mr_w))
        uc_data_w[4:4 + len(inner_mr_w)] = inner_mr_w

        resp_w = await scanner.send_explicit(0x52, cm_path, bytes(uc_data_w))
        assert resp_w.status.is_success

        # Verify write
        assert tags.find_by_name("ADint").read_dint() == 456

        await scanner.close()
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_identity_over_tcp():
    dispatcher, _ = _make_dispatcher()
    adapter = EipAdapter(dispatcher, IdentityInfo(product_name="PyLogix"))
    await adapter.listen('127.0.0.1', 0)

    try:
        scanner = EipScanner()
        await scanner.connect('127.0.0.1', adapter.port)

        # Read product name via Identity class (through Unconnected Send)
        id_path = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x07])
        inner_mr = bytes([0x0E, len(id_path) // 2]) + id_path
        uc_data = bytearray(4 + len(inner_mr) + 2)
        uc_data[0] = 0x0A; uc_data[1] = 0x05
        struct.pack_into('<H', uc_data, 2, len(inner_mr))
        uc_data[4:4 + len(inner_mr)] = inner_mr

        cm_path = bytes([0x20, 0x06, 0x24, 0x01])
        resp = await scanner.send_explicit(0x52, cm_path, bytes(uc_data))
        assert resp.status.is_success
        assert b'PyLogix' in resp.data

        await scanner.close()
    finally:
        await adapter.close()
