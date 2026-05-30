"""Tests for Common Packet Format codec."""

from ethernetip.cip.cpf import CpfItemType, CpfItem, parse_cpf, write_cpf, encode_cpf


def test_parse_null_address_and_unconnected():
    # 2 items: NullAddress(0 bytes) + UnconnectedData(4 bytes)
    data = bytearray([
        0x02, 0x00,  # item count = 2
        0x00, 0x00, 0x00, 0x00,  # NullAddress, length=0
        0xB2, 0x00, 0x04, 0x00,  # UnconnectedData, length=4
        0x0E, 0x03, 0x20, 0x01,  # data bytes
    ])
    items = parse_cpf(data)
    assert len(items) == 2
    assert items[0].type_id == CpfItemType.NULL_ADDRESS
    assert items[0].data == b''
    assert items[1].type_id == CpfItemType.UNCONNECTED_DATA
    assert items[1].data == bytes([0x0E, 0x03, 0x20, 0x01])


def test_round_trip():
    items = [
        CpfItem(CpfItemType.NULL_ADDRESS, b''),
        CpfItem(CpfItemType.UNCONNECTED_DATA, b'\x01\x02\x03'),
    ]
    encoded = encode_cpf(items)
    parsed = parse_cpf(encoded)
    assert len(parsed) == 2
    assert parsed[0].type_id == items[0].type_id
    assert parsed[1].data == items[1].data


def test_parse_empty():
    assert parse_cpf(b'') == []
    assert parse_cpf(b'\x00') == []


def test_parse_truncated_item():
    # Claims 1 item but data is truncated
    data = bytes([0x01, 0x00, 0xB2, 0x00, 0x10, 0x00])  # says 16 bytes but none follow
    items = parse_cpf(data)
    assert len(items) == 0


def test_write_cpf():
    items = [CpfItem(CpfItemType.CONNECTED_ADDRESS, b'\x01\x02\x03\x04')]
    buf = bytearray(10)
    n = write_cpf(buf, 0, items)
    assert n == 10
    parsed = parse_cpf(buf[:n])
    assert len(parsed) == 1
    assert parsed[0].type_id == CpfItemType.CONNECTED_ADDRESS
    assert parsed[0].data == b'\x01\x02\x03\x04'
