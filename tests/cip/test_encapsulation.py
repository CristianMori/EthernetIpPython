"""Tests for encapsulation header codec."""

from ethernetip.cip.encapsulation import (
    EncapsulationHeader, EncapsulationCommand, EncapsulationStatus, SIZE,
)


def test_parse_register_session():
    buf = bytearray(SIZE)
    buf[0:2] = b'\x65\x00'  # RegisterSession
    buf[2:4] = b'\x04\x00'  # length=4
    buf[4:8] = b'\xAB\x00\x00\x00'  # session=0xAB
    header = EncapsulationHeader.parse(buf)
    assert header.command == EncapsulationCommand.REGISTER_SESSION
    assert header.length == 4
    assert header.session_handle == 0xAB
    assert header.status == EncapsulationStatus.SUCCESS


def test_round_trip():
    original = EncapsulationHeader(
        command=EncapsulationCommand.SEND_RR_DATA,
        length=42,
        session_handle=0xDEADBEEF,
        status=EncapsulationStatus.SUCCESS,
        sender_context=0x1234567890ABCDEF,
        options=0,
    )
    data = original.to_bytes()
    assert len(data) == SIZE
    parsed = EncapsulationHeader.parse(data)
    assert parsed.command == original.command
    assert parsed.length == original.length
    assert parsed.session_handle == original.session_handle
    assert parsed.sender_context == original.sender_context


def test_write_to_buffer():
    header = EncapsulationHeader(
        command=EncapsulationCommand.LIST_IDENTITY,
        length=0,
    )
    buf = bytearray(SIZE)
    n = header.write_to(buf)
    assert n == SIZE
    assert buf[0:2] == b'\x63\x00'
