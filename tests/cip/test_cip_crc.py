from ethernetip.cip.cip_crc import crc16


def test_matches_spec_vector_1():
    assert crc16(bytes([0xA2, 0x03, 0xC7, 0xC2, 0xC3])) == 0x5159


def test_matches_spec_vector_2():
    assert crc16(bytes([0xA2, 0x07, 0xC7, 0xA2, 0x03, 0xC7, 0xC2, 0xC3, 0xC3])) == 0x26C7


def test_empty_is_zero():
    assert crc16(b"") == 0


def test_single_zero_byte_stays_zero():
    assert crc16(b"\x00") == 0
