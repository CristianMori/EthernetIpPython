"""CIP 16-bit CRC (polynomial 0xA001, initial 0, right-shift with XOR).

Same math as CRC-16/ARC (reversed 0x8005). Matches the reference
implementation in the CIP spec's polynomial-driven algorithm; passes the
spec's own test vectors:

    >>> from ethernetip.cip.cip_crc import crc16
    >>> hex(crc16(b'\\xA2\\x03\\xC7\\xC2\\xC3'))
    '0x5159'
    >>> hex(crc16(b'\\xA2\\x07\\xC7\\xA2\\x03\\xC7\\xC2\\xC3\\xC3'))
    '0x26c7'
"""

from __future__ import annotations


def crc16(data: bytes | bytearray | memoryview) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            carry = crc & 1
            crc >>= 1
            if carry:
                crc ^= 0xA001
    return crc
