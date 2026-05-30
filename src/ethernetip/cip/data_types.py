"""CIP data type codes matching the CIP specification type IDs."""

from enum import IntEnum


class CipDataType(IntEnum):
    BOOL = 0xC1        # 1 byte
    SINT = 0xC2        # Signed 8-bit
    INT = 0xC3         # Signed 16-bit
    DINT = 0xC4        # Signed 32-bit
    LINT = 0xC5        # Signed 64-bit
    USINT = 0xC6       # Unsigned 8-bit
    UINT = 0xC7        # Unsigned 16-bit
    UDINT = 0xC8       # Unsigned 32-bit
    ULINT = 0xC9       # Unsigned 64-bit
    REAL = 0xCA        # 32-bit IEEE float
    LREAL = 0xCB       # 64-bit IEEE double
    SHORT_STRING = 0xDA  # 1-byte length + ASCII
    STRING = 0xD0      # 2-byte length (UINT) + ASCII
    BYTE = 0xD1        # 8-bit bit string
    WORD = 0xD2        # 16-bit bit string
    DWORD = 0xD3       # 32-bit bit string
    LWORD = 0xD4       # 64-bit bit string
