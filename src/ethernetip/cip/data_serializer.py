"""CIP data type serialization — struct-based read/write for all CIP types.

Each read function returns the typed value from the given offset.
Each write function writes at the given offset and returns the number of bytes written.
All multi-byte values are little-endian.
"""

import struct
from .data_types import CipDataType


# --- Readers ---

def read_bool(src: bytes | bytearray | memoryview, offset: int = 0) -> bool:
    return src[offset] != 0

def read_sint(src: bytes | bytearray | memoryview, offset: int = 0) -> int:
    return struct.unpack_from('<b', src, offset)[0]

def read_int(src: bytes | bytearray | memoryview, offset: int = 0) -> int:
    return struct.unpack_from('<h', src, offset)[0]

def read_dint(src: bytes | bytearray | memoryview, offset: int = 0) -> int:
    return struct.unpack_from('<i', src, offset)[0]

def read_lint(src: bytes | bytearray | memoryview, offset: int = 0) -> int:
    return struct.unpack_from('<q', src, offset)[0]

def read_usint(src: bytes | bytearray | memoryview, offset: int = 0) -> int:
    return src[offset]

def read_uint(src: bytes | bytearray | memoryview, offset: int = 0) -> int:
    return struct.unpack_from('<H', src, offset)[0]

def read_udint(src: bytes | bytearray | memoryview, offset: int = 0) -> int:
    return struct.unpack_from('<I', src, offset)[0]

def read_ulint(src: bytes | bytearray | memoryview, offset: int = 0) -> int:
    return struct.unpack_from('<Q', src, offset)[0]

def read_real(src: bytes | bytearray | memoryview, offset: int = 0) -> float:
    return struct.unpack_from('<f', src, offset)[0]

def read_lreal(src: bytes | bytearray | memoryview, offset: int = 0) -> float:
    return struct.unpack_from('<d', src, offset)[0]

def read_short_string(src: bytes | bytearray | memoryview, offset: int = 0) -> str:
    length = src[offset]
    return bytes(src[offset + 1:offset + 1 + length]).decode('ascii')

def read_string(src: bytes | bytearray | memoryview, offset: int = 0) -> str:
    length = struct.unpack_from('<H', src, offset)[0]
    return bytes(src[offset + 2:offset + 2 + length]).decode('ascii')


# --- Writers (return bytes written) ---

def write_bool(dst: bytearray, offset: int, value: bool) -> int:
    dst[offset] = 1 if value else 0
    return 1

def write_sint(dst: bytearray, offset: int, value: int) -> int:
    struct.pack_into('<b', dst, offset, value)
    return 1

def write_int(dst: bytearray, offset: int, value: int) -> int:
    struct.pack_into('<h', dst, offset, value)
    return 2

def write_dint(dst: bytearray, offset: int, value: int) -> int:
    struct.pack_into('<i', dst, offset, value)
    return 4

def write_lint(dst: bytearray, offset: int, value: int) -> int:
    struct.pack_into('<q', dst, offset, value)
    return 8

def write_usint(dst: bytearray, offset: int, value: int) -> int:
    dst[offset] = value & 0xFF
    return 1

def write_uint(dst: bytearray, offset: int, value: int) -> int:
    struct.pack_into('<H', dst, offset, value)
    return 2

def write_udint(dst: bytearray, offset: int, value: int) -> int:
    struct.pack_into('<I', dst, offset, value)
    return 4

def write_ulint(dst: bytearray, offset: int, value: int) -> int:
    struct.pack_into('<Q', dst, offset, value)
    return 8

def write_real(dst: bytearray, offset: int, value: float) -> int:
    struct.pack_into('<f', dst, offset, value)
    return 4

def write_lreal(dst: bytearray, offset: int, value: float) -> int:
    struct.pack_into('<d', dst, offset, value)
    return 8

def write_short_string(dst: bytearray, offset: int, value: str) -> int:
    length = min(len(value), 255)
    dst[offset] = length
    dst[offset + 1:offset + 1 + length] = value[:length].encode('ascii')
    return 1 + length

def write_string(dst: bytearray, offset: int, value: str) -> int:
    length = min(len(value), 65535)
    struct.pack_into('<H', dst, offset, length)
    dst[offset + 2:offset + 2 + length] = value[:length].encode('ascii')
    return 2 + length


def get_fixed_size(data_type: CipDataType) -> int:
    """Returns the fixed size in bytes for a CIP data type, or -1 for variable-length types."""
    match data_type:
        case CipDataType.BOOL | CipDataType.SINT | CipDataType.USINT | CipDataType.BYTE:
            return 1
        case CipDataType.INT | CipDataType.UINT | CipDataType.WORD:
            return 2
        case CipDataType.DINT | CipDataType.UDINT | CipDataType.REAL | CipDataType.DWORD:
            return 4
        case CipDataType.LINT | CipDataType.ULINT | CipDataType.LREAL | CipDataType.LWORD:
            return 8
        case _:
            return -1
