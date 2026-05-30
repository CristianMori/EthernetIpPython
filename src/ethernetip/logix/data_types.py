"""Logix CIP tag type constants and utilities."""

# Atomic tag type values
BOOL = 0x00C1
SINT = 0x00C2
INT = 0x00C3
DINT = 0x00C4
LINT = 0x00C5
REAL = 0x00CA
LREAL = 0x00CB
DWORD = 0x00D3

# Logix STRING structure layout
STRING_STRUCTURE_SIZE = 88
STRING_LEN_OFFSET = 0
STRING_DATA_OFFSET = 4
STRING_MAX_LENGTH = 82


def get_element_size(tag_type: int) -> int:
    """Returns byte size of an atomic tag type, or -1 if unknown/structure."""
    base_type = tag_type & 0x00FF
    return {
        0xC1: 1, 0xC2: 1, 0xC3: 2, 0xC4: 4,
        0xC5: 8, 0xCA: 4, 0xCB: 8, 0xD3: 4,
    }.get(base_type, -1)


def make_atomic_symbol_type(tag_type: int, array_dims: int = 0) -> int:
    symbol_type = tag_type & 0x00FF
    symbol_type |= (array_dims & 0x03) << 13
    return symbol_type


def make_struct_symbol_type(template_instance_id: int, array_dims: int = 0) -> int:
    symbol_type = 0x8000 | (template_instance_id & 0x0FFF)
    symbol_type |= (array_dims & 0x03) << 13
    return symbol_type


def is_struct(symbol_type: int) -> bool:
    return bool(symbol_type & 0x8000)


def is_system(symbol_type: int) -> bool:
    return bool(symbol_type & 0x1000)


def get_array_dims(symbol_type: int) -> int:
    return (symbol_type >> 13) & 0x03


def get_template_id(symbol_type: int) -> int:
    return symbol_type & 0x0FFF


def is_logix_string(template_name: str) -> bool:
    return (template_name.upper().startswith("STRING") and
            (len(template_name) == 6 or template_name[6] == ';'))
