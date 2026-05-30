"""Generates Python dataclasses from Logix TemplateInfo definitions."""

from __future__ import annotations
from .tag_client import TemplateInfo
from . import data_types as dt


def generate_udt_class(template: TemplateInfo, class_name: str | None = None) -> str:
    """Generate a Python dataclass source code string from a TemplateInfo.

    The generated class has:
    - Properties for each member with correct types
    - to_bytes() method for serialization
    - from_bytes() class method for deserialization
    - structure_handle and structure_size properties
    """
    name = class_name or _sanitize_name(template.name)
    lines = [
        "import struct",
        "from dataclasses import dataclass",
        "",
        "",
        f"@dataclass",
        f"class {name}:",
        f'    """Generated from Logix template: {template.name} ({template.structure_size} bytes)"""',
        f"",
        f"    STRUCTURE_HANDLE: int = {template.structure_handle}",
        f"    STRUCTURE_SIZE: int = {template.structure_size}",
        "",
    ]

    # Fields
    for m in template.members:
        if m.name.startswith("ZZZZZZZZZZ") or m.name.startswith("__") or not m.name:
            continue

        py_type, default = _member_type(m.data_type, m.info, m.is_array)
        field_name = _sanitize_name(m.name)
        lines.append(f"    {field_name}: {py_type} = {default}")

    lines.append("")

    # to_bytes
    lines.append(f"    def to_bytes(self) -> bytes:")
    lines.append(f"        buf = bytearray({template.structure_size})")
    for m in template.members:
        if m.name.startswith("ZZZZZZZZZZ") or m.name.startswith("__") or not m.name:
            continue
        field_name = _sanitize_name(m.name)
        _emit_pack(lines, m, field_name)
    lines.append(f"        return bytes(buf)")
    lines.append("")

    # from_bytes
    lines.append(f"    @classmethod")
    lines.append(f"    def from_bytes(cls, data: bytes) -> '{name}':")
    lines.append(f"        obj = cls()")
    for m in template.members:
        if m.name.startswith("ZZZZZZZZZZ") or m.name.startswith("__") or not m.name:
            continue
        field_name = _sanitize_name(m.name)
        _emit_unpack(lines, m, field_name)
    lines.append(f"        return obj")
    lines.append("")

    # structure properties
    lines.append(f"    @property")
    lines.append(f"    def structure_handle(self) -> int:")
    lines.append(f"        return self.STRUCTURE_HANDLE")
    lines.append("")
    lines.append(f"    @property")
    lines.append(f"    def structure_size(self) -> int:")
    lines.append(f"        return self.STRUCTURE_SIZE")

    return "\n".join(lines)


def _member_type(data_type: int, info: int, is_array: bool) -> tuple[str, str]:
    if data_type == 0x00C1:  # BOOL
        return "bool", "False"

    base = data_type & 0x00FF
    if is_array:
        py = _atomic_type(base)
        return f"list[{py}]", "None"

    match base:
        case 0xC2: return "int", "0"
        case 0xC3: return "int", "0"
        case 0xC4: return "int", "0"
        case 0xC5: return "int", "0"
        case 0xCA: return "float", "0.0"
        case 0xCB: return "float", "0.0"
        case _:
            if data_type & 0x8000:
                return "bytes", "b''"
            return "int", "0"


def _atomic_type(base: int) -> str:
    match base:
        case 0xC2 | 0xC3 | 0xC4 | 0xC5: return "int"
        case 0xCA | 0xCB: return "float"
        case _: return "int"


def _struct_fmt(base: int) -> str:
    match base:
        case 0xC2: return "b"
        case 0xC3: return "h"
        case 0xC4: return "i"
        case 0xC5: return "q"
        case 0xCA: return "f"
        case 0xCB: return "d"
        case _: return "i"


def _emit_pack(lines: list[str], m, field_name: str) -> None:
    if m.data_type == 0x00C1:
        lines.append(f"        if self.{field_name}:")
        lines.append(f"            buf[{m.offset}] |= (1 << {m.info})")
        return

    base = m.data_type & 0x00FF
    fmt = _struct_fmt(base)

    if m.is_array:
        elem_size = dt.get_element_size(m.data_type & 0x00FF)
        if elem_size < 0:
            elem_size = 4
        lines.append(f"        if self.{field_name}:")
        lines.append(f"            for _i, _v in enumerate(self.{field_name}[:{m.info}]):")
        lines.append(f"                struct.pack_into('<{fmt}', buf, {m.offset} + _i * {elem_size}, _v)")
    else:
        lines.append(f"        struct.pack_into('<{fmt}', buf, {m.offset}, self.{field_name})")


def _emit_unpack(lines: list[str], m, field_name: str) -> None:
    if m.data_type == 0x00C1:
        lines.append(f"        obj.{field_name} = bool(data[{m.offset}] & (1 << {m.info}))")
        return

    base = m.data_type & 0x00FF
    fmt = _struct_fmt(base)

    if m.is_array:
        elem_size = dt.get_element_size(m.data_type & 0x00FF)
        if elem_size < 0:
            elem_size = 4
        lines.append(f"        obj.{field_name} = [struct.unpack_from('<{fmt}', data, {m.offset} + _i * {elem_size})[0] for _i in range({m.info})]")
    else:
        lines.append(f"        obj.{field_name} = struct.unpack_from('<{fmt}', data, {m.offset})[0]")


def _sanitize_name(name: str) -> str:
    name = name.replace(':', '_').replace(' ', '_').replace('-', '_')
    if name and name[0].isdigit():
        name = '_' + name
    return name
