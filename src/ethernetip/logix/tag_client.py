"""TagClient — TCP client for reading/writing Logix tags over EtherNet/IP.

Pure TCP, no UDP, no Forward Open. Connects, registers session, sends CIP
explicit messages via UCMM (SendRRData).

Usage:
    client = TagClient("192.168.1.10")
    await client.connect()
    val = await client.read_dint("rate")
    await client.write_dint("rate", 9999)
    tags = await client.browse_tags()
    await client.disconnect()
"""

from __future__ import annotations
import asyncio
import struct
from dataclasses import dataclass, field

from ..cip.encapsulation import (
    EncapsulationHeader, EncapsulationCommand, EncapsulationStatus, SIZE as HEADER_SIZE,
)
from ..cip.cpf import CpfItem, CpfItemType, parse_cpf, encode_cpf
from ..cip import mr_codec
from . import data_types as dt

EIP_PORT = 44818


class TagClient:
    """Client for reading/writing Logix tags over EtherNet/IP."""

    def __init__(self, host: str, port: int = EIP_PORT):
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._lock = asyncio.Lock()
        self.session_handle: int = 0
        self._last_header: EncapsulationHeader | None = None

    @property
    def is_connected(self) -> bool:
        return self._writer is not None and self.session_handle != 0

    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.open_connection(self._host, self._port)
        self.session_handle = await self._register_session()

    async def disconnect(self) -> None:
        if self._writer and self.session_handle:
            try:
                header = EncapsulationHeader(
                    command=EncapsulationCommand.UNREGISTER_SESSION,
                    session_handle=self.session_handle,
                )
                self._writer.write(header.to_bytes())
                await self._writer.drain()
            except Exception:
                pass
        self.session_handle = 0
        if self._writer:
            self._writer.close()
        self._reader = None
        self._writer = None

    async def close(self) -> None:
        await self.disconnect()

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *exc):
        await self.close()

    # --- Read operations ---

    async def read_tag_raw(self, tag_name: str, element_count: int = 1) -> bytes:
        """Read a tag and return raw response (tag_type + data bytes)."""
        path = _build_symbolic_path(tag_name)
        req_data = struct.pack('<H', element_count)
        return await self._send_cip(0x4C, path, req_data)

    async def read_dint(self, tag_name: str) -> int:
        raw = await self.read_tag_raw(tag_name, 1)
        return struct.unpack_from('<i', raw, 2)[0]

    async def read_real(self, tag_name: str) -> float:
        raw = await self.read_tag_raw(tag_name, 1)
        return struct.unpack_from('<f', raw, 2)[0]

    async def read_int(self, tag_name: str) -> int:
        raw = await self.read_tag_raw(tag_name, 1)
        return struct.unpack_from('<h', raw, 2)[0]

    async def read_sint(self, tag_name: str) -> int:
        raw = await self.read_tag_raw(tag_name, 1)
        return struct.unpack_from('<b', raw, 2)[0]

    async def read_lint(self, tag_name: str) -> int:
        raw = await self.read_tag_raw(tag_name, 1)
        return struct.unpack_from('<q', raw, 2)[0]

    async def read_lreal(self, tag_name: str) -> float:
        raw = await self.read_tag_raw(tag_name, 1)
        return struct.unpack_from('<d', raw, 2)[0]

    async def read_string(self, tag_name: str) -> str:
        """Read a Logix STRING tag (UDT: LEN(DINT) + DATA(SINT[82]))."""
        raw = await self.read_tag_raw(tag_name, 1)
        header_size = 4  # tag_type(2) + struct_handle(2)
        if len(raw) < header_size + dt.STRING_DATA_OFFSET:
            return ""
        length = struct.unpack_from('<i', raw, header_size + dt.STRING_LEN_OFFSET)[0]
        if length <= 0:
            return ""
        max_len = min(length, dt.STRING_MAX_LENGTH, len(raw) - header_size - dt.STRING_DATA_OFFSET)
        return raw[header_size + dt.STRING_DATA_OFFSET:header_size + dt.STRING_DATA_OFFSET + max_len].decode('ascii')

    async def read_struct(self, tag_name: str, template: TemplateInfo) -> StructureValue:
        """Read a structure tag using fragmented reads for large structures."""
        path = _build_symbolic_path(tag_name)
        all_data = bytearray()
        byte_offset = 0
        tag_type_header = b''

        while True:
            req_data = struct.pack('<HI', 1, byte_offset)  # 1 element, offset
            status, data = await self._send_cip_with_status(0x52, path, req_data)  # Read Tag Fragmented

            if status not in (0x00, 0x06):
                raise RuntimeError(f"Read struct failed: status=0x{status:02X}")

            if not tag_type_header and len(data) >= 4:
                tag_type_header = data[:4]  # tag_type(2) + struct_handle(2)
                data = data[4:]
            elif tag_type_header and len(data) >= 2:
                data = data[2:]  # skip tag_type on subsequent fragments

            all_data += data
            byte_offset += len(data)

            if status == 0x00:
                break

        return StructureValue(template, bytearray(all_data))

    # --- Write operations ---

    async def write_dint(self, tag_name: str, value: int) -> None:
        path = _build_symbolic_path(tag_name)
        data = struct.pack('<HHi', dt.DINT, 1, value)
        await self._send_cip(0x4D, path, data)

    async def write_real(self, tag_name: str, value: float) -> None:
        path = _build_symbolic_path(tag_name)
        data = struct.pack('<HHf', dt.REAL, 1, value)
        await self._send_cip(0x4D, path, data)

    async def write_int(self, tag_name: str, value: int) -> None:
        path = _build_symbolic_path(tag_name)
        data = struct.pack('<HHh', dt.INT, 1, value)
        await self._send_cip(0x4D, path, data)

    async def write_sint(self, tag_name: str, value: int) -> None:
        path = _build_symbolic_path(tag_name)
        data = struct.pack('<HHb', dt.SINT, 1, value)
        await self._send_cip(0x4D, path, data)

    async def write_lint(self, tag_name: str, value: int) -> None:
        path = _build_symbolic_path(tag_name)
        data = struct.pack('<HHq', dt.LINT, 1, value)
        await self._send_cip(0x4D, path, data)

    async def write_lreal(self, tag_name: str, value: float) -> None:
        path = _build_symbolic_path(tag_name)
        data = struct.pack('<HHd', dt.LREAL, 1, value)
        await self._send_cip(0x4D, path, data)

    async def write_raw(self, tag_name: str, tag_type: int, element_count: int, value: bytes) -> None:
        path = _build_symbolic_path(tag_name)
        data = struct.pack('<HH', tag_type, element_count) + value
        await self._send_cip(0x4D, path, data)

    async def write_string(self, tag_name: str, value: str, structure_handle: int) -> None:
        """Write a Logix STRING tag."""
        str_bytes = value.encode('ascii')
        length = min(len(str_bytes), dt.STRING_MAX_LENGTH)
        struct_data = bytearray(dt.STRING_STRUCTURE_SIZE)
        struct.pack_into('<i', struct_data, 0, length)
        struct_data[dt.STRING_DATA_OFFSET:dt.STRING_DATA_OFFSET + length] = str_bytes[:length]
        await self.write_struct(tag_name, structure_handle, 1, bytes(struct_data))

    async def write_struct(self, tag_name: str, structure_handle: int,
                           element_count: int, value: bytes) -> None:
        """Write a structure tag (uses 0x02A0 + struct_handle tag type)."""
        path = _build_symbolic_path(tag_name)
        data = struct.pack('<HHH', 0x02A0, structure_handle, element_count) + value
        await self._send_cip(0x4D, path, data)

    async def write_struct_value(self, tag_name: str, value: StructureValue) -> None:
        await self.write_struct(tag_name, value.template.structure_handle, 1, value.to_bytes())

    # --- Multiple tag operations ---

    async def read_multiple(self, tag_names: list[str]) -> dict[str, bytes]:
        """Read multiple tags in one request using Multiple Service Packet (0x0A)."""
        if not tag_names:
            return {}

        sub_requests = []
        for name in tag_names:
            path = _build_symbolic_path(name)
            req_data = b'\x01\x00'  # 1 element
            mr = bytes([0x4C, len(path) // 2]) + path + req_data
            sub_requests.append(mr)

        responses = await self._send_multi_service(sub_requests)

        result = {}
        for i, name in enumerate(tag_names):
            if i < len(responses):
                status, data = responses[i]
                if status in (0x00, 0x06):
                    result[name] = data
        return result

    async def write_multiple(self, writes: list[tuple[str, int, bytes]]) -> dict[str, bool]:
        """Write multiple atomic tags. Each entry: (tag_name, tag_type, value_bytes)."""
        if not writes:
            return {}

        sub_requests = []
        for name, tag_type, value in writes:
            path = _build_symbolic_path(name)
            write_data = struct.pack('<HH', tag_type, 1) + value
            mr = bytes([0x4D, len(path) // 2]) + path + write_data
            sub_requests.append(mr)

        responses = await self._send_multi_service(sub_requests)

        result = {}
        for i, (name, _, _) in enumerate(writes):
            if i < len(responses):
                result[name] = responses[i][0] == 0x00
        return result

    # --- Browse and template ---

    async def browse_tags(self) -> TagBrowseResult:
        """Browse all tags (controller + program scope) and resolve templates."""
        tags = await self._browse_symbols(None)

        programs = [t.name for t in tags if t.name.startswith("Program:") and '.' not in t.name]
        for program in programs:
            ptags = await self._browse_symbols(program)
            for t in ptags:
                t.name = f"{program}.{t.name}"
            tags.extend(ptags)

        templates: dict[int, TemplateInfo] = {}
        template_ids = set(t.type_code for t in tags if t.is_struct)
        for tid in template_ids:
            try:
                templates[tid] = await self.read_template(tid)
            except Exception:
                pass

        for tag in tags:
            if tag.is_struct and tag.type_code in templates:
                tag.template = templates[tag.type_code]

        return TagBrowseResult(tags=tags, templates=templates)

    async def read_template(self, template_instance_id: int) -> TemplateInfo:
        """Read a template definition from the controller."""
        # Get attributes (1=handle, 2=member_count, 4=def_size, 5=struct_size)
        attr_path = bytes([0x20, 0x6C, 0x25, 0x00]) + struct.pack('<H', template_instance_id)
        attr_req = struct.pack('<HHHHH', 4, 1, 2, 4, 5)
        attr_data = await self._send_cip(0x03, attr_path, attr_req)

        off = 2  # skip count
        struct_handle = member_count = 0
        definition_size = structure_size = 0

        for _ in range(4):
            if off + 4 > len(attr_data):
                break
            attr_id = struct.unpack_from('<H', attr_data, off)[0]; off += 2
            attr_status = struct.unpack_from('<H', attr_data, off)[0]; off += 2
            if attr_status != 0:
                continue
            if attr_id == 1:
                struct_handle = struct.unpack_from('<H', attr_data, off)[0]; off += 2
            elif attr_id == 2:
                member_count = struct.unpack_from('<H', attr_data, off)[0]; off += 2
            elif attr_id == 4:
                definition_size = struct.unpack_from('<I', attr_data, off)[0]; off += 4
            elif attr_id == 5:
                structure_size = struct.unpack_from('<I', attr_data, off)[0]; off += 4

        # Template Read (0x4C) — fragmented
        # Request: byte_offset(UDINT) + byte_count(UINT)
        read_size = (definition_size * 4) - 23
        if read_size <= 0:
            read_size = definition_size * 4
        all_def_data = bytearray()
        read_offset = 0

        while True:
            remaining = read_size - read_offset
            read_req = struct.pack('<IH', read_offset, min(remaining, 65535))
            status, chunk = await self._send_cip_with_status(0x4C, attr_path, read_req)
            if status not in (0x00, 0x06):
                break
            all_def_data += chunk
            read_offset += len(chunk)
            if status == 0x00:
                break

        # Parse members
        members: list[TemplateMemberDetail] = []
        off = 0
        for _ in range(member_count):
            if off + 8 > len(all_def_data):
                break
            type_and_info = struct.unpack_from('<I', all_def_data, off)[0]; off += 4
            member_offset = struct.unpack_from('<I', all_def_data, off)[0]; off += 4
            members.append(TemplateMemberDetail(
                data_type=(type_and_info >> 16) & 0xFFFF,
                info=type_and_info & 0xFFFF,
                offset=member_offset,
            ))

        # Parse names (null-terminated)
        names: list[str] = []
        while off < len(all_def_data):
            end = all_def_data.find(0, off)
            if end < 0:
                break
            if end > off:
                names.append(all_def_data[off:end].decode('ascii', errors='replace'))
            off = end + 1

        template_name = names[0] if names else ""
        for i, m in enumerate(members):
            if i + 1 < len(names):
                m.name = names[i + 1]

        return TemplateInfo(
            instance_id=template_instance_id, name=template_name,
            structure_handle=struct_handle, member_count=member_count,
            definition_size=definition_size, structure_size=structure_size,
            members=members,
        )

    # --- Private helpers ---

    async def _send_cip(self, service_code: int, cip_path: bytes, service_data: bytes) -> bytes:
        status, data = await self._send_cip_with_status(service_code, cip_path, service_data)
        if status not in (0x00, 0x06):
            raise RuntimeError(f"CIP error: service=0x{service_code:02X}, status=0x{status:02X}")
        return data

    async def _send_cip_with_status(self, service_code: int, cip_path: bytes,
                                     service_data: bytes) -> tuple[int, bytes]:
        mr_data = mr_codec.encode_request(service_code, cip_path, service_data)

        items = [
            CpfItem(CpfItemType.NULL_ADDRESS, b''),
            CpfItem(CpfItemType.UNCONNECTED_DATA, mr_data),
        ]
        cpf_data = encode_cpf(items)
        payload = bytearray(6 + len(cpf_data))
        payload[6:] = cpf_data

        resp_payload = await self._send_encapsulated(EncapsulationCommand.SEND_RR_DATA, bytes(payload))

        resp_items = parse_cpf(resp_payload[6:])
        for item in resp_items:
            if item.type_id == CpfItemType.UNCONNECTED_DATA:
                result = mr_codec.try_parse_response(item.data)
                if result is None:
                    raise RuntimeError("Malformed CIP response")
                _, status, data = result
                return status.general_status, data

        raise RuntimeError("No response data")

    async def _send_multi_service(self, sub_requests: list[bytes]) -> list[tuple[int, bytes]]:
        header_size = 2 + len(sub_requests) * 2
        total = header_size + sum(len(r) for r in sub_requests)

        ms_data = bytearray(total)
        struct.pack_into('<H', ms_data, 0, len(sub_requests))

        offset = header_size
        for i, sr in enumerate(sub_requests):
            struct.pack_into('<H', ms_data, 2 + i * 2, offset)
            ms_data[offset:offset + len(sr)] = sr
            offset += len(sr)

        mr_path = bytes([0x20, 0x02, 0x24, 0x01])
        status, resp_data = await self._send_cip_with_status(0x0A, mr_path, bytes(ms_data))

        if status != 0x00:
            raise RuntimeError(f"Multiple Service Packet failed: status=0x{status:02X}")

        results: list[tuple[int, bytes]] = []
        if len(resp_data) < 2:
            return results

        resp_count = struct.unpack_from('<H', resp_data, 0)[0]
        offsets = [struct.unpack_from('<H', resp_data, 2 + i * 2)[0] for i in range(resp_count)]

        for i in range(resp_count):
            start = offsets[i]
            end = offsets[i + 1] if i + 1 < resp_count else len(resp_data)
            if start + 4 > len(resp_data):
                break
            sub_status = resp_data[start + 2]
            add_size = resp_data[start + 3]
            data_start = start + 4 + add_size * 2
            sub_data = resp_data[data_start:end] if data_start < end else b''
            results.append((sub_status, sub_data))

        return results

    async def _browse_symbols(self, program: str | None) -> list[TagInfo]:
        tags: list[TagInfo] = []
        start_instance = 0

        program_prefix = b''
        if program:
            prog_bytes = program.encode('ascii')
            padded = len(prog_bytes) if len(prog_bytes) % 2 == 0 else len(prog_bytes) + 1
            program_prefix = bytes([0x91, len(prog_bytes)]) + prog_bytes + b'\x00' * (padded - len(prog_bytes))

        while True:
            class_inst_path = bytearray(6)
            class_inst_path[0] = 0x20; class_inst_path[1] = 0x6B
            class_inst_path[2] = 0x25; class_inst_path[3] = 0x00
            struct.pack_into('<H', class_inst_path, 4, start_instance)

            path = program_prefix + bytes(class_inst_path)
            req_data = struct.pack('<HHH', 2, 1, 2)  # 2 attrs: name(1), type(2)

            status, data = await self._send_cip_with_status(0x55, path, req_data)
            if status not in (0x00, 0x06):
                break

            off = 0
            while off + 4 < len(data):
                inst_id = struct.unpack_from('<I', data, off)[0]; off += 4
                # Attr 1: name (UINT length + ASCII chars)
                if off + 2 > len(data): break
                name_len = struct.unpack_from('<H', data, off)[0]; off += 2
                if off + name_len > len(data): break
                name = data[off:off + name_len].decode('ascii', errors='replace'); off += name_len
                # Attr 2: symbol type (UINT)
                if off + 2 > len(data): break
                sym_type = struct.unpack_from('<H', data, off)[0]; off += 2

                tags.append(TagInfo(
                    name=name, instance_id=inst_id, symbol_type=sym_type,
                    is_struct=bool(sym_type & 0x8000),
                    is_system=bool(sym_type & 0x1000),
                    array_dimensions=(sym_type >> 13) & 0x03,
                    type_code=sym_type & 0x0FFF,
                ))
                start_instance = inst_id

            if status == 0x00:
                break
            start_instance += 1

        return tags

    async def _register_session(self) -> int:
        payload = struct.pack('<HH', 1, 0)
        await self._send_encapsulated(EncapsulationCommand.REGISTER_SESSION, payload)
        return self._last_header.session_handle

    async def _send_encapsulated(self, command: EncapsulationCommand, payload: bytes) -> bytes:
        async with self._lock:
            header = EncapsulationHeader(
                command=command,
                length=len(payload),
                session_handle=self.session_handle,
            )
            buf = bytearray(HEADER_SIZE + len(payload))
            header.write_to(buf)
            buf[HEADER_SIZE:] = payload
            self._writer.write(bytes(buf))
            await self._writer.drain()

            resp_header_data = await self._reader.readexactly(HEADER_SIZE)
            self._last_header = EncapsulationHeader.parse(resp_header_data)

            if self._last_header.status != EncapsulationStatus.SUCCESS:
                raise RuntimeError(f"Encapsulation error: {self._last_header.status}")

            resp_payload = b''
            if self._last_header.length > 0:
                resp_payload = await self._reader.readexactly(self._last_header.length)
            return resp_payload


def _build_symbolic_path(name: str) -> bytes:
    """Build ANSI Extended Symbolic path. Splits dotted names into separate segments."""
    parts = name.split('.')
    segments = []
    for part in parts:
        part_bytes = part.encode('ascii')
        padded = len(part_bytes) if len(part_bytes) % 2 == 0 else len(part_bytes) + 1
        seg = bytearray(2 + padded)
        seg[0] = 0x91
        seg[1] = len(part_bytes)
        seg[2:2 + len(part_bytes)] = part_bytes
        segments.append(bytes(seg))
    return b''.join(segments)


# --- Result types ---

@dataclass
class TagInfo:
    name: str = ""
    instance_id: int = 0
    symbol_type: int = 0
    is_struct: bool = False
    is_system: bool = False
    array_dimensions: int = 0
    type_code: int = 0
    template: TemplateInfo | None = None

    def __repr__(self):
        if self.is_struct:
            return f"{self.name} (struct: {self.template.name if self.template else f'#{self.type_code}'})"
        return f"{self.name} (0x{self.type_code:04X})"


@dataclass
class TemplateInfo:
    instance_id: int = 0
    name: str = ""
    structure_handle: int = 0
    member_count: int = 0
    definition_size: int = 0
    structure_size: int = 0
    members: list[TemplateMemberDetail] = field(default_factory=list)


@dataclass
class TemplateMemberDetail:
    name: str = ""
    data_type: int = 0
    info: int = 0
    offset: int = 0

    @property
    def is_array(self) -> bool:
        return self.info > 0 and self.data_type != 0x00C1

    @property
    def array_size(self) -> int:
        return self.info if self.is_array else 0


@dataclass
class TagBrowseResult:
    tags: list[TagInfo] = field(default_factory=list)
    templates: dict[int, TemplateInfo] = field(default_factory=dict)

    @property
    def user_tags(self):
        return [t for t in self.tags if not t.is_system and not t.name.startswith("__")]


class StructureValue:
    """Named access to structure members from raw bytes using a template definition."""

    def __init__(self, template: TemplateInfo, raw_data: bytearray | None = None):
        self.template = template
        self.raw_data = raw_data if raw_data is not None else bytearray(template.structure_size)

    def to_bytes(self) -> bytes:
        return bytes(self.raw_data)

    def get_member(self, name: str) -> TemplateMemberDetail | None:
        for m in self.template.members:
            if m.name.lower() == name.lower():
                return m
        return None

    def get_dint(self, member_name: str) -> int:
        m = self._require(member_name)
        return struct.unpack_from('<i', self.raw_data, m.offset)[0]

    def get_real(self, member_name: str) -> float:
        m = self._require(member_name)
        return struct.unpack_from('<f', self.raw_data, m.offset)[0]

    def get_lint(self, member_name: str) -> int:
        m = self._require(member_name)
        return struct.unpack_from('<q', self.raw_data, m.offset)[0]

    def get_lreal(self, member_name: str) -> float:
        m = self._require(member_name)
        return struct.unpack_from('<d', self.raw_data, m.offset)[0]

    def get_sint(self, member_name: str) -> int:
        m = self._require(member_name)
        return struct.unpack_from('<b', self.raw_data, m.offset)[0]

    def get_int(self, member_name: str) -> int:
        m = self._require(member_name)
        return struct.unpack_from('<h', self.raw_data, m.offset)[0]

    def get_bool(self, member_name: str) -> bool:
        m = self._require(member_name)
        host = self.raw_data[m.offset]
        return bool(host & (1 << m.info))

    def get_string(self, member_name: str) -> str:
        m = self._require(member_name)
        off = m.offset
        if off + dt.STRING_DATA_OFFSET >= len(self.raw_data):
            return ""
        length = struct.unpack_from('<i', self.raw_data, off)[0]
        if length <= 0:
            return ""
        max_len = min(length, dt.STRING_MAX_LENGTH, len(self.raw_data) - off - dt.STRING_DATA_OFFSET)
        return self.raw_data[off + dt.STRING_DATA_OFFSET:off + dt.STRING_DATA_OFFSET + max_len].decode('ascii', errors='replace')

    def set_dint(self, member_name: str, value: int) -> None:
        m = self._require(member_name)
        struct.pack_into('<i', self.raw_data, m.offset, value)

    def set_real(self, member_name: str, value: float) -> None:
        m = self._require(member_name)
        struct.pack_into('<f', self.raw_data, m.offset, value)

    def set_bool(self, member_name: str, value: bool) -> None:
        m = self._require(member_name)
        if value:
            self.raw_data[m.offset] |= (1 << m.info)
        else:
            self.raw_data[m.offset] &= ~(1 << m.info)

    def set_string(self, member_name: str, value: str) -> None:
        m = self._require(member_name)
        off = m.offset
        str_bytes = value.encode('ascii')
        length = min(len(str_bytes), dt.STRING_MAX_LENGTH)
        struct.pack_into('<i', self.raw_data, off, length)
        self.raw_data[off + dt.STRING_DATA_OFFSET:off + dt.STRING_DATA_OFFSET + dt.STRING_MAX_LENGTH] = b'\x00' * dt.STRING_MAX_LENGTH
        self.raw_data[off + dt.STRING_DATA_OFFSET:off + dt.STRING_DATA_OFFSET + length] = str_bytes[:length]

    def to_dict(self) -> dict[str, str]:
        result = {}
        for m in self.template.members:
            if m.name.startswith("ZZZZZZZZZZ") or m.name.startswith("__") or not m.name:
                continue
            try:
                result[m.name] = self._format_member(m)
            except Exception:
                result[m.name] = "?"
        return result

    def _require(self, name: str) -> TemplateMemberDetail:
        m = self.get_member(name)
        if m is None:
            raise KeyError(f"Member '{name}' not found in {self.template.name}")
        return m

    def _format_member(self, m: TemplateMemberDetail) -> str:
        off = m.offset
        if off >= len(self.raw_data):
            return "?"

        if m.data_type == 0x00C1:
            return str(bool(self.raw_data[off] & (1 << m.info)))

        base_type = m.data_type & 0x00FF
        if not m.is_array and (m.data_type & 0xFF00) == 0:
            match base_type:
                case 0xC2: return str(struct.unpack_from('<b', self.raw_data, off)[0])
                case 0xC3: return str(struct.unpack_from('<h', self.raw_data, off)[0])
                case 0xC4: return str(struct.unpack_from('<i', self.raw_data, off)[0])
                case 0xC5: return str(struct.unpack_from('<q', self.raw_data, off)[0])
                case 0xCA: return f"{struct.unpack_from('<f', self.raw_data, off)[0]:g}"
                case 0xCB: return f"{struct.unpack_from('<d', self.raw_data, off)[0]:g}"

        if m.data_type & 0x8000:
            return f"[struct@{off}]"

        return f"0x{m.data_type:04X}@{off}"
