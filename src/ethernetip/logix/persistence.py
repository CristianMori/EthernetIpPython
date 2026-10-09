"""TagDatabase save/load — cross-port binary format matching C# and Rust.

Format v1: header magic "EIPS" + version 1 byte + 3 reserved bytes.
Controller-tag section (UDINT count + records) then program section
(UDINT program_count + per program: UINT name_len + ASCII + UDINT
tag_count + records).  Each record: UINT name_len + ASCII + UINT
tag_type + UDINT data_size + bytes.  All little-endian.

Semantics: saves tag BUFFER CONTENTS keyed by name; assumes the schema
has been re-registered before load.  Tolerant of added/removed/renamed
tags between versions.
"""

from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import BinaryIO

from .tag_database import TagDatabase

_MAGIC = b"EIPS"
_VERSION = 1


@dataclass
class LoadResult:
    tags_restored: int = 0
    tags_skipped: int = 0
    warnings: list[str] = field(default_factory=list)


def save(db: TagDatabase, stream: BinaryIO) -> None:
    stream.write(_MAGIC + bytes([_VERSION, 0, 0, 0]))
    controller_tags = sorted(db.all_tags, key=lambda t: t.instance_id)
    stream.write(struct.pack('<I', len(controller_tags)))
    for tag in controller_tags:
        _write_tag_record(stream, tag.name, tag.tag_type, bytes(tag.get_data()))

    programs = list(db.all_programs)
    stream.write(struct.pack('<I', len(programs)))
    for scope in programs:
        _write_string(stream, scope.name)
        scope_tags = sorted(scope.tags.values(), key=lambda t: t.instance_id)
        stream.write(struct.pack('<I', len(scope_tags)))
        for tag in scope_tags:
            _write_tag_record(stream, tag.name, tag.tag_type, bytes(tag.get_data()))


def load(db: TagDatabase, stream: BinaryIO) -> LoadResult:
    header = stream.read(8)
    if len(header) < 8 or header[:4] != _MAGIC:
        raise ValueError("not a TagDatabase snapshot: bad magic")
    version = header[4]
    if version > _VERSION:
        raise ValueError(f"snapshot version {version} is newer than this loader ({_VERSION})")

    result = LoadResult()

    controller_count = _read_u32(stream)
    for _ in range(controller_count):
        _restore_one(stream, db, program=None, result=result)

    program_count = _read_u32(stream)
    for _ in range(program_count):
        program_name = _read_string(stream)
        tag_count = _read_u32(stream)
        has_program = db.find_program(program_name) is not None
        for _ in range(tag_count):
            if has_program:
                _restore_one(stream, db, program=program_name, result=result)
            else:
                _skip_tag_record(stream)
                result.tags_skipped += 1
                result.warnings.append(
                    f"Program '{program_name}' not registered — skipping tag records"
                )
    return result


def _restore_one(stream: BinaryIO, db: TagDatabase, program: str | None,
                 result: LoadResult) -> None:
    name = _read_string(stream)
    tag_type = _read_u16(stream)
    data_size = _read_u32(stream)
    buffer = stream.read(data_size)
    if len(buffer) != data_size:
        raise EOFError("truncated tag record")

    if program is None:
        tag = db.find_by_name(name)
    else:
        tag = db.find_program_tag(program, name)
    if tag is None:
        result.tags_skipped += 1
        result.warnings.append(f"Tag '{name}' not registered — skipping")
        return
    if tag.tag_type != tag_type:
        result.tags_skipped += 1
        result.warnings.append(
            f"Tag '{name}' tag_type mismatch (file=0x{tag_type:04X}, "
            f"current=0x{tag.tag_type:04X}) — skipping"
        )
        return
    if tag.data_size != data_size:
        result.tags_skipped += 1
        result.warnings.append(
            f"Tag '{name}' data_size mismatch (file={data_size}, "
            f"current={tag.data_size}) — skipping"
        )
        return
    tag.set_data_silent(buffer)
    result.tags_restored += 1


def _skip_tag_record(stream: BinaryIO) -> None:
    _read_string(stream)
    _read_u16(stream)
    size = _read_u32(stream)
    stream.read(size)


def _write_tag_record(stream: BinaryIO, name: str, tag_type: int, data: bytes) -> None:
    _write_string(stream, name)
    stream.write(struct.pack('<HI', tag_type, len(data)))
    stream.write(data)


def _write_string(stream: BinaryIO, s: str) -> None:
    b = s.encode('ascii')
    stream.write(struct.pack('<H', len(b)))
    stream.write(b)


def _read_u16(stream: BinaryIO) -> int:
    b = stream.read(2)
    if len(b) < 2:
        raise EOFError()
    return struct.unpack('<H', b)[0]


def _read_u32(stream: BinaryIO) -> int:
    b = stream.read(4)
    if len(b) < 4:
        raise EOFError()
    return struct.unpack('<I', b)[0]


def _read_string(stream: BinaryIO) -> str:
    length = _read_u16(stream)
    return stream.read(length).decode('ascii')
