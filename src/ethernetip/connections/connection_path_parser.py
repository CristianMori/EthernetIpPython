"""Parses Forward Open connection paths to extract assembly instance IDs."""

from __future__ import annotations
from dataclasses import dataclass
from .forward_open_request import ForwardOpenRequest


@dataclass(frozen=True)
class ConnectionPathResult:
    config_assembly_instance: int | None = None
    consumed_assembly_instance: int | None = None   # O→T
    produced_assembly_instance: int | None = None   # T→O
    has_electronic_key: bool = False
    safety_segment: bytes | None = None             # Raw 0x50 segment if present
    # Bytes from the Simple Data Segment (0x80), aka Connection Data. For a
    # Generic Ethernet Module Forward Open these are the config assembly
    # contents the originator pushes at connection setup.
    config_data: bytes = b''


def parse_connection_path(path: bytes | bytearray | memoryview,
                          request: ForwardOpenRequest) -> ConnectionPathResult:
    """Parse a connection path to extract assembly instances.

    Handles Logix Emulate wrapper, electronic keys, port segments, safety
    segments, and the common assembly shortcut: class 0x04, config instance,
    2 connection points.

    Safety paths use 3 class+instance pairs (config, O→T, T→O) instead of
    connection points.
    """
    p = memoryview(path) if not isinstance(path, memoryview) else path

    # Some originators prepend extra path segments (class 0x04FC + connection
    # point 0x01) before the real connection path. Not sure why — strip them
    # so the parser can find the actual assembly instances.
    if (len(p) >= 6 and p[0] == 0x21 and p[1] == 0x00 and
            p[2] == 0xFC and p[3] == 0x04 and p[4] == 0x2C and p[5] == 0x01):
        p = p[6:]

    current_class: int | None = None
    current_instance: int | None = None
    connection_points: list[int] = []
    instance_ids: list[int] = []
    has_key = False
    safety_segment: bytes | None = None
    config_data: bytes = b''
    offset = 0

    while offset < len(p):
        seg = p[offset]
        seg_type = seg & 0xE0

        if seg_type == 0x20:  # Logical segment
            logical_type = seg & 0x1C
            fmt = seg & 0x03
            offset += 1

            if fmt == 0x00:  # 8-bit
                if offset >= len(p): break
                value = p[offset]; offset += 1
            elif fmt == 0x01:  # 16-bit
                if offset % 2 != 0: offset += 1
                if offset + 2 > len(p): break
                value = p[offset] | (p[offset + 1] << 8); offset += 2
            else:
                break

            if logical_type == 0x00:    # class
                current_class = value
            elif logical_type == 0x04:  # instance
                current_instance = value
                instance_ids.append(value)
            elif logical_type == 0x0C:  # connection point
                connection_points.append(value)

        elif seg_type == 0x00:  # Port segment
            extended = bool(seg & 0x10)
            offset += 1
            if extended:
                if offset >= len(p): break
                addr_size = p[offset]; offset += 1
                offset += addr_size
                if offset % 2 != 0: offset += 1
            else:
                if offset >= len(p): break
                offset += 1

        elif seg == 0x34:  # Electronic key
            has_key = True
            offset += 1
            if offset >= len(p): break
            key_format = p[offset]; offset += 1
            key_size = 8 if key_format in (4, 5) else 0
            offset += key_size

        elif seg_type == 0x80:  # Simple Data Segment (config data)
            offset += 1
            if offset >= len(p): break
            data_words = p[offset]; offset += 1
            data_bytes = data_words * 2
            if offset + data_bytes > len(p): break
            config_data = bytes(p[offset:offset + data_bytes])
            offset += data_bytes

        elif seg_type == 0x40:  # Network segment
            if seg == 0x50:  # Safety Network Segment
                if offset + 1 >= len(p): break
                seg_data_words = p[offset + 1]
                seg_total = 2 + seg_data_words * 2
                if offset + seg_total > len(p): break
                safety_segment = bytes(p[offset:offset + seg_total])
                offset += seg_total
            else:
                offset += 1
                if offset >= len(p): break
                net_seg_len = p[offset]; offset += 1
                offset += net_seg_len * 2

        else:
            break

    # Determine assembly instances
    config_inst = None
    consumed_inst = None
    produced_inst = None

    if current_class == 0x04 and len(connection_points) >= 2:
        config_inst = current_instance
        consumed_inst = connection_points[0]
        produced_inst = connection_points[1]
    elif current_class == 0x04 and len(connection_points) == 1:
        config_inst = current_instance
        if not request.ot_params.is_null and not request.to_params.is_null:
            consumed_inst = connection_points[0]
            produced_inst = connection_points[0]
        elif not request.ot_params.is_null:
            consumed_inst = connection_points[0]
        else:
            produced_inst = connection_points[0]
    elif current_class == 0x04 and len(connection_points) == 0 and len(instance_ids) >= 3:
        # Safety format: 3 class+instance pairs, no connection points.
        # [config inst] [O→T inst] [T→O inst]
        config_inst = instance_ids[0]
        consumed_inst = instance_ids[1]
        produced_inst = instance_ids[2]
    elif len(connection_points) >= 2:
        consumed_inst = connection_points[0]
        produced_inst = connection_points[1]

    return ConnectionPathResult(
        config_assembly_instance=config_inst,
        consumed_assembly_instance=consumed_inst,
        produced_assembly_instance=produced_inst,
        has_electronic_key=has_key,
        safety_segment=safety_segment,
        config_data=config_data,
    )
