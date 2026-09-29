"""Walk PathSegment list over a root Tag → (offset, type_code, element_size, bit_pos).

Mirrors the C# TagPathWalker: same rules, same error surface. Used by
LogixDispatcher whenever a request path carries member or element segments
past the root.
"""

from __future__ import annotations
from dataclasses import dataclass

from ..cip.path import ElementPathSegment, LogicalPathSegment, SymbolicPathSegment
from . import data_types as dt
from .tag import Tag
from .tag_database import TagDatabase, TemplateDefinition


@dataclass
class WalkResult:
    offset: int
    type_code: int
    element_size: int
    bit_pos: int | None
    template: TemplateDefinition | None


def walk(root: Tag, segments, db: TagDatabase) -> tuple[WalkResult | None, str | None]:
    """Return (result, error). On success error is None."""
    offset = 0
    type_code = root.tag_type
    element_size = _atomic_size(type_code) or root.element_size
    bit_pos: int | None = None
    template = root.template
    pending_dims: list[int] | None = list(root.dims) if root.dims else None
    pending_idx = 0
    pending_running = 0
    root_is_bool_array = root.tag_type == dt.BOOL and bool(root.dims)

    for seg in segments:
        if isinstance(seg, SymbolicPathSegment):
            if bit_pos is not None:
                return None, f"cannot drill into BOOL member with '{seg.name}'"
            if pending_dims is not None:
                return None, f"cannot drill into array element without an index: '{seg.name}'"
            if template is None:
                return None, f"cannot resolve member '{seg.name}' on non-structure type 0x{type_code:04X}"
            member = _find_member(template, seg.name)
            if member is None:
                return None, f"member '{seg.name}' not found in template '{template.name}'"
            offset += member.byte_offset
            type_code = member.data_type
            if type_code == dt.BOOL and member.element_size == 0:
                # Scalar BOOL member: `info` (or `array_size`) carries bit position.
                bit_pos = member.info if member.info else member.array_size
                element_size = 1
                template = None
            elif type_code & 0x8000:
                nested_id = type_code & 0x0FFF
                nested = db.find_template(nested_id)
                if nested is None:
                    return None, f"member '{seg.name}' references unknown template 0x{nested_id:04X}"
                element_size = nested.structure_size
                template = nested
                if member.array_size > 1:
                    pending_dims = [member.array_size]
                    pending_idx = 0
                    pending_running = 0
            else:
                template = None
                element_size = member.element_size or (_atomic_size(type_code) or 1)
                if member.array_size > 1:
                    pending_dims = [member.array_size]
                    pending_idx = 0
                    pending_running = 0
        elif isinstance(seg, ElementPathSegment):
            if bit_pos is not None:
                return None, "cannot index into a BOOL member"
            if pending_dims is None:
                return None, "element index on non-array target"
            dim = pending_dims[pending_idx]
            if seg.index >= dim:
                return None, f"element index {seg.index} out of range for dim {pending_idx} (size {dim})"
            pending_running = pending_running * dim + seg.index
            pending_idx += 1
            if pending_idx == len(pending_dims):
                if root_is_bool_array:
                    offset += pending_running // 8
                    bit_pos = pending_running % 8
                else:
                    offset += pending_running * element_size
                pending_dims = None
                pending_idx = 0
                pending_running = 0
        elif isinstance(seg, LogicalPathSegment):
            pass  # handled by outer dispatcher

    if pending_dims is not None:
        return None, f"under-indexed array: expected {len(pending_dims)} element segments, got {pending_idx}"

    return WalkResult(offset, type_code, element_size, bit_pos, template), None


def _find_member(template: TemplateDefinition, name: str):
    lower = name.lower()
    for m in template.members:
        if m.name.lower() == lower:
            return m
    return None


def _atomic_size(type_code: int) -> int | None:
    """Return byte size for a scalar atomic type code, else None."""
    if type_code & 0x8000:
        return None
    size = dt.get_element_size(type_code)
    return size if size > 0 else None
