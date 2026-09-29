"""Tag storage — manages tags, templates, and program scopes with Logix rules."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable

from .tag import Tag, TagChangeInfo
from . import data_types as dt


@dataclass
class TemplateMember:
    """Input for add_template: name + data type + optional array size."""
    name: str
    data_type: int          # CIP type code (0xC4=DINT, etc.) or 0 for nested struct
    array_size: int = 1
    template_id: int = 0    # For nested structs referenced by legacy caller.


@dataclass
class TemplateMemberInfo:
    """Resolved member with computed offset and element size.

    For scalar BOOL members inside a struct, `info` carries the bit
    position (0..7); the walker reads this to build the correct BOOL
    write mask.  For arrays, `info` carries the array size.
    """
    name: str
    data_type: int
    array_size: int
    byte_offset: int
    element_size: int
    info: int = 0


@dataclass
class TemplateDefinition:
    """Complete structure template definition."""
    instance_id: int
    name: str
    struct_handle: int
    member_count: int
    structure_size: int
    members: list[TemplateMemberInfo] = field(default_factory=list)


@dataclass
class ProgramScope:
    """A named tag scope belonging to a Logix program.

    Program-scoped tags live in a per-program table with their own
    Symbol Object instance-id space, distinct from the controller scope.
    Addressed by clients as `Program:<name>.<tag>`.
    """
    name: str
    pseudo_instance: int
    tags: dict[str, Tag] = field(default_factory=dict)
    next_instance: int = 1


class TagDatabase:
    """In-memory tag and template storage with Logix alignment rules."""

    def __init__(self):
        self._tags_by_name: dict[str, Tag] = {}
        self._tags_by_id: dict[int, Tag] = {}
        self._templates: dict[int, TemplateDefinition] = {}
        self._programs: dict[str, ProgramScope] = {}
        self._next_tag_id = 0
        self._next_template_id = 0x100
        self._next_program_pseudo = 0xF000

        self.on_any_tag_changed: list[Callable[[Tag, TagChangeInfo], None]] = []
        self.on_tag_added: list[Callable[[Tag], None]] = []
        self.on_template_added: list[Callable[[TemplateDefinition], None]] = []

        # Gap 8: global event-suppression flag + optional dirty tracking.
        self.suppress_events: bool = False
        self._dirty_tracking: bool = False
        self._dirty_tag_ids: set[int] = set()

    def add_tag(self, name: str, tag_type: int, element_count: int = 1,
                dims: tuple[int, ...] | None = None) -> Tag:
        """Add an atomic tag. BOOL[] arrays are DWORD-packed automatically
        (element_count must be a multiple of 32 in that case)."""
        # Multi-dim path if dims is passed.
        if dims is not None:
            if not 1 <= len(dims) <= 3:
                raise ValueError("dims must have 1, 2, or 3 entries")
            element_count = 1
            for d in dims:
                element_count *= d
        else:
            dims = (element_count,) if element_count > 1 else ()

        element_size = dt.get_element_size(tag_type)
        if element_size < 0:
            raise ValueError(f"Unknown atomic tag type: 0x{tag_type:04X}")

        # BOOL arrays: DWORD-packed storage.
        data_size = None
        if tag_type == dt.BOOL and element_count > 1:
            if element_count % 32 != 0:
                raise ValueError(
                    f"BOOL array element count must be a multiple of 32 (got {element_count})"
                )
            data_size = element_count // 8

        self._next_tag_id += 1
        array_dims = len(dims) if dims else 0
        symbol_type = dt.make_atomic_symbol_type(tag_type, array_dims=array_dims)
        tag = Tag(
            self._next_tag_id, name, symbol_type, tag_type,
            element_size, element_count, dims=dims, data_size=data_size,
        )
        self._register(tag)
        return tag

    def add_struct_tag(self, name: str, template: TemplateDefinition,
                       element_count: int = 1,
                       dims: tuple[int, ...] | None = None) -> Tag:
        """Add a structured tag backed by a template."""
        if dims is not None:
            if not 1 <= len(dims) <= 3:
                raise ValueError("dims must have 1, 2, or 3 entries")
            element_count = 1
            for d in dims:
                element_count *= d
        else:
            dims = (element_count,) if element_count > 1 else ()

        self._next_tag_id += 1
        array_dims = len(dims) if dims else 0
        symbol_type = dt.make_struct_symbol_type(template.instance_id, array_dims=array_dims)
        tag = Tag(
            self._next_tag_id, name, symbol_type, template.struct_handle,
            template.structure_size, element_count, dims=dims,
        )
        tag.template = template
        self._register(tag)
        return tag

    def _register(self, tag: Tag) -> None:
        """Order matters (gap 7): publish to _tags_by_id and TagAdded
        subscribers BEFORE _tags_by_name so a concurrent lookup by
        instance always finds a fully-registered tag."""
        self._tags_by_id[tag.instance_id] = tag
        tag.on_value_changed.append(self._on_tag_changed)
        for cb in self.on_tag_added:
            cb(tag)
        self._tags_by_name[tag.name.lower()] = tag

    def add_template(self, name: str, *members: TemplateMember) -> TemplateDefinition:
        """Define a structure template with Logix alignment."""
        self._next_template_id += 1
        inst_id = self._next_template_id

        resolved: list[TemplateMemberInfo] = []
        offset = 0

        for m in members:
            # Nested-struct member: caller passes template_id and (optionally)
            # data_type with 0x8000 bit set. Resolve to the nested template's
            # structure size and force the 0x8000 bit on data_type so
            # Template_Read emits it and clients recurse.
            resolved_data_type = m.data_type
            elem_size = -1
            if m.template_id or (m.data_type & 0x8000):
                nested_id = m.template_id or (m.data_type & 0x0FFF)
                nested = self._templates.get(nested_id)
                if nested is None:
                    raise ValueError(
                        f"Template member '{m.name}' references unregistered nested template 0x{nested_id:04X}"
                    )
                elem_size = nested.structure_size
                resolved_data_type = 0x8000 | (nested_id & 0x0FFF)
            elif m.data_type:
                elem_size = dt.get_element_size(m.data_type)

            if elem_size < 0:
                elem_size = 4

            alignment = min(elem_size, 8) if elem_size > 0 else 1
            if alignment > 1:
                offset = (offset + alignment - 1) & ~(alignment - 1)

            resolved.append(TemplateMemberInfo(
                name=m.name, data_type=resolved_data_type, array_size=m.array_size,
                byte_offset=offset, element_size=elem_size,
                info=m.array_size if m.array_size > 1 else 0,
            ))
            offset += elem_size * m.array_size

        structure_size = (offset + 3) & ~3

        template = TemplateDefinition(
            instance_id=inst_id, name=name,
            struct_handle=inst_id & 0xFFFF,
            member_count=len(resolved),
            structure_size=structure_size,
            members=resolved,
        )
        self._templates[inst_id] = template
        for cb in self.on_template_added:
            cb(template)
        return template

    def add_template_prebuilt(self, template: TemplateDefinition) -> TemplateDefinition:
        """Register a pre-resolved template (explicit offsets, sizes, bit
        positions). Escape hatch the transpiler uses to import L5X layouts
        including AOI backing structures (32-per-DINT BOOL packing, SINT
        reordering) — the caller supplies the layout, no library recompute.

        template.instance_id must be non-zero and unique. The auto-assign
        counter is bumped past it so a subsequent add_template call won't
        collide.
        """
        if template.instance_id == 0:
            raise ValueError("template.instance_id must be non-zero")
        if template.instance_id in self._templates:
            raise ValueError(f"template 0x{template.instance_id:04X} already exists")
        if template.instance_id >= self._next_template_id:
            self._next_template_id = template.instance_id + 1
        self._templates[template.instance_id] = template
        for cb in self.on_template_added:
            cb(template)
        return template

    def find_by_name(self, name: str) -> Tag | None:
        return self._tags_by_name.get(name.lower())

    def find_by_instance_id(self, instance_id: int) -> Tag | None:
        return self._tags_by_id.get(instance_id)

    def find_template(self, instance_id: int) -> TemplateDefinition | None:
        return self._templates.get(instance_id)

    @property
    def all_tags(self):
        return self._tags_by_id.values()

    @property
    def all_templates(self):
        return self._templates.values()

    @property
    def count(self) -> int:
        return len(self._tags_by_id)

    # --- Program-scope management (gap 1) ---

    def register_program(self, name: str) -> ProgramScope:
        """Register or return an existing named program scope."""
        existing = self._programs.get(name)
        if existing is not None:
            return existing
        pseudo = self._next_program_pseudo
        self._next_program_pseudo += 1
        scope = ProgramScope(name=name, pseudo_instance=pseudo)
        self._programs[name] = scope
        return scope

    def find_program(self, name: str) -> ProgramScope | None:
        return self._programs.get(name)

    @property
    def all_programs(self):
        return self._programs.values()

    def add_program_tag(self, program: str, name: str, tag_type: int) -> Tag:
        """Add an atomic tag inside a program scope. Returns the tag."""
        scope = self._programs.get(program)
        if scope is None:
            raise ValueError(f"program '{program}' not registered")
        if name.lower() in {n.lower() for n in scope.tags}:
            raise ValueError(f"tag '{name}' already exists in program '{program}'")
        elem_size = dt.get_element_size(tag_type)
        if elem_size < 0:
            raise ValueError(f"Unknown atomic tag type: 0x{tag_type:04X}")
        inst = scope.next_instance
        scope.next_instance += 1
        symbol_type = dt.make_atomic_symbol_type(tag_type)
        tag = Tag(inst, name, symbol_type, tag_type, elem_size)
        scope.tags[name.lower()] = tag
        return tag

    def find_program_tag(self, program: str, name: str) -> Tag | None:
        scope = self._programs.get(program)
        if scope is None:
            return None
        return scope.tags.get(name.lower())

    # --- Gap 8: dirty tracking helpers ---

    def enable_dirty_tracking(self) -> None:
        self._dirty_tracking = True

    def disable_dirty_tracking(self) -> None:
        self._dirty_tracking = False
        self._dirty_tag_ids.clear()

    def drain_dirty(self) -> list[int]:
        out = list(self._dirty_tag_ids)
        self._dirty_tag_ids.clear()
        return out

    def _on_tag_changed(self, tag: Tag, info: TagChangeInfo) -> None:
        if self.suppress_events:
            return
        if self._dirty_tracking:
            self._dirty_tag_ids.add(tag.instance_id)
        for cb in self.on_any_tag_changed:
            cb(tag, info)
