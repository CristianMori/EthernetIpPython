"""Tag storage — manages tags and templates with Logix alignment rules."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable

from .tag import Tag, TagChangeInfo
from . import data_types as dt


@dataclass
class TemplateMember:
    """Input for AddTemplate: name + data type + optional array size."""
    name: str
    data_type: int          # CIP type code (0xC4=DINT, etc.) or 0 for nested struct
    array_size: int = 1
    template_id: int = 0    # For nested structs


@dataclass
class TemplateMemberInfo:
    """Resolved member with computed offset and element size."""
    name: str
    data_type: int
    array_size: int
    byte_offset: int
    element_size: int
    info: int = 0           # Bit position for BOOL, array size for arrays


@dataclass
class TemplateDefinition:
    """Complete structure template definition."""
    instance_id: int
    name: str
    struct_handle: int
    member_count: int
    structure_size: int
    members: list[TemplateMemberInfo] = field(default_factory=list)


class TagDatabase:
    """In-memory tag and template storage with Logix alignment rules."""

    def __init__(self):
        self._tags_by_name: dict[str, Tag] = {}
        self._tags_by_id: dict[int, Tag] = {}
        self._templates: dict[int, TemplateDefinition] = {}
        self._next_tag_id = 0
        self._next_template_id = 0x100

        self.on_any_tag_changed: list[Callable[[Tag, TagChangeInfo], None]] = []
        self.on_tag_added: list[Callable[[Tag], None]] = []
        self.on_template_added: list[Callable[[TemplateDefinition], None]] = []

    def add_tag(self, name: str, tag_type: int, element_count: int = 1) -> Tag:
        """Add an atomic tag."""
        self._next_tag_id += 1
        element_size = dt.get_element_size(tag_type)
        if element_size < 0:
            raise ValueError(f"Unknown atomic tag type: 0x{tag_type:04X}")

        symbol_type = dt.make_atomic_symbol_type(tag_type, array_dims=1 if element_count > 1 else 0)
        tag = Tag(self._next_tag_id, name, symbol_type, tag_type, element_size, element_count)
        tag.on_value_changed.append(self._on_tag_changed)

        self._tags_by_name[name.lower()] = tag
        self._tags_by_id[tag.instance_id] = tag
        for cb in self.on_tag_added:
            cb(tag)
        return tag

    def add_struct_tag(self, name: str, template: TemplateDefinition, element_count: int = 1) -> Tag:
        """Add a structured tag backed by a template."""
        self._next_tag_id += 1
        symbol_type = dt.make_struct_symbol_type(template.instance_id, array_dims=1 if element_count > 1 else 0)
        tag = Tag(self._next_tag_id, name, symbol_type, template.struct_handle,
                  template.structure_size, element_count)
        tag.on_value_changed.append(self._on_tag_changed)

        self._tags_by_name[name.lower()] = tag
        self._tags_by_id[tag.instance_id] = tag
        for cb in self.on_tag_added:
            cb(tag)
        return tag

    def add_template(self, name: str, *members: TemplateMember) -> TemplateDefinition:
        """Define a structure template with Logix alignment."""
        self._next_template_id += 1
        inst_id = self._next_template_id

        resolved: list[TemplateMemberInfo] = []
        offset = 0

        for m in members:
            elem_size = dt.get_element_size(m.data_type) if m.data_type else -1
            if elem_size < 0 and m.template_id:
                tmpl = self._templates.get(m.template_id)
                elem_size = tmpl.structure_size if tmpl else 4

            if elem_size < 0:
                elem_size = 4

            # Logix alignment
            alignment = min(elem_size, 8)
            if alignment > 1:
                offset = (offset + alignment - 1) & ~(alignment - 1)

            resolved.append(TemplateMemberInfo(
                name=m.name, data_type=m.data_type, array_size=m.array_size,
                byte_offset=offset, element_size=elem_size,
                info=m.array_size if m.array_size > 1 else 0,
            ))
            offset += elem_size * m.array_size

        # Pad structure to 4-byte boundary
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

    def _on_tag_changed(self, tag: Tag, info: TagChangeInfo) -> None:
        for cb in self.on_any_tag_changed:
            cb(tag, info)
