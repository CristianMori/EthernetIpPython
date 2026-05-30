"""CIP instance — holds attributes and belongs to a CIP class."""

from __future__ import annotations
from typing import TYPE_CHECKING

from .attribute import CipAttribute, AttributeAccess

if TYPE_CHECKING:
    from .cip_class import CipClass


class CipInstance:
    """A CIP object instance identified by numeric ID within a CipClass.

    Instance 0 is the class-level instance (holds class attributes).
    Instances 1+ are regular object instances.
    """

    def __init__(self, instance_id: int):
        self.instance_id = instance_id
        self.owner_class: CipClass | None = None
        self.user_data: object = None
        self._attributes: dict[int, CipAttribute] = {}
        self._sorted_get_all_cache: list[CipAttribute] | None = None

    def add_attribute(self, attr: CipAttribute) -> None:
        self._attributes[attr.id] = attr
        self._sorted_get_all_cache = None  # invalidate cache

    def get_attribute(self, attr_id: int) -> CipAttribute | None:
        return self._attributes.get(attr_id)

    @property
    def attributes(self):
        return self._attributes.values()

    @property
    def attribute_count(self) -> int:
        return len(self._attributes)

    def encode_all_attributes(self, dst: bytearray, offset: int = 0) -> int:
        """Encode all GetAll-capable attributes sorted by ID. Returns bytes written."""
        if self._sorted_get_all_cache is None:
            self._sorted_get_all_cache = sorted(
                (a for a in self._attributes.values() if AttributeAccess.GET_ALL in a.access),
                key=lambda a: a.id
            )

        pos = offset
        for attr in self._sorted_get_all_cache:
            pos += attr.encode_to(dst, pos)
        return pos - offset
