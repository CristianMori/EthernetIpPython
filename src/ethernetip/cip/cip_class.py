"""CIP class — holds instances, attributes, and services in the CIP object model."""

from __future__ import annotations
import struct

from .instance import CipInstance
from .attribute import CipAttribute, AttributeAccess
from .data_types import CipDataType
from .service import CipServiceDefinition
from . import standard_services as std
from . import data_serializer as ds


class CipClass:
    """A CIP class (object type) with instances, class-level and instance-level services.

    Instance 0 (class_instance) holds class-level attributes like revision and max instance.
    """

    def __init__(self, class_code: int, name: str, revision: int = 1):
        self.class_code = class_code
        self.name = name
        self._instances: dict[int, CipInstance] = {}
        self._max_instance_id = 0
        self._instance_services: dict[int, CipServiceDefinition] = {}
        self._class_services: dict[int, CipServiceDefinition] = {}

        # Instance 0 — class-level attributes
        self.class_instance = CipInstance(0)
        self.class_instance.owner_class = self

        # Standard class attributes
        self.class_instance.add_attribute(
            CipAttribute.create_uint(1, CipDataType.UINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, revision))
        self.class_instance.add_attribute(
            CipAttribute.create_uint(2, CipDataType.UINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, 0))

        # Standard class-level services
        self.add_class_service(CipServiceDefinition(
            std.GET_ATTRIBUTE_SINGLE, "Get_Attribute_Single", std.handle_get_attribute_single))
        self.add_class_service(CipServiceDefinition(
            std.GET_ATTRIBUTE_ALL, "Get_Attributes_All", std.handle_get_attribute_all))

    def create_instance(self, instance_id: int) -> CipInstance:
        inst = CipInstance(instance_id)
        inst.owner_class = self
        self._instances[instance_id] = inst
        self._update_max_instance(instance_id)
        return inst

    def add_instance(self, instance: CipInstance) -> None:
        instance.owner_class = self
        self._instances[instance.instance_id] = instance
        self._update_max_instance(instance.instance_id)

    def _update_max_instance(self, instance_id: int) -> None:
        if instance_id <= self._max_instance_id:
            return
        self._max_instance_id = instance_id
        attr = self.class_instance.get_attribute(2)
        if attr is not None:
            buf = bytearray(2)
            ds.write_uint(buf, 0, self._max_instance_id)
            attr.set_data(buf)

    def get_instance(self, instance_id: int) -> CipInstance | None:
        if instance_id == 0:
            return self.class_instance
        return self._instances.get(instance_id)

    @property
    def instances(self) -> dict[int, CipInstance]:
        return self._instances

    def add_instance_service(self, service: CipServiceDefinition) -> None:
        self._instance_services[service.service_code] = service

    def get_instance_service(self, service_code: int) -> CipServiceDefinition | None:
        return self._instance_services.get(service_code)

    def add_class_service(self, service: CipServiceDefinition) -> None:
        self._class_services[service.service_code] = service

    def get_class_service(self, service_code: int) -> CipServiceDefinition | None:
        return self._class_services.get(service_code)

    def get_service(self, service_code: int, is_class_level: bool) -> CipServiceDefinition | None:
        if is_class_level:
            return self.get_class_service(service_code)
        return self.get_instance_service(service_code)

    def add_standard_instance_services(self) -> None:
        self.add_instance_service(CipServiceDefinition(
            std.GET_ATTRIBUTE_SINGLE, "Get_Attribute_Single", std.handle_get_attribute_single))
        self.add_instance_service(CipServiceDefinition(
            std.SET_ATTRIBUTE_SINGLE, "Set_Attribute_Single", std.handle_set_attribute_single))
        self.add_instance_service(CipServiceDefinition(
            std.GET_ATTRIBUTE_ALL, "Get_Attributes_All", std.handle_get_attribute_all))
