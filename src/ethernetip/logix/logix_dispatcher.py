"""Logix dispatcher — CipDispatcher with symbolic tag addressing."""

from __future__ import annotations

from ..cip.dispatcher import CipDispatcher
from ..cip.cip_class import CipClass
from ..cip.path import CipPath
from ..cip.service import CipServiceDefinition, CipServiceResponse
from ..cip.status import CipStatus, SERVICE_NOT_SUPPORTED
from ..cip.identity_info import IdentityInfo
from ..cip.attribute import CipAttribute, AttributeAccess
from ..cip.data_types import CipDataType
from ..connections.connection_manager import ConnectionManagerObject

from .tag import Tag
from .tag_database import TagDatabase, TemplateDefinition
from .symbol_object import SymbolObject
from .template_object import TemplateObject
from .multi_service import SERVICE_CODE as MULTI_SVC, handle_multi_service
from . import tag_services as ts


class LogixDispatcher(CipDispatcher):
    """CipDispatcher subclass that handles symbolic tag addressing for Logix controllers."""

    def __init__(self, tags: TagDatabase | None = None, identity: IdentityInfo | None = None):
        super().__init__()
        self.tags = tags or TagDatabase()

        self._symbol_object = SymbolObject(self.tags)
        self._template_object = TemplateObject(self.tags)
        self._symbol_cache: dict[str, Tag] = {}

        self.register_class(self._symbol_object.cip_class)
        self.register_class(self._template_object.cip_class)

        # Message Router with Multiple Service Packet
        mr = CipClass(0x02, "Message Router", revision=1)
        mr.add_standard_instance_services()
        mr.create_instance(1)
        mr.add_instance_service(CipServiceDefinition(
            MULTI_SVC, "Multiple_Service_Packet",
            lambda inst, req: handle_multi_service(self, req)))
        self.register_class(mr)

        # Connection Manager with Unconnected Send
        cm = ConnectionManagerObject()
        cm.dispatch_request = self.dispatch
        self.register_class(cm.cip_class)

        # Identity
        if identity:
            from ..device.identity_object import create_identity_class
            self.register_class(create_identity_class(identity))

            # Program Name (Class 0x64, Rockwell KB 23341). pycomm3's connect
            # flow calls GetAttributesAll on class 0x64 instance 1 to populate
            # LogixDriver.info["name"]; without it the connect aborts.
            # Attribute 1 = controller program name as CIP STRING (UINT length
            # + ASCII chars).
            import struct as _struct
            pn = CipClass(0x64, "Program Name", revision=1)
            pn.add_standard_instance_services()
            pn_inst = pn.create_instance(1)
            pn_bytes = identity.product_name.encode('ascii')
            pn_data = _struct.pack('<H', len(pn_bytes)) + pn_bytes
            pn_inst.add_attribute(CipAttribute(
                1, CipDataType.STRING,
                AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL,
                pn_data))
            self.register_class(pn)

        # Auto-register on add
        self.tags.on_tag_added.append(self._on_tag_added)
        self.tags.on_template_added.append(lambda t: self._template_object.ensure_instance(t))

        self.sync_cip_instances()

    def _on_tag_added(self, tag: Tag) -> None:
        self._symbol_object.ensure_instance(tag)
        self._symbol_cache[tag.name.lower()] = tag

    def sync_cip_instances(self) -> None:
        for tag in self.tags.all_tags:
            self._symbol_object.ensure_instance(tag)
            self._symbol_cache[tag.name.lower()] = tag
        for template in self.tags.all_templates:
            self._template_object.ensure_instance(template)

    def on_unhandled(self, service_code: int, path: CipPath, data: bytes,
                     default_status: int | None = None) -> CipServiceResponse:
        if path.symbolic_name is not None:
            key = path.symbolic_name.lower()
            tag = self._symbol_cache.get(key)
            if tag is None:
                tag = self.tags.find_by_name(path.symbolic_name)
                if tag is None:
                    return CipServiceResponse.error(service_code, CipStatus.error(0x05))
                self._symbol_cache[key] = tag

            element_offset = path.element_id or 0
            return _dispatch_tag_service(tag, service_code, data, element_offset)

        if default_status is None:
            from ..cip.status import PATH_DESTINATION_UNKNOWN
            default_status = PATH_DESTINATION_UNKNOWN
        return super().on_unhandled(service_code, path, data, default_status)


def _dispatch_tag_service(tag: Tag, service_code: int, data: bytes,
                          element_offset: int = 0) -> CipServiceResponse:
    match service_code:
        case 0x4C:
            return ts.handle_read_tag(tag, service_code, data, element_offset)
        case 0x4D:
            return ts.handle_write_tag(tag, service_code, data, element_offset)
        case 0x52:
            return ts.handle_read_tag_fragmented(tag, service_code, data)
        case 0x53:
            return ts.handle_write_tag_fragmented(tag, service_code, data)
        case 0x4E:
            return ts.handle_read_modify_write(tag, service_code, data)
        case _:
            return CipServiceResponse.error(service_code, CipStatus.error(SERVICE_NOT_SUPPORTED))
