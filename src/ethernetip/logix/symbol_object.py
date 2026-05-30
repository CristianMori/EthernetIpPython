"""CIP Symbol Object (Class 0x6B) — tag instances and browsing."""

from __future__ import annotations
import struct

from ..cip.cip_class import CipClass
from ..cip.instance import CipInstance
from ..cip.attribute import CipAttribute, AttributeAccess
from ..cip.data_types import CipDataType
from ..cip.service import CipServiceDefinition, CipServiceRequest, CipServiceResponse
from ..cip.status import CipStatus

from .tag import Tag
from .tag_database import TagDatabase
from . import tag_services as ts

CLASS_CODE = 0x6B
GET_INSTANCE_ATTRIBUTE_LIST = 0x55


class SymbolObject:
    """CIP Symbol Object — one instance per tag, plus tag browsing."""

    def __init__(self, tags: TagDatabase):
        self._tags = tags
        self.cip_class = CipClass(CLASS_CODE, "Symbol", revision=1)

        self.cip_class.add_instance_service(CipServiceDefinition(ts.READ_TAG, "Read_Tag", self._handle_read))
        self.cip_class.add_instance_service(CipServiceDefinition(ts.WRITE_TAG, "Write_Tag", self._handle_write))
        self.cip_class.add_instance_service(CipServiceDefinition(ts.READ_TAG_FRAGMENTED, "Read_Tag_Fragmented", self._handle_read_frag))
        self.cip_class.add_instance_service(CipServiceDefinition(ts.WRITE_TAG_FRAGMENTED, "Write_Tag_Fragmented", self._handle_write_frag))
        self.cip_class.add_instance_service(CipServiceDefinition(ts.READ_MODIFY_WRITE, "Read_Modify_Write", self._handle_rmw))

        self.cip_class.add_class_service(CipServiceDefinition(
            GET_INSTANCE_ATTRIBUTE_LIST, "Get_Instance_Attribute_List", self._handle_browse))

    def ensure_instance(self, tag: Tag) -> None:
        if self.cip_class.get_instance(tag.instance_id) is not None:
            return
        inst = self.cip_class.create_instance(tag.instance_id)

        # Attr 1: Symbol Name (UINT length + ASCII)
        name_bytes = tag.name.encode('ascii')
        name_data = struct.pack('<H', len(name_bytes)) + name_bytes
        inst.add_attribute(CipAttribute(1, CipDataType.STRING, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, name_data))

        # Attr 2: Symbol Type
        inst.add_attribute(CipAttribute.create_uint(2, CipDataType.UINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, tag.symbol_type))

        inst.user_data = tag

    def _get_tag(self, instance: CipInstance) -> Tag | None:
        return instance.user_data if isinstance(instance.user_data, Tag) else None

    def _handle_read(self, instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
        tag = self._get_tag(instance)
        if tag is None:
            return CipServiceResponse.error(request.service_code, CipStatus.error(0x05))
        element_offset = request.path.element_id or 0
        return ts.handle_read_tag(tag, request.service_code, request.data, element_offset)

    def _handle_write(self, instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
        tag = self._get_tag(instance)
        if tag is None:
            return CipServiceResponse.error(request.service_code, CipStatus.error(0x05))
        element_offset = request.path.element_id or 0
        return ts.handle_write_tag(tag, request.service_code, request.data, element_offset)

    def _handle_read_frag(self, instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
        tag = self._get_tag(instance)
        if tag is None:
            return CipServiceResponse.error(request.service_code, CipStatus.error(0x05))
        return ts.handle_read_tag_fragmented(tag, request.service_code, request.data)

    def _handle_write_frag(self, instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
        tag = self._get_tag(instance)
        if tag is None:
            return CipServiceResponse.error(request.service_code, CipStatus.error(0x05))
        return ts.handle_write_tag_fragmented(tag, request.service_code, request.data)

    def _handle_rmw(self, instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
        tag = self._get_tag(instance)
        if tag is None:
            return CipServiceResponse.error(request.service_code, CipStatus.error(0x05))
        return ts.handle_read_modify_write(tag, request.service_code, request.data)

    def _handle_browse(self, instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
        """Get_Instance_Attribute_List (Symbol class-level service 0x55).

        Wire format per CIP / Rockwell KB and pycomm3:
          - start instance comes from the request path's instance_id
          - request data = attr_count (UINT) + attr_ids[] (UINT each)
          - response = for each tag: instance_id (UDINT) + attribute values
            concatenated in the requested order, with NO per-attribute status

        Pycomm3 asks for attrs [1, 2, 3, 5, 6, 8] (+ 10 if revision_major >= 18)
        and parses the response as a flat positional record. Implementations
        that only emit attrs 1/2 (or that wrap each attr with a status word)
        misalign pycomm3's parser and the connect fails.
        """
        if len(request.data) < 2:
            return CipServiceResponse.error(request.service_code, CipStatus.error(0x13))

        attr_count = struct.unpack_from('<H', request.data, 0)[0]
        if len(request.data) < 2 + attr_count * 2:
            return CipServiceResponse.error(request.service_code, CipStatus.error(0x13))
        attr_ids = [struct.unpack_from('<H', request.data, 2 + i * 2)[0]
                     for i in range(attr_count)]

        start_instance = request.path.instance_id or 0
        max_response = 480
        buf = bytearray(4096)
        offset = 0
        tags_packed = 0
        truncated = False

        sorted_tags = [t for t in sorted(self._tags.all_tags, key=lambda t: t.instance_id)
                        if t.instance_id > start_instance]

        for tag in sorted_tags:
            self.ensure_instance(tag)
            entry_start = offset

            # Instance ID (UDINT) — required first field per Rockwell wire layout.
            if offset + 4 > max_response and tags_packed > 0:
                truncated = True
                break
            struct.pack_into('<I', buf, offset, tag.instance_id)
            offset += 4

            rolled_back = False
            for aid in attr_ids:
                # Per-attribute size we will write for this attr_id.
                if aid == 1:
                    entry = 2 + len(tag.name)
                elif aid == 2:
                    entry = 2
                elif aid in (3, 5, 6):
                    entry = 4
                elif aid == 8:
                    entry = 12
                elif aid == 10:
                    entry = 1
                else:
                    entry = 0

                if entry > 0 and offset + entry > max_response and tags_packed > 0:
                    offset = entry_start
                    truncated = True
                    rolled_back = True
                    break

                if aid == 1:  # Symbol Name (STRING — UINT length + ASCII chars)
                    name_bytes = tag.name.encode('ascii')
                    struct.pack_into('<H', buf, offset, len(name_bytes)); offset += 2
                    buf[offset:offset + len(name_bytes)] = name_bytes
                    offset += len(name_bytes)
                elif aid == 2:  # Symbol Type (UINT)
                    struct.pack_into('<H', buf, offset, tag.symbol_type); offset += 2
                elif aid in (3, 5, 6):  # Symbol Address / Symbol Object Address / Software Control (UDINT)
                    struct.pack_into('<I', buf, offset, 0); offset += 4
                elif aid == 8:  # Array Dimensions — three UDINTs.
                    d1 = tag.element_count if tag.element_count > 1 else 0
                    struct.pack_into('<III', buf, offset, d1, 0, 0); offset += 12
                elif aid == 10:  # External Access (USINT). 3 = Read/Write.
                    buf[offset] = 0x03; offset += 1
                # Other attrs silently omitted (consistent with C++ port).

            if rolled_back:
                break
            tags_packed += 1

        more_data = truncated and tags_packed < len(sorted_tags)
        if more_data:
            return CipServiceResponse(
                service_code=request.service_code | 0x80,
                status=CipStatus.error(0x06),
                data=bytes(buf[:offset]),
            )
        return CipServiceResponse.success(request.service_code, bytes(buf[:offset]))
