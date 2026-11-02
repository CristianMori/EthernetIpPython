"""CIP Template Object (Class 0x6C) — structure definitions."""

from __future__ import annotations
import struct

from ..cip.cip_class import CipClass
from ..cip.instance import CipInstance
from ..cip.attribute import CipAttribute, AttributeAccess
from ..cip.data_types import CipDataType
from ..cip.service import CipServiceDefinition, CipServiceRequest, CipServiceResponse
from ..cip.status import CipStatus
from ..cip import standard_services as std

from .tag_database import TagDatabase, TemplateDefinition

CLASS_CODE = 0x6C
TEMPLATE_READ = 0x4C
GET_ATTRIBUTE_LIST = 0x03


class TemplateObject:
    """CIP Template Object — one instance per structure definition."""

    def __init__(self, tags: TagDatabase):
        self._tags = tags
        self.cip_class = CipClass(CLASS_CODE, "Template", revision=1)
        self.cip_class.add_standard_instance_services()
        self.cip_class.add_instance_service(CipServiceDefinition(
            TEMPLATE_READ, "Template_Read", self._handle_template_read))
        self.cip_class.add_instance_service(CipServiceDefinition(
            GET_ATTRIBUTE_LIST, "Get_Attribute_List", self._handle_get_attr_list))

    def ensure_instance(self, template: TemplateDefinition) -> None:
        if self.cip_class.get_instance(template.instance_id) is not None:
            return
        inst = self.cip_class.create_instance(template.instance_id)

        inst.add_attribute(CipAttribute.create_uint(1, CipDataType.UINT, AttributeAccess.ALL, template.struct_handle))
        inst.add_attribute(CipAttribute.create_uint(2, CipDataType.UINT, AttributeAccess.ALL, template.member_count))

        # Attr 4: definition size in 32-bit words.  pycomm3 (and Studio 5000)
        # computes the Template_Read body size as `(def_size*4) - 21`, treating
        # 21 bytes as a header that lives inside the "definition" count but is
        # not part of the body we actually return via service 0x4C.  Match
        # Logix's convention by sizing attr 4 to make `(def_size*4) - 21` ≥ the
        # member-data length — rounded up to a 32-bit boundary.
        member_data = self._build_member_data(template)
        def_size_words = (21 + len(member_data) + 3) // 4
        inst.add_attribute(CipAttribute.create_udint(4, CipDataType.UDINT, AttributeAccess.ALL, def_size_words))

        # Attr 5: structure size in bytes
        inst.add_attribute(CipAttribute.create_udint(5, CipDataType.UDINT, AttributeAccess.ALL, template.structure_size))

        inst.user_data = template

    def _build_member_data(self, template: TemplateDefinition) -> bytes:
        """Build the template member definition data for Template Read."""
        buf = bytearray()

        # Per member: type_and_info(4) + offset(4)
        for m in template.members:
            type_info = (m.data_type << 16) | (m.info & 0xFFFF)
            buf += struct.pack('<II', type_info, m.byte_offset)

        # Template name (null-terminated).  Logix exports and pycomm3 both
        # expect the "<Name>;<crc>" convention — pycomm3 splits on ';' to pull
        # the name.  Without the ';' pycomm3 appends the name to the member
        # list as if it were an extra member and the parse fails.
        buf += template.name.encode('ascii') + b';0' + b'\x00'

        # Member names (null-terminated)
        for m in template.members:
            buf += m.name.encode('ascii') + b'\x00'

        # Pad to 4-byte boundary
        while len(buf) % 4 != 0:
            buf += b'\x00'

        return bytes(buf)

    def _handle_template_read(self, instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
        template = instance.user_data
        if not isinstance(template, TemplateDefinition):
            return CipServiceResponse.error(request.service_code, CipStatus.error(0x05))

        if len(request.data) < 6:
            return CipServiceResponse.error(request.service_code, CipStatus.error(0x13))

        # CIP Vol 1 §C-5.11 Template_Read request: [Byte_Offset:UDINT][Size:UINT].
        # Earlier code had these in the wrong order and misread pycomm3's
        # perfectly-valid request as an out-of-range offset, returning 0x05.
        byte_offset = struct.unpack_from('<I', request.data, 0)[0]
        requested_size = struct.unpack_from('<H', request.data, 4)[0]

        member_data = self._build_member_data(template)

        if byte_offset >= len(member_data):
            return CipServiceResponse.error(request.service_code, CipStatus.error(0x05))

        remaining = len(member_data) - byte_offset
        chunk = min(remaining, requested_size, 480)
        more = byte_offset + chunk < len(member_data)

        resp_data = member_data[byte_offset:byte_offset + chunk]

        if more:
            return CipServiceResponse(
                service_code=request.service_code | 0x80,
                status=CipStatus.error(0x06),
                data=resp_data,
            )
        return CipServiceResponse.success(request.service_code, resp_data)

    def _handle_get_attr_list(self, instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
        if len(request.data) < 2:
            return CipServiceResponse.error(request.service_code, CipStatus.error(0x13))

        attr_count = struct.unpack_from('<H', request.data, 0)[0]
        attr_ids = []
        for i in range(attr_count):
            if 2 + i * 2 + 2 <= len(request.data):
                attr_ids.append(struct.unpack_from('<H', request.data, 2 + i * 2)[0])

        buf = bytearray(256)
        offset = 0
        struct.pack_into('<H', buf, offset, attr_count); offset += 2

        for aid in attr_ids:
            attr = instance.get_attribute(aid)
            if attr is not None:
                struct.pack_into('<H', buf, offset, aid); offset += 2
                struct.pack_into('<H', buf, offset, 0); offset += 2  # status
                offset += attr.encode_to(buf, offset)
            else:
                struct.pack_into('<H', buf, offset, aid); offset += 2
                struct.pack_into('<H', buf, offset, 0x14); offset += 2

        return CipServiceResponse.success(request.service_code, bytes(buf[:offset]))
