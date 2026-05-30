"""CIP Identity Object (Class 0x01)."""

from ..cip.cip_class import CipClass
from ..cip.attribute import CipAttribute, AttributeAccess
from ..cip.data_types import CipDataType
from ..cip.service import CipServiceDefinition, CipServiceRequest, CipServiceResponse
from ..cip.instance import CipInstance
from ..cip.identity_info import IdentityInfo
from ..cip import standard_services as std

CLASS_CODE = 0x01


def create_identity_class(identity: IdentityInfo) -> CipClass:
    cls = CipClass(CLASS_CODE, "Identity", revision=1)
    cls.add_standard_instance_services()
    cls.add_instance_service(CipServiceDefinition(std.RESET, "Reset", _handle_reset))

    inst = cls.create_instance(1)
    inst.add_attribute(CipAttribute.create_uint(1, CipDataType.UINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, identity.vendor_id))
    inst.add_attribute(CipAttribute.create_uint(2, CipDataType.UINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, identity.device_type))
    inst.add_attribute(CipAttribute.create_uint(3, CipDataType.UINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, identity.product_code))
    inst.add_attribute(CipAttribute(4, CipDataType.USINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL,
                                     bytes([identity.major_revision, identity.minor_revision])))
    inst.add_attribute(CipAttribute.create_uint(5, CipDataType.WORD, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, identity.status))
    inst.add_attribute(CipAttribute.create_udint(6, CipDataType.UDINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, identity.serial_number))
    inst.add_attribute(CipAttribute.create_short_string(7, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, identity.product_name))
    return cls


def _handle_reset(instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
    return CipServiceResponse.success(request.service_code)
