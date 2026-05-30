"""CIP Ethernet Link Object (Class 0xF6)."""

from ..cip.cip_class import CipClass
from ..cip.attribute import CipAttribute, AttributeAccess
from ..cip.data_types import CipDataType

CLASS_CODE = 0xF6


def create_ethernet_link_class() -> CipClass:
    cls = CipClass(CLASS_CODE, "Ethernet Link", revision=4)
    cls.add_standard_instance_services()
    inst = cls.create_instance(1)

    inst.add_attribute(CipAttribute.create_udint(1, CipDataType.UDINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, 100))
    inst.add_attribute(CipAttribute.create_udint(2, CipDataType.UDINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, 0x0F))
    inst.add_attribute(CipAttribute(3, CipDataType.USINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL,
                                     bytes([0x00, 0x1C, 0x2E, 0x00, 0x00, 0x01])))
    return cls
