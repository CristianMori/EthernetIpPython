"""CIP TCP/IP Interface Object (Class 0xF5)."""

import socket

from ..cip.cip_class import CipClass
from ..cip.attribute import CipAttribute, AttributeAccess
from ..cip.data_types import CipDataType

CLASS_CODE = 0xF5


def create_tcpip_interface_class(ip_address: str) -> CipClass:
    cls = CipClass(CLASS_CODE, "TCP/IP Interface", revision=4)
    cls.add_standard_instance_services()
    inst = cls.create_instance(1)

    inst.add_attribute(CipAttribute.create_udint(1, CipDataType.UDINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, 1))
    inst.add_attribute(CipAttribute.create_udint(2, CipDataType.UDINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, 0x04))
    inst.add_attribute(CipAttribute.create_udint(3, CipDataType.UDINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, 0x02))

    if_config = bytearray(22)
    if_config[0:4] = socket.inet_aton(ip_address)
    if_config[4:8] = bytes([255, 255, 255, 0])
    inst.add_attribute(CipAttribute(5, CipDataType.BYTE, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, bytes(if_config)))

    return cls
