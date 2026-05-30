"""Standard CIP service handlers: GetAttributeSingle, SetAttributeSingle, GetAttributeAll."""

from .instance import CipInstance
from .attribute import AttributeAccess
from .service import CipServiceRequest, CipServiceResponse
from .status import CipStatus, PATH_SEGMENT_ERROR, ATTRIBUTE_NOT_SUPPORTED, ATTRIBUTE_NOT_SETTABLE

# Service codes
GET_ATTRIBUTE_ALL = 0x01
SET_ATTRIBUTE_ALL = 0x02
GET_ATTRIBUTE_LIST = 0x03
SET_ATTRIBUTE_LIST = 0x04
RESET = 0x05
GET_ATTRIBUTE_SINGLE = 0x0E
SET_ATTRIBUTE_SINGLE = 0x10


def handle_get_attribute_single(instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
    attr_id = request.path.attribute_id
    if attr_id is None:
        return CipServiceResponse.error(request.service_code, CipStatus.error(PATH_SEGMENT_ERROR))

    attr = instance.get_attribute(attr_id)
    if attr is None:
        return CipServiceResponse.error(request.service_code, CipStatus.error(ATTRIBUTE_NOT_SUPPORTED))

    if not (attr.access & AttributeAccess.GET_SINGLE):
        return CipServiceResponse.error(request.service_code, CipStatus.error(ATTRIBUTE_NOT_SUPPORTED))

    data = bytearray(attr.data_length)
    attr.encode_to(data)
    return CipServiceResponse.success(request.service_code, bytes(data))


def handle_set_attribute_single(instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
    attr_id = request.path.attribute_id
    if attr_id is None:
        return CipServiceResponse.error(request.service_code, CipStatus.error(PATH_SEGMENT_ERROR))

    attr = instance.get_attribute(attr_id)
    if attr is None:
        return CipServiceResponse.error(request.service_code, CipStatus.error(ATTRIBUTE_NOT_SUPPORTED))

    if not (attr.access & AttributeAccess.SET_SINGLE):
        return CipServiceResponse.error(request.service_code, CipStatus.error(ATTRIBUTE_NOT_SETTABLE))

    attr.set_data(request.data)
    return CipServiceResponse.success(request.service_code)


def handle_get_attribute_all(instance: CipInstance, request: CipServiceRequest) -> CipServiceResponse:
    buf = bytearray(4096)
    length = instance.encode_all_attributes(buf)
    return CipServiceResponse.success(request.service_code, bytes(buf[:length]))
