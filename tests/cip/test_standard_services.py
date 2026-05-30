"""Tests for standard CIP services."""

from ethernetip.cip.instance import CipInstance
from ethernetip.cip.attribute import CipAttribute, AttributeAccess
from ethernetip.cip.data_types import CipDataType
from ethernetip.cip.service import CipServiceRequest
from ethernetip.cip.path import CipPath
from ethernetip.cip.standard_services import (
    handle_get_attribute_single,
    handle_set_attribute_single,
    handle_get_attribute_all,
)


def _make_instance():
    inst = CipInstance(1)
    inst.add_attribute(CipAttribute.create_uint(1, CipDataType.UINT, AttributeAccess.ALL, 0x1234))
    inst.add_attribute(CipAttribute.create_udint(2, CipDataType.UDINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, 0xDEADBEEF))
    inst.add_attribute(CipAttribute.create_byte(3, CipDataType.USINT, AttributeAccess.GET_SINGLE, 0x42))
    return inst


def test_get_attribute_single():
    inst = _make_instance()
    req = CipServiceRequest(service_code=0x0E, path=CipPath(attribute_id=1))
    resp = handle_get_attribute_single(inst, req)
    assert resp.status.is_success
    assert resp.data == b'\x34\x12'


def test_get_attribute_single_missing():
    inst = _make_instance()
    req = CipServiceRequest(service_code=0x0E, path=CipPath(attribute_id=99))
    resp = handle_get_attribute_single(inst, req)
    assert not resp.status.is_success


def test_get_attribute_single_no_attr_id():
    inst = _make_instance()
    req = CipServiceRequest(service_code=0x0E, path=CipPath())
    resp = handle_get_attribute_single(inst, req)
    assert resp.status.general_status == 0x04  # PATH_SEGMENT_ERROR


def test_set_attribute_single():
    inst = _make_instance()
    req = CipServiceRequest(service_code=0x10, path=CipPath(attribute_id=1), data=b'\xFF\x00')
    resp = handle_set_attribute_single(inst, req)
    assert resp.status.is_success
    assert bytes(inst.get_attribute(1).data) == b'\xFF\x00'


def test_set_attribute_read_only():
    inst = _make_instance()
    req = CipServiceRequest(service_code=0x10, path=CipPath(attribute_id=2), data=b'\x00\x00\x00\x00')
    resp = handle_set_attribute_single(inst, req)
    assert resp.status.general_status == 0x0E  # ATTRIBUTE_NOT_SETTABLE


def test_get_attribute_all():
    inst = _make_instance()
    req = CipServiceRequest(service_code=0x01, path=CipPath())
    resp = handle_get_attribute_all(inst, req)
    assert resp.status.is_success
    # Attr 1 (UINT, GetAll) + Attr 2 (UDINT, GetAll) = 2 + 4 = 6 bytes
    # Attr 3 doesn't have GetAll flag
    assert len(resp.data) == 6
