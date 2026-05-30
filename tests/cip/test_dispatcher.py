"""Tests for CIP dispatcher and object model."""

from ethernetip.cip.dispatcher import CipDispatcher
from ethernetip.cip.cip_class import CipClass
from ethernetip.cip.instance import CipInstance
from ethernetip.cip.attribute import CipAttribute, AttributeAccess
from ethernetip.cip.data_types import CipDataType
from ethernetip.cip.path import CipPath
from ethernetip.cip import status as st


def _make_identity_class() -> CipClass:
    cls = CipClass(0x01, "Identity")
    cls.add_standard_instance_services()
    inst = cls.create_instance(1)
    inst.add_attribute(CipAttribute.create_uint(1, CipDataType.UINT, AttributeAccess.ALL, 0x0001))
    inst.add_attribute(CipAttribute.create_uint(2, CipDataType.UINT, AttributeAccess.ALL, 0x000C))
    inst.add_attribute(CipAttribute.create_short_string(7, AttributeAccess.ALL, "TestDevice"))
    return cls


def test_dispatch_get_attribute_single():
    dispatcher = CipDispatcher()
    dispatcher.register_class(_make_identity_class())

    path = CipPath(class_id=0x01, instance_id=1, attribute_id=1)
    resp = dispatcher.dispatch(0x0E, path, b'')
    assert resp.status.is_success
    assert resp.service_code == 0x8E
    # UINT 0x0001 = 2 bytes LE
    assert resp.data == b'\x01\x00'


def test_dispatch_get_attribute_all():
    dispatcher = CipDispatcher()
    dispatcher.register_class(_make_identity_class())

    path = CipPath(class_id=0x01, instance_id=1)
    resp = dispatcher.dispatch(0x01, path, b'')
    assert resp.status.is_success
    assert len(resp.data) > 0


def test_dispatch_class_not_found():
    dispatcher = CipDispatcher()
    path = CipPath(class_id=0xFF, instance_id=1)
    resp = dispatcher.dispatch(0x0E, path, b'')
    assert resp.status.general_status == st.PATH_DESTINATION_UNKNOWN


def test_dispatch_instance_not_found():
    dispatcher = CipDispatcher()
    dispatcher.register_class(_make_identity_class())

    path = CipPath(class_id=0x01, instance_id=999)
    resp = dispatcher.dispatch(0x0E, path, b'')
    assert resp.status.general_status == st.OBJECT_DOES_NOT_EXIST


def test_dispatch_service_not_supported():
    dispatcher = CipDispatcher()
    cls = CipClass(0x99, "Empty")
    cls.create_instance(1)
    dispatcher.register_class(cls)

    path = CipPath(class_id=0x99, instance_id=1)
    resp = dispatcher.dispatch(0x0E, path, b'')
    assert resp.status.general_status == st.SERVICE_NOT_SUPPORTED


def test_dispatch_symbolic_unhandled():
    dispatcher = CipDispatcher()
    path = CipPath(symbolic_name="MyTag")
    resp = dispatcher.dispatch(0x4C, path, b'')
    assert resp.status.general_status == st.PATH_DESTINATION_UNKNOWN


def test_set_attribute_single():
    dispatcher = CipDispatcher()
    dispatcher.register_class(_make_identity_class())

    path = CipPath(class_id=0x01, instance_id=1, attribute_id=1)
    resp = dispatcher.dispatch(0x10, path, b'\x42\x00')
    assert resp.status.is_success

    # Read back
    resp2 = dispatcher.dispatch(0x0E, path, b'')
    assert resp2.data == b'\x42\x00'


def test_class_instance_0_attributes():
    dispatcher = CipDispatcher()
    cls = _make_identity_class()
    dispatcher.register_class(cls)

    # Read class-level attr 1 (revision)
    path = CipPath(class_id=0x01, instance_id=0, attribute_id=1)
    resp = dispatcher.dispatch(0x0E, path, b'')
    assert resp.status.is_success


def test_max_instance_tracking():
    cls = CipClass(0x04, "Assembly")
    cls.create_instance(100)
    cls.create_instance(200)
    # Max instance attr (attr 2) should be 200
    attr = cls.class_instance.get_attribute(2)
    import struct
    val = struct.unpack_from('<H', attr.data)[0]
    assert val == 200
