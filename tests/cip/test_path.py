"""Tests for CIP EPATH parser."""

from ethernetip.cip.path import CipPath


def test_parse_class_instance():
    # Class 0x04, Instance 1: 20 04 24 01
    data = bytes([0x20, 0x04, 0x24, 0x01])
    path, consumed = CipPath.parse(data)
    assert consumed == 4
    assert path.class_id == 0x04
    assert path.instance_id == 1
    assert path.symbolic_name is None


def test_parse_class_instance_attribute():
    # Class 0x01, Instance 1, Attribute 7: 20 01 24 01 30 07
    data = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x07])
    path, consumed = CipPath.parse(data)
    assert consumed == 6
    assert path.class_id == 0x01
    assert path.instance_id == 1
    assert path.attribute_id == 7


def test_parse_connection_point():
    # Class 0x04, Connection Point 100: 20 04 2C 64
    data = bytes([0x20, 0x04, 0x2C, 0x64])
    path, consumed = CipPath.parse(data)
    assert consumed == 4
    assert path.class_id == 0x04
    assert path.connection_point == 100


def test_parse_symbolic_segment():
    # Symbolic "MyTag" (5 chars + 1 pad): 91 05 4D 79 54 61 67 00
    name = b'MyTag'
    data = bytes([0x91, 5]) + name + bytes([0x00])  # pad
    path, consumed = CipPath.parse(data)
    assert consumed == 8
    assert path.symbolic_name == "MyTag"
    assert path.class_id is None


def test_parse_dotted_symbolic():
    # Two symbolic segments: "Program:Main" and "Counter"
    seg1_name = b'Program:Main'
    seg1 = bytes([0x91, len(seg1_name)]) + seg1_name  # 12 chars, even, no pad
    seg2_name = b'Counter'
    seg2 = bytes([0x91, len(seg2_name)]) + seg2_name + bytes([0x00])  # 7 chars + pad
    data = seg1 + seg2
    path, consumed = CipPath.parse(data)
    assert path.symbolic_name == "Program:Main.Counter"


def test_parse_16bit_instance():
    # Class 0x6B, Instance 0x1234 (16-bit): 20 6B 25 00 34 12
    data = bytes([0x20, 0x6B, 0x25, 0x00, 0x34, 0x12])
    path, consumed = CipPath.parse(data)
    assert path.class_id == 0x6B
    assert path.instance_id == 0x1234


def test_parse_element_id():
    # Element 5: 28 05
    data = bytes([0x28, 0x05])
    path, consumed = CipPath.parse(data)
    assert path.element_id == 5


def test_encode_logical_8():
    buf = bytearray(2)
    n = CipPath.encode_logical_8(buf, 0, 0x00, 0x04)  # class 0x04
    assert n == 2
    assert buf == bytes([0x20, 0x04])


def test_parse_empty():
    path, consumed = CipPath.parse(b'')
    assert consumed == 0
    assert path.class_id is None


def test_parse_stops_on_unknown_segment():
    # Class 0x01, then unknown segment type 0x80
    data = bytes([0x20, 0x01, 0x80, 0x00])
    path, consumed = CipPath.parse(data)
    assert consumed == 2
    assert path.class_id == 0x01
