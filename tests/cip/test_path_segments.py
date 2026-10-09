"""Tests for the ordered Segments list on CipPath."""

from __future__ import annotations

from ethernetip.cip.path import (
    CipPath,
    ElementPathSegment,
    LogicalKind,
    LogicalPathSegment,
    SymbolicPathSegment,
)


def test_parses_program_scoped_tag():
    data = bytes([
        0x91, 12, *b'Program:Main',
        0x91, 5, *b'MyTag', 0x00,
    ])
    path, consumed = CipPath.parse(data)
    assert consumed == len(data)
    assert path.segments == (
        SymbolicPathSegment('Program:Main'),
        SymbolicPathSegment('MyTag'),
    )
    # Back-compat: flat SymbolicName still joins with '.'.
    assert path.symbolic_name == 'Program:Main.MyTag'


def test_parses_member_chain():
    data = bytes([
        0x91, 5, *b'Motor', 0x00,
        0x91, 5, *b'Timer', 0x00,
        0x91, 3, *b'PRE', 0x00,
    ])
    path, _ = CipPath.parse(data)
    assert path.segments == (
        SymbolicPathSegment('Motor'),
        SymbolicPathSegment('Timer'),
        SymbolicPathSegment('PRE'),
    )
    assert path.symbolic_name == 'Motor.Timer.PRE'


def test_parses_element_between_members():
    data = bytes([
        0x91, 4, *b'Line',
        0x28, 0x02,
        0x91, 5, *b'Motor', 0x00,
        0x91, 5, *b'Fault', 0x00,
    ])
    path, _ = CipPath.parse(data)
    assert path.segments == (
        SymbolicPathSegment('Line'),
        ElementPathSegment(2),
        SymbolicPathSegment('Motor'),
        SymbolicPathSegment('Fault'),
    )
    # Back-compat: flat SymbolicName concatenates every 0x91 with '.'.
    assert path.symbolic_name == 'Line.Motor.Fault'
    # Back-compat: flat ElementId keeps the last-seen index.
    assert path.element_id == 2


def test_parses_multi_dim_indices():
    data = bytes([
        0x91, 6, *b'Matrix',
        0x28, 0x01,
        0x28, 0x02,
    ])
    path, _ = CipPath.parse(data)
    assert path.segments == (
        SymbolicPathSegment('Matrix'),
        ElementPathSegment(1),
        ElementPathSegment(2),
    )
    # Back-compat: last-write-wins for flat element_id.
    assert path.element_id == 2


def test_segments_default_empty():
    path = CipPath(symbolic_name='rate')
    assert path.segments == ()


def test_parses_class_instance_logical():
    data = bytes([0x20, 0x06, 0x24, 0x01])
    path, _ = CipPath.parse(data)
    assert path.segments == (
        LogicalPathSegment(LogicalKind.CLASS_ID, 6),
        LogicalPathSegment(LogicalKind.INSTANCE_ID, 1),
    )
    assert path.class_id == 6
    assert path.instance_id == 1
