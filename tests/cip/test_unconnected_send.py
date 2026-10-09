"""Unconnected_Send wire-format tests — mirrors the C# and Rust vectors."""

from __future__ import annotations
import pytest

from ethernetip.cip.unconnected_send import build_inner_mr, wrap


def test_build_inner_encodes_service_path_and_data():
    path = bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x07])
    inner = build_inner_mr(0x0E, path)
    assert inner[0] == 0x0E
    assert inner[1] == 3  # path words
    assert inner[2:] == path


def test_empty_route_errors():
    inner = build_inner_mr(0x0E, bytes([0x20, 0x01, 0x24, 0x01]))
    with pytest.raises(ValueError):
        wrap(inner, b'')


def test_odd_route_errors():
    inner = build_inner_mr(0x0E, bytes([0x20, 0x01, 0x24, 0x01]))
    with pytest.raises(ValueError):
        wrap(inner, bytes([0x01]))


def test_matches_reference_wire_layout():
    """CIP Vol 1 §3-5.5.4 reference vector, same as C#/Rust tests."""
    inner_mr = bytes([0x0E, 0x02, 0x20, 0x01, 0x24, 0x01])
    outer = wrap(inner_mr, bytes([0x01, 0x00]))
    expected = bytes([
        0x52, 0x02, 0x20, 0x06, 0x24, 0x01,
        0x07, 0xF9,
        0x06, 0x00,
        0x0E, 0x02, 0x20, 0x01, 0x24, 0x01,
        0x01, 0x00,
        0x01, 0x00,
    ])
    assert outer == expected


def test_odd_inner_inserts_pad():
    inner_mr = bytes([0x0E, 0x02, 0x20, 0x01, 0x24, 0x01, 0xAA])
    outer = wrap(inner_mr, bytes([0x01, 0x00]))
    # embedded_size UINT at offset 8.
    assert outer[8] == 7
    # route_size at 8+2+7+1 = 18.
    assert outer[18] == 1
    assert outer[19] == 0
