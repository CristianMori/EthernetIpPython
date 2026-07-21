"""Regression tests for connection_path_parser.

Covers the Electronic Key (0x34) detection that was silently dead code
before the check-ordering fix, plus a couple of surrounding cases so
future edits can't regress the segment ordering.
"""

from ethernetip.connections.connection_path_parser import parse_connection_path
from ethernetip.connections.forward_open_request import (
    ForwardOpenRequest,
    NetworkConnectionParams,
)


def _p2p_request() -> ForwardOpenRequest:
    """FO request with both directions non-null (P2P) so the safety-format
    and one-conn-point-both-directions branches don't accidentally trigger."""
    return ForwardOpenRequest(
        ot_params=NetworkConnectionParams.parse_16(0x4001),  # P2P, size 1
        to_params=NetworkConnectionParams.parse_16(0x4001),
    )


def test_electronic_key_detected_and_rest_of_path_parsed():
    # Real ControlLogix Generic Ethernet Module Forward Open path:
    #   34 04                                Electronic Key, format 4
    #   00 00 00 00 00 00 00 00              8 key bytes (any-match)
    #   20 04                                Class = Assembly
    #   24 69                                Instance = 105 (config)
    #   2C 66                                Conn point = 102 (O→T)
    #   2C 64                                Conn point = 100 (T→O)
    #   80 05  00*10                         Data segment (5 words config data)
    path = bytes([
        0x34, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x04,
        0x24, 0x69,
        0x2C, 0x66,
        0x2C, 0x64,
        0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    r = parse_connection_path(path, _p2p_request())
    assert r.has_electronic_key is True
    assert r.config_assembly_instance == 105
    assert r.consumed_assembly_instance == 102
    assert r.produced_assembly_instance == 100
    assert len(r.config_data) == 10


def test_electronic_key_only_then_assemblies_no_config_data():
    path = bytes([
        0x34, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x04, 0x24, 0x01, 0x2C, 0x02, 0x2C, 0x03,
    ])
    r = parse_connection_path(path, _p2p_request())
    assert r.has_electronic_key is True
    assert r.config_assembly_instance == 1
    assert r.consumed_assembly_instance == 2
    assert r.produced_assembly_instance == 3
    assert r.config_data == b''


def test_no_electronic_key_flag_false():
    # Pure assembly shortcut, no key segment.
    path = bytes([0x20, 0x04, 0x24, 0x05, 0x2C, 0x64, 0x2C, 0x66])
    r = parse_connection_path(path, _p2p_request())
    assert r.has_electronic_key is False
    assert r.config_assembly_instance == 5
    assert r.consumed_assembly_instance == 100
    assert r.produced_assembly_instance == 102


def test_unknown_key_format_skips_zero_bytes_so_rest_parses():
    # Format 0 (unknown) → skip 0 key bytes; the rest still parses.
    path = bytes([
        0x34, 0x00,                       # key seg, unknown format
        0x20, 0x04, 0x24, 0x07, 0x2C, 0x08, 0x2C, 0x09,
    ])
    r = parse_connection_path(path, _p2p_request())
    assert r.has_electronic_key is True
    assert r.config_assembly_instance == 7
    assert r.consumed_assembly_instance == 8
    assert r.produced_assembly_instance == 9
