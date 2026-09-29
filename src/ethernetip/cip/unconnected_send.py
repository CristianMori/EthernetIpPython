"""Build the wire bytes for an Unconnected_Send (service 0x52) message
routed through the Connection Manager (class 0x06, instance 1).

Byte-for-byte compatible with the C# UnconnectedSendBuilder and the Rust
ethernetip_core::unconnected_send module.
"""

from __future__ import annotations
import struct

_SERVICE_CODE = 0x52
_DEFAULT_PRIORITY_TICK = 0x07
_DEFAULT_TIMEOUT_TICKS = 0xF9
_CONNECTION_MANAGER_PATH = bytes([0x20, 0x06, 0x24, 0x01])


def build_inner_mr(service_code: int, path_bytes: bytes,
                   service_data: bytes = b'') -> bytes:
    """Return service + path_size_words + path + service_data ready for
    send_explicit or as the embedded MR for wrap()."""
    if len(path_bytes) % 2 != 0:
        raise ValueError("path must be an even number of bytes")
    path_words = len(path_bytes) // 2
    return bytes([service_code, path_words]) + path_bytes + service_data


def wrap(inner_mr: bytes, route_path: bytes) -> bytes:
    """Wrap an inner MR into an Unconnected_Send MR ready for SendRRData."""
    if not route_path:
        raise ValueError(
            "route path must not be empty; caller should send bare MR instead"
        )
    if len(route_path) % 2 != 0:
        raise ValueError("route path must be an even number of bytes")

    route_words = len(route_path) // 2
    pad_embed = len(inner_mr) % 2 != 0

    us = bytearray()
    us.append(_DEFAULT_PRIORITY_TICK)
    us.append(_DEFAULT_TIMEOUT_TICKS)
    us += struct.pack('<H', len(inner_mr))
    us += inner_mr
    if pad_embed:
        us.append(0)
    us.append(route_words)
    us.append(0)  # reserved
    us += route_path

    outer = bytearray()
    outer.append(_SERVICE_CODE)
    outer.append(len(_CONNECTION_MANAGER_PATH) // 2)
    outer += _CONNECTION_MANAGER_PATH
    outer += us
    return bytes(outer)
