"""Base protocols for typed encapsulation messages."""
from __future__ import annotations
from typing import Protocol, runtime_checkable


@runtime_checkable
class IMessage(Protocol):
    """Marker for any parsed message coming off the wire.

    `remote_addr` is a (host, port) tuple identifying the peer that sent
    (or will receive) this message. Always populated by the manager when
    parsing inbound traffic; required when serializing outbound traffic.
    """
    remote_addr: tuple[str, int]


@runtime_checkable
class ISerializableMessage(IMessage, Protocol):
    """Message that knows how to serialize itself onto the wire."""

    @property
    def wire_size(self) -> int:
        """Total bytes this message will occupy (header + payload)."""
        ...

    def to_bytes(self) -> bytes:
        """Serialize the entire message as a single bytes object."""
        ...
