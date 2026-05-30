"""Fallback typed message for commands the manager doesn't have a dedicated class for."""
from __future__ import annotations
from dataclasses import dataclass, field

from ...cip.encapsulation import EncapsulationHeader


@dataclass
class EncapsulationMessage:
    """Catch-all carrying the parsed header + raw payload bytes.

    Used when EncapsulationMessageManager sees a command it has no
    dedicated typed class for. The adapter typically responds with an
    InvalidCommand error.
    """
    header: EncapsulationHeader = field(default_factory=EncapsulationHeader)
    payload: bytes = b''
    remote_addr: tuple[str, int] = ('0.0.0.0', 0)
