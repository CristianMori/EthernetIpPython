"""Protocol for safety-specific Forward Open validation and connection setup.

Implemented by SafetyDevice and attached to ConnectionManagerObject.safety_handler.
"""
from __future__ import annotations
from typing import Protocol

from .io_connection import IoConnection
from .forward_open_request import ForwardOpenRequest


class SafetyConnectionHandler(Protocol):
    """Hook surface that ConnectionManagerObject uses for safety connections."""

    # Target identity emitted in the safety Application Reply.
    vendor_id: int
    serial_number: int

    def validate_safety_open(self, safety_segment: bytes,
                              fwd_open: ForwardOpenRequest) -> int | None:
        """Return None to accept, or a CIP extended status code to reject."""
        ...

    def configure_safety_connection(self, conn: IoConnection,
                                     fwd_open: ForwardOpenRequest) -> None:
        """Compute CRC seeds, validator-instance assignment, time-correction
        constant, and any other safety fields on the new connection."""
        ...
