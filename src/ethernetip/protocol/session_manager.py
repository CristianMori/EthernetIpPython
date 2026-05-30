"""EtherNet/IP encapsulation session management."""

from __future__ import annotations
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable


@runtime_checkable
class SessionManagerProtocol(Protocol):
    def register(self) -> int: ...
    def unregister(self, handle: int) -> bool: ...
    def is_valid(self, handle: int) -> bool: ...
    @property
    def active_count(self) -> int: ...


@dataclass
class SessionInfo:
    handle: int
    created_utc: datetime


class SessionManager:
    """Thread-safe session manager for EtherNet/IP encapsulation sessions."""

    def __init__(self):
        self._sessions: dict[int, SessionInfo] = {}
        self._next_handle = 0
        self._lock = threading.Lock()

    def register(self) -> int:
        with self._lock:
            self._next_handle += 1
            handle = self._next_handle
        self._sessions[handle] = SessionInfo(handle=handle, created_utc=datetime.now(timezone.utc))
        return handle

    def unregister(self, handle: int) -> bool:
        return self._sessions.pop(handle, None) is not None

    def is_valid(self, handle: int) -> bool:
        return handle in self._sessions

    @property
    def active_count(self) -> int:
        return len(self._sessions)
