"""Bounded TLS session registry with epoch-based invalidation.

OpenSSL keeps its own session state (TLS 1.2 session IDs / TLS 1.3 session
tickets) inside each ``SSLContext``.  Recreating a context (on cert reload or
session-key rotation) inherently invalidates sessions negotiated under it.

This registry is the gateway-level, *bounded* bookkeeping layer on top of
that:

* it caps the number of remembered sessions (LRU eviction), so a long-running
  process cannot grow without limit;
* every entry is tagged with an epoch; :meth:`SessionCache.rotate` bumps the
  epoch and wipes the registry, guaranteeing no session survives a session
  key rotation and no stale session is ever resumed.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True)
class SessionInfo:
    session_id: str
    vhost: str
    epoch: int
    has_ticket: bool


class SessionCache:
    """Thread-safe bounded mapping of session id -> :class:`SessionInfo`.

    The class is deliberately lock-based (not asyncio-locks) because OpenSSL's
    SNI/verify callbacks execute in a thread-pool context where coroutine
    locks are unusable.  Critical sections are O(1), so contention is tiny.
    """

    def __init__(self, max_entries: int = 4096) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._max = max_entries
        self._entries: OrderedDict[str, SessionInfo] = OrderedDict()
        self._epoch = 0
        self._lock = threading.Lock()

    @property
    def epoch(self) -> int:
        with self._lock:
            return self._epoch

    def put(self, info: SessionInfo) -> None:
        """Insert or refresh *info*; evicts least-recently-used over the cap.

        Entries from a previous epoch are never stored: callers observe the
        post-rotation world only.
        """
        with self._lock:
            if info.epoch != self._epoch:
                return
            if info.session_id in self._entries:
                self._entries.move_to_end(info.session_id)
            self._entries[info.session_id] = info
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)

    def get(self, session_id: str) -> SessionInfo | None:
        """Return live info, or ``None`` when absent or from an old epoch."""
        with self._lock:
            info = self._entries.get(session_id)
            if info is None:
                return None
            if info.epoch != self._epoch:
                # Defensive: a rotated entry must never be treated as live.
                self._entries.pop(session_id, None)
                return None
            self._entries.move_to_end(session_id)
            return info

    def discard(self, session_id: str) -> None:
        with self._lock:
            self._entries.pop(session_id, None)

    def rotate(self) -> int:
        """Advance the epoch and invalidate every cached session.

        Returns the new epoch number.
        """
        with self._lock:
            self._epoch += 1
            self._entries.clear()
            return self._epoch

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
