"""Bounded TLS session cache with TTL and key-rotation invalidation.

Semantics (see README):
  * bounded: at most ``max_size`` entries; the least-recently-used entry is
    evicted when the cache is full, so long-running processes never grow
    without limit;
  * TTL: every entry expires ``ttl`` seconds after it was stored; expired
    entries are never returned and are purged lazily;
  * rotation: every entry is tagged with the session-key generation that
    issued it. ``rotate_keys()`` bumps the generation and purges all entries
    issued under older generations, so a rotated-out session ticket can
    never be replayed.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Callable


class BoundedSessionCache:
    """LRU session cache bound by size and TTL."""

    def __init__(
        self,
        max_size: int,
        ttl: float,
        time_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        self._max_size = max_size
        self._ttl = ttl
        self._time = time_fn
        self._generation = 0
        # session_id -> (ticket, expires_at, generation)
        self._entries: OrderedDict[bytes, tuple[bytes, float, int]] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def generation(self) -> int:
        return self._generation

    def _purge_expired_locked(self, now: float) -> int:
        stale = [sid for sid, (_, exp, _) in self._entries.items() if exp <= now]
        for sid in stale:
            del self._entries[sid]
        return len(stale)

    def put(self, session_id: bytes, ticket: bytes) -> None:
        now = self._time()
        with self._lock:
            self._purge_expired_locked(now)
            if session_id in self._entries:
                del self._entries[session_id]
            while len(self._entries) >= self._max_size:
                self._entries.popitem(last=False)  # evict LRU
            self._entries[session_id] = (ticket, now + self._ttl, self._generation)

    def get(self, session_id: bytes) -> bytes | None:
        now = self._time()
        with self._lock:
            entry = self._entries.get(session_id)
            if entry is None:
                return None
            ticket, expires_at, generation = entry
            if expires_at <= now or generation != self._generation:
                # expired, or issued under a rotated-out key generation
                del self._entries[session_id]
                return None
            self._entries.move_to_end(session_id)
            return ticket

    def rotate_keys(self) -> int:
        """Rotate the session-key generation; invalidate all prior entries."""
        with self._lock:
            self._generation += 1
            self._entries.clear()
            return self._generation

    def __len__(self) -> int:
        with self._lock:
            self._purge_expired_locked(self._time())
            return len(self._entries)
