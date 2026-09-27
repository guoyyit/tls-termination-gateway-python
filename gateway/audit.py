"""Structured audit logging for certificate and client-auth events.

Audit records are stable and correlatable: every event carries a
monotonically increasing sequence number, an ISO-8601 UTC timestamp and a
fixed event type. Records never contain private key material or request
bodies; only hostnames, failure reasons and public-key fingerprints.
"""

from __future__ import annotations

import enum
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


class AuditEventType(enum.Enum):
    CERT_LOADED = "cert_loaded"
    CERT_LOAD_FAILED = "cert_load_failed"
    CERT_RELOADED = "cert_reloaded"
    CERT_SELECTED = "cert_selected"
    CERT_DEFAULT_USED = "cert_default_used"
    CLIENT_CERT_OK = "client_cert_ok"
    CLIENT_CERT_MISSING = "client_cert_missing"
    CLIENT_CERT_INVALID = "client_cert_invalid"
    SESSION_CACHE_EVICTED = "session_cache_evicted"
    SESSION_KEYS_ROTATED = "session_keys_rotated"
    CONNECTION_REJECTED = "connection_rejected"
    SLOW_CLIENT_TIMEOUT = "slow_client_timeout"


@dataclass(frozen=True)
class AuditEvent:
    """A single audit record. Never carries private keys or request bodies."""

    event_type: AuditEventType
    message: str
    hostname: str | None = None
    reason: str | None = None
    detail: dict | None = None
    seq: int = field(default=0, compare=False)
    timestamp: str = field(default="", compare=False)

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "message": self.message,
            "hostname": self.hostname,
            "reason": self.reason,
            "detail": self.detail or {},
        }


class AuditLogger:
    """Records audit events to memory and (optionally) a JSONL file sink."""

    def __init__(self, log_path: str | Path | None = None) -> None:
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()
        self._seq = 0
        self._file = open(log_path, "a", encoding="utf-8") if log_path else None

    def record(self, event: AuditEvent) -> None:
        with self._lock:
            self._seq += 1
            stamped = AuditEvent(
                event_type=event.event_type,
                message=event.message,
                hostname=event.hostname,
                reason=event.reason,
                detail=event.detail,
                seq=self._seq,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            self._events.append(stamped)
            if self._file is not None:
                self._file.write(json.dumps(stamped.to_dict()) + "\n")
                self._file.flush()

    def events(self) -> list[AuditEvent]:
        with self._lock:
            return list(self._events)

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.close()
                self._file = None
