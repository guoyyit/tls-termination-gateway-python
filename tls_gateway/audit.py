"""Audit logging for certificate and client-cert verification events.

Audit records are JSON lines with a stable schema:

    ts, event, correlation_id, vhost, reason, extra{...}

Only an explicit whitelist of non-sensitive keys is allowed in ``extra``.
Private keys, PEM material, certificates' full subjects, request headers and
bodies are never accepted into an audit record, so the audit trail cannot
leak key material or request-sensitive content.
"""

from __future__ import annotations

import enum
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

# Keys that may legally appear in a record's ``extra`` section.  Anything
# else is dropped (and counted as redacted) rather than emitted.
_ALLOWED_EXTRA_KEYS = frozenset(
    {
        "fingerprint",
        "not_before",
        "not_after",
        "serial_number",
        "cipher",
        "version",
        "client_subject_cn",  # CN only, kept for diagnosis
        "client_issuer_cn",
        "has_ticket",
        "session_reused",
        "peer",
        "epoch",
        "active_connections",
        "error_type",
    }
)


class AuditEvent(str, enum.Enum):
    CERT_LOADED = "cert_loaded"
    CERT_LOAD_FAILED = "cert_load_failed"
    CERT_SELECTED = "cert_selected"
    CERT_DEFAULT_USED = "cert_default_used"
    CLIENT_CERT_REQUIRED = "client_cert_required"
    CLIENT_CERT_FAILED = "client_cert_failed"
    CLIENT_CERT_OK = "client_cert_ok"
    SESSION_ROTATED = "session_rotated"
    CONNECTION_REJECTED = "connection_rejected"
    GATEWAY_STOPPED = "gateway_stopped"


@dataclass(frozen=True)
class AuditRecord:
    event: str
    vhost: str | None
    correlation_id: str
    reason: str | None = None
    extra: tuple[tuple[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "event": self.event,
            "correlation_id": self.correlation_id,
            "vhost": self.vhost,
        }
        if self.reason is not None:
            d["reason"] = self.reason
        if self.extra:
            d["extra"] = dict(self.extra)
        return d


def new_correlation_id() -> str:
    """Stable id tying all audit rows of one TLS connection together."""
    return uuid.uuid4().hex


class AuditLogger:
    """Writes structured audit records, redacting sensitive content."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("tls_gateway.audit")
        self._lock = threading.Lock()

    def emit(
        self,
        event: AuditEvent,
        *,
        vhost: str | None,
        correlation_id: str,
        reason: str | None = None,
        **extra: Any,
    ) -> AuditRecord:
        safe_extra = {
            k: v for k, v in extra.items() if k in _ALLOWED_EXTRA_KEYS
        }
        record = AuditRecord(
            event=event.value,
            vhost=vhost,
            correlation_id=correlation_id,
            reason=reason,
            extra=tuple(sorted(safe_extra.items())),
        )
        line = json.dumps(
            {
                "ts": round(time.time(), 3),
                **record.to_dict(),
            },
            separators=(",", ":"),
            sort_keys=True,
            default=str,
        )
        with self._lock:
            self._logger.info(line)
        return record
