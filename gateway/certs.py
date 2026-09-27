"""Certificate loading, validation and atomic hot-reload.

Reload protocol: a new CertBundle is fully built and validated *before* the
store swaps it in. The store replaces its whole mapping (copy-on-write), so
readers always observe a complete, consistent snapshot — a new connection
never sees a half-updated cert/key pair, and in-flight connections keep the
bundle they started with.
"""

from __future__ import annotations

import hashlib
import ssl
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .config import VHostConfig


class CertLoadError(Exception):
    """Raised when a certificate/key pair cannot be loaded or validated."""


@dataclass(frozen=True)
class CertBundle:
    """An immutable, fully-validated cert/key pair plus its TLS context."""

    hostname: str
    context: ssl.SSLContext
    not_before: float
    not_after: float
    fingerprint: str
    version: int


def _public_key_der(obj) -> bytes:
    return obj.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _build_context(config: VHostConfig) -> ssl.SSLContext:
    """Per-vhost context carrying only the server certificate chain.

    Client-certificate policy is enforced by the gateway's dispatcher
    context and the application layer (see clientauth.py): OpenSSL fixes
    the verify mode when the handshake starts, before SNI can switch
    contexts, so per-context verify modes would not take effect anyway.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(config.cert_path), keyfile=str(config.key_path))
    return ctx


def load_bundle(config: VHostConfig, version: int = 0) -> CertBundle:
    """Load and validate a cert/key pair. Raises CertLoadError on any failure."""
    host = config.hostname
    try:
        cert_pem = Path(config.cert_path).read_bytes()
    except OSError as exc:
        raise CertLoadError(f"{host}: cannot read certificate: {exc}") from exc
    try:
        key_pem = Path(config.key_path).read_bytes()
    except OSError as exc:
        raise CertLoadError(f"{host}: cannot read private key: {exc}") from exc

    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError as exc:
        raise CertLoadError(f"{host}: malformed certificate: {exc}") from exc
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError) as exc:
        raise CertLoadError(f"{host}: malformed private key: {exc}") from exc

    if _public_key_der(cert) != _public_key_der(key):
        raise CertLoadError(f"{host}: certificate and private key do not match")

    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if now < not_before:
        raise CertLoadError(f"{host}: certificate not valid before {not_before.isoformat()}")
    if now > not_after:
        raise CertLoadError(f"{host}: certificate expired at {not_after.isoformat()}")

    try:
        ctx = _build_context(config)
    except (ssl.SSLError, OSError) as exc:
        raise CertLoadError(f"{host}: cannot build TLS context: {exc}") from exc

    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return CertBundle(
        hostname=host,
        context=ctx,
        not_before=not_before.timestamp(),
        not_after=not_after.timestamp(),
        fingerprint=fingerprint,
        version=version,
    )


class CertStore:
    """Holds the current CertBundle per hostname; supports atomic reload."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._bundles: dict[str, CertBundle] = {}

    def load_initial(self, configs) -> dict[str, CertLoadError | None]:
        """Load every vhost; failures are reported, never raised.

        A missing, corrupt or expired certificate only disables its own
        hostname — all other virtual hosts remain available.
        """
        errors: dict[str, CertLoadError | None] = {}
        for config in configs:
            try:
                bundle = load_bundle(config)
            except CertLoadError as exc:
                errors[config.hostname] = exc
                continue
            with self._lock:
                new = dict(self._bundles)
                new[config.hostname] = bundle
                self._bundles = new
            errors[config.hostname] = None
        return errors

    def get(self, hostname: str) -> CertBundle | None:
        return self._bundles.get(hostname)

    def reload(self, config: VHostConfig) -> CertBundle:
        """Build a fresh bundle and swap it in atomically.

        On failure the previous bundle stays active and CertLoadError is
        raised, so a bad update never interrupts service.
        """
        with self._lock:
            old = self._bundles.get(config.hostname)
            version = (old.version + 1) if old else 0
        bundle = load_bundle(config, version=version)
        with self._lock:
            new = dict(self._bundles)
            new[config.hostname] = bundle
            self._bundles = new
        return bundle

    def hostnames(self) -> list[str]:
        return sorted(self._bundles)
