"""Virtual-host certificate store with atomic hot-reload semantics.

Certificate selection order
----------------------------
1. TLS SNI hostname matching a configured virtual host -> that host's cert.
2. SNI unknown / absent / matching host currently unhealthy -> default cert.

Hot reload
----------
Reloading a host first constructs a *brand new* ``SSLContext`` holding the
new chain; it is published only after the full chain (cert AND key) has been
successfully loaded.  Consequently:

* a new connection never observes a half-updated cert/key pair (no mismatch
  window);
* an already established connection keeps using the context it completed its
  handshake with, so reloads never interrupt live connections.

Client certificate verification
-------------------------------
Hosts configured with ``require_client_cert`` use ``CERT_REQUIRED``; OpenSSL
verifies the chain during the handshake and aborts with a specific TLS alert
(expired / unknown CA / certificate required ...).  The gateway classifies
the resulting ``ssl.SSLError`` into a stable reason code for auditing.
"""

from __future__ import annotations

import contextvars
import datetime as _dt
import ssl
import threading
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from tls_gateway.audit import AuditEvent, AuditLogger, new_correlation_id
from tls_gateway.config import VHostConfig
from tls_gateway.errors import (
    CertificateExpired,
    CertificateInvalid,
    CertificateNotFound,
)
from tls_gateway.session_cache import SessionCache

# Placeholder key (id() of the per-connection state dict) published by the
# gateway before driving the handshake.  The SNI callback runs synchronously
# inside start_tls on the same task, so it sees this value and can rebind the
# state to the inner SSL object id.
_HANDSHAKE_KEY: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "handshake_state_key", default=None
)

# Stable classification of client-side TLS verification failures.  The match
# uses substrings of OpenSSL's (version-independent) reason phrases.
_CLIENT_REASON_PATTERNS: tuple[tuple[str, str], ...] = (
    ("PEER_DID_NOT_RETURN_A_CERTIFICATE", "client_cert_absent"),
    ("certificate required", "client_cert_absent"),
    ("certificate has expired", "client_cert_expired"),
    ("is not yet", "client_cert_not_yet_valid"),
    ("self signed certificate in certificate chain", "client_cert_self_signed_chain"),
    ("self-signed certificate in certificate chain", "client_cert_self_signed_chain"),
    ("self signed certificate", "client_cert_self_signed"),
    ("self-signed", "client_cert_self_signed"),
    ("unable to get local issuer certificate", "client_cert_unknown_ca"),
    ("unable to verify the first certificate", "client_cert_unknown_ca"),
    ("unsupported certificate purpose", "client_cert_invalid_purpose"),
    ("invalid certificate purpose", "client_cert_invalid_purpose"),
    ("certificate revoked", "client_cert_revoked"),
    ("certificate signature failure", "client_cert_bad_signature"),
    ("bad certificate", "client_cert_bad"),
    ("unknown ca", "client_cert_unknown_ca"),
    ("CERTIFICATE_VERIFY_FAILED", "client_cert_verify_failed"),
)


def classify_client_cert_error(exc: BaseException) -> str:
    """Map an OpenSSL handshake failure to a stable client-cert reason code."""
    text = str(exc)
    for needle, code in _CLIENT_REASON_PATTERNS:
        if needle in text:
            return code
    return "client_cert_failed"


# Per-connection handshake state.
#
# The SNI callback runs synchronously inside ``loop.start_tls`` on the same
# task/thread, so the gateway publishes a mutable state dict via a
# contextvar-backed registry before upgrading; the callback fills in the
# selected vhost / correlation id.  Entries are keyed by id(inner ``SSL``),
# which is stable between the callback's ``conn`` and the post-handshake
# ``ssl_object``.  A placeholder key (the dict id) covers clients with no SNI.
_PENDING: dict[int, dict[str, str | None]] = {}
_PENDING_LOCK = threading.Lock()


def save_handshake_state(key: int, state: dict[str, str | None]) -> None:
    with _PENDING_LOCK:
        _PENDING[key] = state


def update_handshake_state(
    old_key: int, new_key: int, state: dict[str, str | None]
) -> None:
    with _PENDING_LOCK:
        _PENDING.pop(old_key, None)
        _PENDING[new_key] = state


def take_handshake_state_by_key(key: int) -> dict[str, str | None] | None:
    with _PENDING_LOCK:
        return _PENDING.pop(key, None)


def _load_x509(cert_file: str) -> x509.Certificate:
    """Parse the leaf certificate from PEM or DER."""
    try:
        with open(cert_file, "rb") as fh:
            data = fh.read()
    except FileNotFoundError as exc:
        raise CertificateNotFound(str(cert_file)) from exc
    except OSError as exc:
        raise CertificateInvalid(str(cert_file)) from exc
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        try:
            return x509.load_der_x509_certificate(data)
        except Exception as exc:
            raise CertificateInvalid(f"unparseable certificate: {cert_file}") from exc


def _validate_key_pair(cert: x509.Certificate, key_file: str) -> None:
    """Read private key and confirm it matches the certificate public key."""
    try:
        with open(key_file, "rb") as fh:
            key_data = fh.read()
    except FileNotFoundError as exc:
        raise CertificateNotFound(str(key_file)) from exc
    except OSError as exc:
        raise CertificateInvalid(str(key_file)) from exc
    try:
        private_key = serialization.load_pem_private_key(key_data, password=None)
    except Exception:
        try:
            private_key = serialization.load_der_private_key(key_data, password=None)
        except Exception as exc:
            raise CertificateInvalid(f"unparseable private key: {key_file}") from exc
    if private_key is None:
        raise CertificateInvalid(f"encrypted/unsupported private key: {key_file}")
    cert_pub = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_pub = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if cert_pub != key_pub:
        raise CertificateInvalid("certificate and private key do not match")


def _check_validity(cert: x509.Certificate) -> None:
    now = _dt.datetime.now(_dt.timezone.utc)
    if now < cert.not_valid_before_utc:
        raise CertificateExpired("certificate is not yet valid")
    if now > cert.not_valid_after_utc:
        raise CertificateExpired("certificate has expired")


def cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def apply_server_session_policy(ctx: ssl.SSLContext) -> None:
    """Configure stateful, server-managed TLS sessions.

    Stateless session tickets are disabled so negotiated sessions carry a
    session id that OpenSSL stores in the (bounded, ephemeral) server session
    cache of *this* context.  Rebuilding a context on reload/rotation creates a
    fresh cache and fresh keys, so prior sessions can no longer resume.  This
    makes resumption observable and keeps it tightly coupled to the rotation
    boundary, instead of relying on long-lived, opaque stateless tickets.
    """
    ctx.options |= ssl.OP_NO_TICKET


def leaf_cn(cert_der: bytes) -> str | None:
    """Best-effort extraction of the leaf certificate CN for audit."""
    try:
        cert = x509.load_der_x509_certificate(cert_der)
        names = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        return names[0].value if names else None
    except Exception:
        return None


@dataclass(frozen=True)
class CertEntry:
    """Immutable, hot-swappable certificate snapshot for one hostname."""

    vhost: str | None  # None marks the default entry
    context: ssl.SSLContext
    not_before: float
    not_after: float
    fingerprint: str
    require_client_cert: bool
    cert_file: str
    key_file: str
    client_ca_file: str | None = None


@dataclass(frozen=True)
class CertSnapshot:
    default: CertEntry | None
    vhosts: dict[str, CertEntry]

    def select(self, server_name: str | None) -> CertEntry | None:
        if server_name is not None:
            entry = self.vhosts.get(server_name)
            if entry is not None:
                return entry
        return self.default


class CertificateStore:
    """Loads, serves and atomically reloads virtual-host certificates."""

    def __init__(self, session_cache: SessionCache, audit: AuditLogger) -> None:
        self._sessions = session_cache
        self._audit = audit
        self._lock = threading.Lock()
        self._snapshot = CertSnapshot(default=None, vhosts={})
        # Union of client-CA files across vhosts that require client certs.
        # The front context verifies in CERT_OPTIONAL mode (request a cert;
        # if one is offered it MUST verify, else the handshake fails).  The
        # per-vhost decision to *require* one is enforced after the handshake.
        # This is necessary because SSL_set_SSL_CTX (SNI swap) does not apply
        # a swapped context's verify_mode to the already-created connection.
        self._client_cas: frozenset[str] = frozenset()
        # The single "front" context handed to asyncio.start_server.  Its own
        # chain is the default certificate; the SNI callback swaps in a vhost's
        # immutable entry context per connection when SNI matches.
        self._front: ssl.SSLContext | None = None

    # ------------------------------------------------------------------ views
    @property
    def snapshot(self) -> CertSnapshot:
        return self._snapshot

    @property
    def front_context(self) -> ssl.SSLContext | None:
        return self._front

    def select(self, server_name: str | None) -> CertEntry | None:
        return self._snapshot.select(server_name)

    # --------------------------------------------------------------- building
    def _new_context(
        self,
        entry: CertEntry | None,
        cert_file: str,
        key_file: str,
        require_client_cert: bool,
        client_ca_file: str | None,
    ) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        apply_server_session_policy(ctx)
        # load_cert_chain validates cert/key atomically; if it fails the just
        # created context is discarded and nothing published changes.
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        # A context swapped in by the SNI callback carries verification state
        # with it (SSL_set_SSL_CTX replaces it), so every entry context must
        # share the gateway-wide client-verification posture: CERT_OPTIONAL
        # plus the union of trusted client CAs.  Host-level "required" is
        # enforced after the handshake by checking getpeercert().
        for ca in sorted(self._client_cas):
            try:
                ctx.load_verify_locations(cafile=ca)
            except ssl.SSLError:
                continue
        if self._client_cas:
            ctx.verify_mode = ssl.CERT_OPTIONAL
        return ctx

    def _make_entry(
        self,
        vhost: str | None,
        cert_file: str,
        key_file: str,
        require_client_cert: bool = False,
        client_ca_file: str | None = None,
    ) -> CertEntry:
        cert = _load_x509(cert_file)
        _validate_key_pair(cert, key_file)
        _check_validity(cert)
        ctx = self._new_context(
            None, cert_file, key_file, require_client_cert, client_ca_file
        )
        return CertEntry(
            vhost=vhost,
            context=ctx,
            not_before=cert.not_valid_before_utc.timestamp(),
            not_after=cert.not_valid_after_utc.timestamp(),
            fingerprint=cert_fingerprint(cert),
            require_client_cert=require_client_cert,
            cert_file=cert_file,
            key_file=key_file,
            client_ca_file=client_ca_file,
        )

    # ------------------------------------------------------------- public API
    def load_initial(
        self,
        configs: list[VHostConfig],
        default_cert: tuple[str, str] | None,
    ) -> dict[str, str]:
        """Load all configured vhosts at startup.

        Missing, corrupt or expired material for one host is reported in the
        returned ``{name: reason}`` map and never prevents other hosts or the
        default certificate from being served.
        """
        failures: dict[str, str] = {}
        vhosts: dict[str, CertEntry] = {}
        default_entry: CertEntry | None = None

        # Establish the gateway-wide trusted client-CA union before any entry
        # context is built, so every published context shares verify posture.
        self._client_cas = frozenset(
            str(cfg.client_ca_file)
            for cfg in configs
            if cfg.require_client_cert and cfg.client_ca_file
        )

        if default_cert is not None:
            cid = new_correlation_id()
            try:
                default_entry = self._make_entry(
                    None, default_cert[0], default_cert[1]
                )
                self._audit.emit(
                    AuditEvent.CERT_LOADED,
                    vhost="*default*",
                    correlation_id=cid,
                    fingerprint=default_entry.fingerprint,
                    not_before=default_entry.not_before,
                    not_after=default_entry.not_after,
                )
            except Exception as exc:  # noqa: BLE001 - isolate default failure
                reason = f"{type(exc).__name__}: {exc}"
                failures["*default*"] = reason
                self._audit.emit(
                    AuditEvent.CERT_LOAD_FAILED,
                    vhost="*default*",
                    correlation_id=cid,
                    reason=reason,
                )

        for cfg in configs:
            cid = new_correlation_id()
            try:
                entry = self._make_entry(
                    cfg.name,
                    str(cfg.cert_file),
                    str(cfg.key_file),
                    cfg.require_client_cert,
                    str(cfg.client_ca_file) if cfg.client_ca_file else None,
                )
                vhosts[cfg.name] = entry
                self._audit.emit(
                    AuditEvent.CERT_LOADED,
                    vhost=cfg.name,
                    correlation_id=cid,
                    fingerprint=entry.fingerprint,
                    not_before=entry.not_before,
                    not_after=entry.not_after,
                )
            except Exception as exc:  # noqa: BLE001 - isolate per host
                reason = f"{type(exc).__name__}: {exc}"
                failures[cfg.name] = reason
                self._audit.emit(
                    AuditEvent.CERT_LOAD_FAILED,
                    vhost=cfg.name,
                    correlation_id=cid,
                    reason=reason,
                )

        client_cas = frozenset(
            str(cfg.client_ca_file)
            for cfg in configs
            if cfg.require_client_cert and cfg.client_ca_file
        )
        front = self._make_front(default_entry, client_cas)
        with self._lock:
            self._client_cas = client_cas
            self._snapshot = CertSnapshot(default=default_entry, vhosts=vhosts)
            self._front = front
        return failures

    def _current_client_cas(self) -> frozenset[str]:
        return frozenset(
            e.client_ca_file
            for e in self._snapshot.vhosts.values()
            if e.require_client_cert and e.client_ca_file
        )

    def _refresh_front(self) -> ssl.SSLContext | None:
        """Rebuild the listener context from the current snapshot (CA union)."""
        front = self._make_front(self._snapshot.default)
        self._front = front
        return front

    def _make_front(
        self,
        default_entry: CertEntry | None,
        client_cas: frozenset[str] | None = None,
    ) -> ssl.SSLContext | None:
        """Build the listener context carrying the default chain + SNI hook."""
        if default_entry is None:
            return None
        front = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        front.minimum_version = ssl.TLSVersion.TLSv1_2
        apply_server_session_policy(front)
        front.load_cert_chain(
            certfile=default_entry.cert_file, keyfile=default_entry.key_file
        )
        cas = client_cas if client_cas is not None else self._client_cas
        if cas:
            # Request (do not force) a client certificate; if one is offered
            # it must chain to one of the trusted CAs, otherwise the handshake
            # aborts.  Host-level "required" is enforced post-handshake.
            front.verify_mode = ssl.CERT_OPTIONAL
            for ca in sorted(cas):
                try:
                    front.load_verify_locations(cafile=ca)
                except ssl.SSLError:
                    # One unreadable CA must not disable verification entirely
                    # for hosts trusted by the other CAs; it is diagnosed at
                    # vhost load time.
                    continue
        store = self

        def sni_cb(
            conn: ssl.SSLObject,
            server_name: str | None,
            _ctx: ssl.SSLContext,
        ) -> None:
            entry = store._snapshot.select(server_name)
            target = entry  # exact vhost match or default (may be None)

            # Reuse the per-connection state the gateway registered before the
            # handshake (same correlation id for SNI + verification events),
            # rebinding it from placeholder key to the inner SSL object id.
            placeholder = _HANDSHAKE_KEY.get()
            if placeholder is not None:
                with _PENDING_LOCK:
                    state = _PENDING.get(placeholder)
                if state is not None:
                    state["vhost"] = target.vhost if target else None
                    state["sni"] = server_name
                    state["inner_key"] = id(conn._sslobj)
                    update_handshake_state(
                        placeholder, id(conn._sslobj), state
                    )
                    cid = state["correlation_id"]
                else:
                    cid = new_correlation_id()
            else:
                cid = new_correlation_id()

            if target is None:
                return None
            if server_name is not None and target.vhost == server_name:
                store._audit.emit(
                    AuditEvent.CERT_SELECTED,
                    vhost=server_name,
                    correlation_id=cid,
                    fingerprint=target.fingerprint,
                )
            else:
                store._audit.emit(
                    AuditEvent.CERT_DEFAULT_USED,
                    vhost=None,
                    correlation_id=cid,
                    reason="sni_unmatched" if server_name else "sni_absent",
                )
            # Swap the immutable entry context into this connection only.
            conn.context = target.context
            return None

        front.set_servername_callback(sni_cb)
        return front

    def reload_vhost(self, config: VHostConfig) -> CertEntry:
        """Atomically replace one vhost's cert/key.

        The new entry is fully built and validated before publication; on any
        failure the old entry keeps serving all (including new) connections.
        """
        cid = new_correlation_id()
        entry = self._make_entry(
            config.name,
            str(config.cert_file),
            str(config.key_file),
            config.require_client_cert,
            str(config.client_ca_file) if config.client_ca_file else None,
        )
        with self._lock:
            vhosts = dict(self._snapshot.vhosts)
            vhosts[config.name] = entry
            self._snapshot = CertSnapshot(
                default=self._snapshot.default, vhosts=vhosts
            )
            # A changed verify requirement / CA set must reach new handshakes
            # consistently on every context (SNI swap carries verify state).
            new_cas = self._current_client_cas()
            if new_cas != self._client_cas:
                self._client_cas = new_cas
                self._reapply_verify_posture_locked()
            self._refresh_front()
        self._audit.emit(
            AuditEvent.CERT_LOADED,
            vhost=config.name,
            correlation_id=cid,
            fingerprint=entry.fingerprint,
            not_before=entry.not_before,
            not_after=entry.not_after,
        )
        return entry

    def _reapply_verify_posture_locked(self) -> None:
        """Rebuild every entry context so the CA union/verify mode is shared.

        Cert material is unchanged and re-read from the recorded file paths;
        the whole snapshot is replaced atomically.
        """
        rebuilt: dict[str, CertEntry] = {}
        for name, ent in self._snapshot.vhosts.items():
            try:
                rebuilt[name] = self._make_entry(
                    name,
                    ent.cert_file,
                    ent.key_file,
                    ent.require_client_cert,
                    ent.client_ca_file,
                )
            except Exception:  # noqa: BLE001 - keep prior entry if file vanished
                rebuilt[name] = ent
        default = self._snapshot.default
        new_default = default
        if default is not None:
            try:
                new_default = self._make_entry(
                    None, default.cert_file, default.key_file
                )
            except Exception:  # noqa: BLE001
                new_default = default
        self._snapshot = CertSnapshot(default=new_default, vhosts=rebuilt)

    def reload_default(self, cert_file: str, key_file: str) -> CertEntry:
        """Atomically replace the default cert/key and its listener context.

        A fresh front context carrying the new chain is published in one step;
        connections that already entered the handshake under the old context
        are unaffected.  Any failure leaves everything unchanged.
        """
        cid = new_correlation_id()
        entry = self._make_entry(None, cert_file, key_file)
        with self._lock:
            self._snapshot = CertSnapshot(
                default=entry, vhosts=self._snapshot.vhosts
            )
            # Build the new front under the current CA union, before anyone can
            # observe the change, so there is no half-updated window.
            new_front = self._make_front(entry)
            assert new_front is not None
            self._front = new_front
        self._audit.emit(
            AuditEvent.CERT_LOADED,
            vhost="*default*",
            correlation_id=cid,
            fingerprint=entry.fingerprint,
        )
        return entry
