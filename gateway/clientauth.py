"""Application-layer client certificate chain verification.

The TLS layer verifies presented client certificates against the union of
all vhost client CAs (a Python ssl limitation: the verify mode is fixed
when the handshake starts, before SNI chooses the vhost). To keep trust
strictly per-vhost, the presented certificate is verified again here,
against the *selected* vhost's own client CA.
"""

from __future__ import annotations

import threading
from pathlib import Path

from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError


class ClientCAStore:
    """Loads and caches client-CA trust stores keyed by file path."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stores: dict[Path, Store] = {}

    def store_for(self, ca_path: Path) -> Store:
        path = Path(ca_path)
        with self._lock:
            store = self._stores.get(path)
            if store is None:
                certs = x509.load_pem_x509_certificates(path.read_bytes())
                if not certs:
                    raise ValueError(f"no certificates found in {path}")
                store = Store(certs)
                self._stores[path] = store
            return store

    def verify(self, peer_der: bytes, ca_path: Path) -> str | None:
        """Return None if the peer certificate chains to ca_path, else a reason."""
        try:
            peer = x509.load_der_x509_certificate(peer_der)
        except ValueError:
            return "unparseable client certificate"
        try:
            store = self.store_for(ca_path)
        except (OSError, ValueError) as exc:
            return f"client CA unavailable: {exc}"
        try:
            verifier = PolicyBuilder().store(store).build_client_verifier()
            verifier.verify(peer, [])
        except VerificationError as exc:
            return str(exc)
        return None
