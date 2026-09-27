"""Virtual-host registry: SNI-based certificate selection.

Selection order (see README):
  1. exact match of the normalized SNI server name against loaded vhosts
  2. otherwise (unknown name, no SNI, lookup error) the default certificate

The default certificate is resolved through the CertStore on every lookup,
so hot-reloading the default vhost takes effect for new connections too.
"""

from __future__ import annotations

import ssl
import weakref

from .audit import AuditEvent, AuditEventType, AuditLogger
from .certs import CertBundle, CertStore
from .config import ClientAuthMode, VHostConfig


def normalize_hostname(name: str | None) -> str | None:
    if name is None:
        return None
    name = name.strip().rstrip(".").lower()
    return name or None


class VHostRegistry:
    """Resolves the TLS context for a requested server name (SNI)."""

    def __init__(
        self,
        store: CertStore,
        default_hostname: str,
        default_config: VHostConfig,
        vhost_configs: dict[str, VHostConfig],
        audit: AuditLogger,
    ) -> None:
        self._store = store
        self._default_hostname = normalize_hostname(default_hostname) or default_hostname
        self._default_config = default_config
        self._configs = {
            (normalize_hostname(h) or h): c for h, c in vhost_configs.items()
        }
        self._audit = audit
        # hostname chosen during the handshake, keyed by the SSLObject itself
        self._selected: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        # Union of all vhost client CAs. OpenSSL consults the *switched-to*
        # context when building the CertificateRequest, so every context
        # involved in a handshake must carry the same client-CA setup.
        self._client_cas = sorted(
            {
                str(c.client_ca_path)
                for c in self._configs.values()
                if c.client_auth is not ClientAuthMode.NONE and c.client_ca_path
            }
        )
        # contexts already fully configured (client auth + SNI callback);
        # configuration mutates the shared context, so do it exactly once
        self._configured: weakref.WeakSet = weakref.WeakSet()
        for bundle_hostname in store.hostnames():
            bundle = store.get(bundle_hostname)
            if bundle is not None:
                self._configure_client_auth(bundle.context)

    def _configure_client_auth(self, context: ssl.SSLContext) -> ssl.SSLContext:
        """Request (and union-verify) client certificates if any vhost needs them."""
        if context in self._configured:
            return context
        if self._client_cas:
            context.verify_mode = ssl.CERT_OPTIONAL
            for ca in self._client_cas:
                context.load_verify_locations(cafile=ca)
        self._configured.add(context)
        return context

    def bootstrap_context(self) -> ssl.SSLContext:
        """The context the listening socket starts each handshake on.

        This is the *current* default vhost bundle's own context (or any
        loaded vhost's, if the default is unavailable, so the gateway stays
        up for the hostnames that work). The SNI callback switches each
        handshake to the selected vhost's context.

        Reusing the bundle context (instead of a dedicated dispatcher
        context) keeps TLS session tickets working for the default vhost:
        OpenSSL scopes ticket keys per SSLContext, and CPython offers no
        API to share them across contexts. See README "Session cache".
        """
        bundle = self._store.get(self._default_hostname)
        if bundle is None:
            names = self._store.hostnames()
            if not names:
                raise RuntimeError(
                    f"default certificate for {self._default_hostname!r} is not "
                    "loaded and no other virtual host is available"
                )
            bundle = self._store.get(names[0])
            self._audit.record(
                AuditEvent(
                    AuditEventType.CERT_DEFAULT_USED,
                    "default certificate unavailable; listener bootstrapped "
                    "with another virtual host",
                    hostname=names[0],
                    reason="default certificate missing",
                )
            )
        ctx = bundle.context
        self._configure_client_auth(ctx)
        ctx.sni_callback = self.sni_callback
        return ctx

    def reload(self, config: VHostConfig) -> "CertBundle":
        """Hot-reload one vhost; the new bundle is swapped in atomically."""
        bundle = self._store.reload(config)
        self._configure_client_auth(bundle.context)
        self._audit.record(
            AuditEvent(
                AuditEventType.CERT_RELOADED,
                "certificate reloaded",
                hostname=bundle.hostname,
                detail={"version": bundle.version, "fingerprint": bundle.fingerprint},
            )
        )
        return bundle

    def config_for(self, hostname: str | None) -> VHostConfig:
        """The vhost config for a (normalized) hostname, else the default's."""
        key = normalize_hostname(hostname)
        config = self._configs.get(key) if key else None
        return config if config is not None else self._default_config

    def client_auth_mode(self, hostname: str | None) -> ClientAuthMode:
        return self.config_for(hostname).client_auth

    def selected_hostname(self, sslobj: ssl.SSLObject) -> str | None:
        """Hostname chosen for this connection during the SNI callback."""
        try:
            return self._selected.get(sslobj)
        except TypeError:
            return None

    def sni_callback(
        self, sslobj: ssl.SSLObject, server_name: str | None, ctx: ssl.SSLContext
    ) -> None:
        hostname = normalize_hostname(server_name)
        try:
            bundle = self._store.get(hostname) if hostname else None
        except Exception as exc:  # lookup failure must not break other vhosts
            self._audit.record(
                AuditEvent(
                    AuditEventType.CERT_DEFAULT_USED,
                    "certificate lookup failed; falling back to default",
                    hostname=hostname,
                    reason=str(exc),
                )
            )
            bundle = None

        if bundle is not None:
            sslobj.context = bundle.context
            self._selected[sslobj] = bundle.hostname
            self._audit.record(
                AuditEvent(
                    AuditEventType.CERT_SELECTED,
                    "virtual host certificate selected",
                    hostname=bundle.hostname,
                    detail={"version": bundle.version, "fingerprint": bundle.fingerprint},
                )
            )
            return

        # unknown / missing SNI -> switch to the *current* default bundle,
        # so hot-reloads of the default certificate take effect immediately
        default = self._store.get(self._default_hostname)
        if default is not None:
            sslobj.context = default.context
        self._selected[sslobj] = self._default_hostname
        self._audit.record(
            AuditEvent(
                AuditEventType.CERT_DEFAULT_USED,
                "no matching virtual host; default certificate used",
                hostname=hostname,
                reason="no SNI provided" if hostname is None else "unknown hostname",
            )
        )
