"""Per-vhost client certificate verification."""

from __future__ import annotations

import pytest

import certgen
from conftest import audit_types, https_request, start_gateway
from gateway.audit import AuditEventType
from gateway.config import ClientAuthMode


@pytest.fixture()
def secure_vhost(cert_layout):
    return cert_layout.make_vhost(
        "secure.example.com",
        client_auth=ClientAuthMode.REQUIRED,
        client_ca_path=cert_layout.ca_cert,
    )


def _client_cert(layout, ca_name: str, suffix: str):
    """A client certificate; ca_name='main' signs with the layout CA,
    anything else creates a fresh CA of that name."""
    from cryptography import x509

    if ca_name == "main":
        ca = x509.load_pem_x509_certificate(layout.ca_cert.read_bytes())
        return certgen.make_leaf(
            layout.base, "client", ca, layout.ca_key, client=True, name_suffix=suffix
        )
    _, ca_key, ca = certgen.make_ca(layout.base, name=ca_name)
    return certgen.make_leaf(
        layout.base, "client", ca, ca_key, client=True, name_suffix=suffix
    )


async def test_missing_client_cert_rejected_with_reason(cert_layout, backend, secure_vhost):
    gw = await start_gateway(cert_layout, backend.port, vhosts=(secure_vhost,))
    try:
        result = await https_request(gw.port, sni="secure.example.com", layout=cert_layout)
        assert result.status == 403
        assert result.headers.get("x-gateway-error") == "missing_client_certificate"
        assert b"client certificate required" in result.body
        # the request must not reach the backend
        assert backend.requests == []
        missing = [
            e for e in gw.audit.events() if e.event_type is AuditEventType.CLIENT_CERT_MISSING
        ]
        assert missing and missing[-1].hostname == "secure.example.com"
    finally:
        await gw.server.stop()


async def test_valid_client_cert_accepted(cert_layout, backend, secure_vhost):
    gw = await start_gateway(cert_layout, backend.port, vhosts=(secure_vhost,))
    try:
        crt, key = _client_cert(cert_layout, "main", ".ok")
        result = await https_request(
            gw.port, sni="secure.example.com", layout=cert_layout, client_cert=(crt, key)
        )
        assert result.status == 200
        assert len(backend.requests) == 1
        assert AuditEventType.CLIENT_CERT_OK in audit_types(gw.audit)
    finally:
        await gw.server.stop()


async def test_untrusted_ca_client_cert_rejected_at_tls_layer(
    cert_layout, backend, secure_vhost
):
    """A client cert chaining to an unknown CA fails TLS verification;
    the connection is dropped and the failure is audited with the
    distinguishable OpenSSL verify reason."""
    import asyncio
    import ssl

    gw = await start_gateway(cert_layout, backend.port, vhosts=(secure_vhost,))
    try:
        crt, key = _client_cert(cert_layout, "Unknown CA", ".unknown")
        # TLS 1.3: the client finishes its handshake before the server
        # rejects the certificate, so the failure surfaces on first use
        with pytest.raises((ssl.SSLError, ConnectionError, asyncio.IncompleteReadError)):
            await https_request(
                gw.port, sni="secure.example.com", layout=cert_layout, client_cert=(crt, key)
            )
        invalid = None
        for _ in range(50):
            invalid = next(
                (
                    e
                    for e in gw.audit.events()
                    if e.event_type is AuditEventType.CLIENT_CERT_INVALID
                ),
                None,
            )
            if invalid is not None:
                break
            await asyncio.sleep(0.02)
        assert invalid is not None, "expected CLIENT_CERT_INVALID audit event"
        assert invalid.reason  # e.g. "unable to get local issuer certificate"
        assert backend.requests == []
    finally:
        await gw.server.stop()


async def test_cert_valid_for_other_vhost_rejected_with_distinct_reason(
    cert_layout, backend, secure_vhost
):
    """A client cert trusted deployment-wide but not by *this* vhost must
    fail with a distinguishable reason and an audit record."""
    # second vhost trusting a different CA, so the dispatcher's union trust
    # accepts the certificate at TLS level and the per-vhost check decides
    _, other_ca_key, _ = certgen.make_ca(cert_layout.base, name="Other CA")
    other_vhost = cert_layout.make_vhost(
        "other.example.com",
        client_auth=ClientAuthMode.REQUIRED,
        client_ca_path=cert_layout.base / "Other CA.crt.pem",
    )
    gw = await start_gateway(
        cert_layout, backend.port, vhosts=(secure_vhost, other_vhost)
    )
    try:
        # cert signed by the *main* CA (valid for secure.example.com) is
        # presented to other.example.com, which trusts only "Other CA"
        crt, key = _client_cert(cert_layout, "main", ".cross")
        result = await https_request(
            gw.port, sni="other.example.com", layout=cert_layout, client_cert=(crt, key)
        )
        assert result.status == 403
        assert result.headers.get("x-gateway-error") == "untrusted_client_certificate"
        assert backend.requests == []
        invalid = [
            e for e in gw.audit.events() if e.event_type is AuditEventType.CLIENT_CERT_INVALID
        ]
        assert invalid, "expected CLIENT_CERT_INVALID audit event"
        assert invalid[-1].hostname == "other.example.com"
        assert invalid[-1].reason  # distinguishable verification failure reason
    finally:
        await gw.server.stop()


async def test_client_auth_is_per_vhost(cert_layout, backend, secure_vhost):
    """The REQUIRED policy must not leak onto other virtual hosts."""
    gw = await start_gateway(cert_layout, backend.port, vhosts=(secure_vhost,))
    try:
        # default vhost (client_auth=NONE) still serves without a client cert
        result = await https_request(gw.port, sni="localhost", layout=cert_layout)
        assert result.status == 200
    finally:
        await gw.server.stop()
