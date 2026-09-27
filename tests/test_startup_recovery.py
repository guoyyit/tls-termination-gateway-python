"""Startup recovery: missing, corrupt or expired certificates must not
take the whole gateway down."""

from __future__ import annotations

import pytest

import certgen
from conftest import audit_types, https_request, start_gateway
from gateway.audit import AuditEventType
from gateway.config import VHostConfig


def _corrupt(path, content=b"-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n"):
    path.write_bytes(content)
    return path


async def test_corrupt_vhost_cert_is_isolated(cert_layout, backend):
    broken = cert_layout.vhost("www.example.com")
    _corrupt(broken.cert_path)
    gw = await start_gateway(
        cert_layout,
        backend.port,
        vhosts=(broken, cert_layout.vhost("api.example.com")),
    )
    try:
        # the healthy vhost keeps serving
        result = await https_request(gw.port, sni="api.example.com", layout=cert_layout)
        assert result.status == 200
        bundle = gw.server._registry._store.get("api.example.com")
        assert result.cert_fingerprint == bundle.fingerprint

        # the broken vhost falls back to the default certificate
        result = await https_request(gw.port, sni="www.example.com", layout=cert_layout)
        assert result.status == 200
        default = gw.server._registry._store.get("localhost")
        assert result.cert_fingerprint == default.fingerprint

        # diagnosable audit record for the failure
        failed = [
            e for e in gw.audit.events() if e.event_type is AuditEventType.CERT_LOAD_FAILED
        ]
        assert len(failed) == 1
        assert failed[0].hostname == "www.example.com"
        assert "www.example.com" in failed[0].reason
    finally:
        await gw.server.stop()


async def test_expired_cert_is_rejected_but_isolated(cert_layout, backend):
    from cryptography import x509

    ca = x509.load_pem_x509_certificate(cert_layout.ca_cert.read_bytes())
    crt, key = certgen.make_leaf(
        cert_layout.base, "api.example.com", ca, cert_layout.ca_key,
        days_valid=0, not_before_offset_days=-2, name_suffix=".expired",
    )
    expired = VHostConfig("api.example.com", crt, key)
    gw = await start_gateway(cert_layout, backend.port, vhosts=(expired,))
    try:
        failed = [
            e for e in gw.audit.events() if e.event_type is AuditEventType.CERT_LOAD_FAILED
        ]
        assert failed and "expired" in failed[0].reason
        # default vhost unaffected
        result = await https_request(gw.port, sni="localhost", layout=cert_layout)
        assert result.status == 200
    finally:
        await gw.server.stop()


async def test_missing_key_file_is_diagnosed(cert_layout, backend):
    missing = cert_layout.vhost("www.example.com")
    missing.key_path.unlink()
    gw = await start_gateway(cert_layout, backend.port, vhosts=(missing,))
    try:
        failed = [
            e for e in gw.audit.events() if e.event_type is AuditEventType.CERT_LOAD_FAILED
        ]
        assert failed and "private key" in failed[0].reason
        result = await https_request(gw.port, sni="localhost", layout=cert_layout)
        assert result.status == 200
    finally:
        await gw.server.stop()


async def test_broken_default_cert_degrades_but_serves_vhosts(cert_layout, backend):
    default = cert_layout.vhost("localhost")
    _corrupt(default.cert_path)
    gw = await start_gateway(
        cert_layout,
        backend.port,
        vhosts=(cert_layout.vhost("api.example.com"),),
        default=default,
    )
    try:
        # gateway is still up and serves the healthy vhost
        result = await https_request(gw.port, sni="api.example.com", layout=cert_layout)
        assert result.status == 200
        bundle = gw.server._registry._store.get("api.example.com")
        assert result.cert_fingerprint == bundle.fingerprint
        assert AuditEventType.CERT_LOAD_FAILED in audit_types(gw.audit)
        degraded = [
            e
            for e in gw.audit.events()
            if e.event_type is AuditEventType.CERT_DEFAULT_USED
            and e.reason == "default certificate missing"
        ]
        assert degraded
    finally:
        await gw.server.stop()


async def test_start_raises_when_nothing_usable(cert_layout, backend):
    from gateway.audit import AuditLogger
    from gateway.config import GatewayConfig
    from gateway.server import build_gateway

    default = cert_layout.vhost("localhost")
    _corrupt(default.cert_path)
    audit = AuditLogger()
    config = GatewayConfig(port=0, backend_port=backend.port, default_vhost=default)
    server = build_gateway(config, audit)  # building must not raise
    with pytest.raises(RuntimeError, match="not .*loaded|no other virtual host"):
        await server.start()
    assert AuditEventType.CERT_LOAD_FAILED in audit_types(audit)
