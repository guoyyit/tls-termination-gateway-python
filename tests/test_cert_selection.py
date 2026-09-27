"""Certificate selection: known vhost, unknown hostname, missing SNI."""

from __future__ import annotations

import pytest

from conftest import audit_types, https_request, start_gateway
from gateway.audit import AuditEventType


async def test_known_vhost_gets_its_own_certificate(cert_layout, backend):
    gw = await start_gateway(
        cert_layout, backend.port, vhosts=(cert_layout.vhost("www.example.com"),)
    )
    try:
        result = await https_request(gw.port, sni="www.example.com", layout=cert_layout)
        assert result.status == 200
        assert result.cert_fingerprint is not None
        bundle = gw.server._registry._store.get("www.example.com")
        assert result.cert_fingerprint == bundle.fingerprint
        assert b'"host": "www.example.com"' in result.body
        assert AuditEventType.CERT_SELECTED in audit_types(gw.audit)
    finally:
        await gw.server.stop()


async def test_unknown_hostname_falls_back_to_default(cert_layout, backend):
    gw = await start_gateway(
        cert_layout, backend.port, vhosts=(cert_layout.vhost("www.example.com"),)
    )
    try:
        result = await https_request(gw.port, sni="unknown.example.org", layout=cert_layout)
        assert result.status == 200
        default = gw.server._registry._store.get("localhost")
        assert result.cert_fingerprint == default.fingerprint
        defaults = [
            e
            for e in gw.audit.events()
            if e.event_type is AuditEventType.CERT_DEFAULT_USED
        ]
        assert defaults and defaults[-1].reason == "unknown hostname"
        assert defaults[-1].hostname == "unknown.example.org"
    finally:
        await gw.server.stop()


async def test_missing_sni_uses_default_certificate(cert_layout, backend):
    gw = await start_gateway(cert_layout, backend.port)
    try:
        result = await https_request(gw.port, sni=None, layout=cert_layout)
        assert result.status == 200
        default = gw.server._registry._store.get("localhost")
        assert result.cert_fingerprint == default.fingerprint
        defaults = [
            e
            for e in gw.audit.events()
            if e.event_type is AuditEventType.CERT_DEFAULT_USED
        ]
        assert defaults and defaults[-1].reason == "no SNI provided"
    finally:
        await gw.server.stop()


async def test_hostname_matching_is_case_and_dot_insensitive(cert_layout, backend):
    gw = await start_gateway(
        cert_layout, backend.port, vhosts=(cert_layout.vhost("www.example.com"),)
    )
    try:
        result = await https_request(gw.port, sni="WWW.Example.COM.", layout=cert_layout)
        bundle = gw.server._registry._store.get("www.example.com")
        assert result.cert_fingerprint == bundle.fingerprint
    finally:
        await gw.server.stop()
