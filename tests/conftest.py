"""Shared pytest fixtures for the TLS termination gateway."""

from __future__ import annotations

import datetime as dt
import io
import logging
import ssl
from pathlib import Path

import pytest

from tests import certs
from tls_gateway.audit import AuditLogger
from tls_gateway.cert_store import CertificateStore
from tls_gateway.config import GatewayConfig, VHostConfig
from tls_gateway.session_cache import SessionCache


@pytest.fixture
def cert_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def material(cert_dir: Path) -> dict[str, Path]:
    default_c, default_k = certs.self_signed(cert_dir, "default", "default.example")
    a_c, a_k = certs.self_signed(cert_dir, "a", "a.example")
    b_c, b_k = certs.self_signed(cert_dir, "b", "b.example")
    ca_c, ca_k = certs.self_signed(cert_dir, "ca", "client-ca", is_ca=True)
    other_ca_c, other_ca_k = certs.self_signed(
        cert_dir, "other-ca", "other-ca", is_ca=True
    )
    good_c, good_k = certs.client_cert(cert_dir, "good", ca_c, ca_k)
    bad_c, bad_k = certs.client_cert(cert_dir, "bad", other_ca_c, other_ca_k)
    expired_c, expired_k = certs.self_signed(
        cert_dir,
        "expired",
        "expired.example",
        not_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2020, 2, 1, tzinfo=dt.timezone.utc),
    )
    return {
        "default_c": default_c, "default_k": default_k,
        "a_c": a_c, "a_k": a_k, "b_c": b_c, "b_k": b_k,
        "ca_c": ca_c, "ca_k": ca_k,
        "good_c": good_c, "good_k": good_k,
        "bad_c": bad_c, "bad_k": bad_k,
        "expired_c": expired_c, "expired_k": expired_k,
    }


@pytest.fixture
def audit_buffer() -> tuple[AuditLogger, io.StringIO]:
    buf = io.StringIO()
    logger = logging.getLogger("tls_gateway.audit.test")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(buf)
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False
    return AuditLogger(logger), buf


def client_context(cert: Path | None = None, key: Path | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if cert is not None:
        ctx.load_cert_chain(cert, key)
    return ctx


@pytest.fixture
def build(material, audit_buffer):
    audit, _buf = audit_buffer

    def _build(
        vhosts: list[VHostConfig],
        *,
        with_default: bool = True,
        max_connections: int = 64,
        max_sessions: int = 256,
        handshake_timeout: float = 5.0,
        read_timeout: float = 5.0,
        shutdown_timeout: float = 3.0,
    ):
        sessions = SessionCache(max_entries=max_sessions)
        store = CertificateStore(sessions, audit)
        default_pair = (
            (str(material["default_c"]), str(material["default_k"]))
            if with_default
            else None
        )
        failures = store.load_initial(vhosts, default_pair)
        config = GatewayConfig(
            vhosts={c.name: c for c in vhosts},
            default_cert_file=material["default_c"] if with_default else None,
            default_key_file=material["default_k"] if with_default else None,
            tls_host="127.0.0.1",
            tls_port=0,
            handshake_timeout=handshake_timeout,
            read_timeout=read_timeout,
            shutdown_timeout=shutdown_timeout,
            max_connections=max_connections,
            max_sessions=max_sessions,
        )
        return config, store, sessions, audit, failures

    return _build
