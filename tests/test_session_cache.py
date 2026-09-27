"""Bounded session cache semantics, key rotation, connection reuse."""

from __future__ import annotations

import asyncio

import pytest

from conftest import TlsClient, client_ctx, start_gateway
from gateway.audit import AuditEventType
from gateway.session_cache import BoundedSessionCache


# -- unit semantics -------------------------------------------------------

def test_cache_is_bounded_and_evicts_lru():
    cache = BoundedSessionCache(max_size=3, ttl=60)
    for i in range(10_000):  # long-running must not grow without limit
        cache.put(f"sid-{i}".encode(), b"ticket")
    assert len(cache) == 3
    assert cache.get(b"sid-9999") == b"ticket"
    assert cache.get(b"sid-0") is None


def test_cache_entries_expire_with_ttl():
    now = [1000.0]
    cache = BoundedSessionCache(max_size=10, ttl=5.0, time_fn=lambda: now[0])
    cache.put(b"a", b"ticket")
    assert cache.get(b"a") == b"ticket"
    now[0] += 6.0
    assert cache.get(b"a") is None, "expired entries must not be reused"
    assert len(cache) == 0


def test_rotation_invalidates_all_prior_entries():
    cache = BoundedSessionCache(max_size=10, ttl=300)
    cache.put(b"a", b"t1")
    cache.put(b"b", b"t2")
    generation = cache.rotate_keys()
    assert generation == 1 and cache.generation == 1
    assert cache.get(b"a") is None and cache.get(b"b") is None
    assert len(cache) == 0
    # entries stored after rotation are usable
    cache.put(b"c", b"t3")
    assert cache.get(b"c") == b"t3"


def test_invalid_parameters_rejected():
    with pytest.raises(ValueError):
        BoundedSessionCache(max_size=0, ttl=1.0)
    with pytest.raises(ValueError):
        BoundedSessionCache(max_size=1, ttl=0.0)


# -- server integration ---------------------------------------------------


async def test_rotation_task_rotates_and_audits(cert_layout, backend):
    gw = await start_gateway(
        cert_layout, backend.port, session_key_rotation_interval=0.05
    )
    try:
        cache = gw.server._sessions
        cache.put(b"sid", b"ticket")
        assert cache.get(b"sid") == b"ticket"
        for _ in range(100):
            if cache.generation >= 1:
                break
            await asyncio.sleep(0.02)
        assert cache.generation >= 1
        assert cache.get(b"sid") is None, "rotation must invalidate old sessions"
        rotated = [
            e for e in gw.audit.events() if e.event_type is AuditEventType.SESSION_KEYS_ROTATED
        ]
        assert rotated and rotated[0].detail["generation"] >= 1
    finally:
        await gw.server.stop()


async def test_connection_reuse_over_keep_alive(cert_layout, backend):
    """Multiple requests over one TLS connection (HTTP keep-alive)."""
    gw = await start_gateway(cert_layout, backend.port)
    try:
        client = await TlsClient.connect(gw.port, sni="localhost", layout=cert_layout)
        for _ in range(3):
            status, _, body = await client.request("localhost")
            assert status == 200 and b'"backend": true' in body
        assert len(backend.requests) == 3
        await client.close()
    finally:
        await gw.server.stop()


async def test_tls_session_resumption(cert_layout, backend):
    """A client presenting a previously issued session ticket resumes the
    session instead of doing a full handshake."""
    import socket
    import ssl as ssl_mod

    gw = await start_gateway(cert_layout, backend.port)
    try:
        ctx = ssl_mod.create_default_context(cafile=str(cert_layout.ca_cert))
        ctx.check_hostname = False

        def sync_client(session=None):
            sock = socket.create_connection(("127.0.0.1", gw.port), timeout=5)
            tls = ctx.wrap_socket(sock, server_hostname="localhost", session=session)
            tls.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            while tls.read(4096):
                pass
            reused = tls.session_reused
            sess = tls.session
            tls.close()
            return reused, sess

        # full handshake issues a resumable session ticket
        reused, session = await asyncio.to_thread(sync_client)
        assert reused is False
        assert session is not None and session.id

        # presenting the ticket resumes the session
        reused, _ = await asyncio.to_thread(sync_client, session)
        assert reused is True, "expected the second connection to resume the session"
    finally:
        await gw.server.stop()
