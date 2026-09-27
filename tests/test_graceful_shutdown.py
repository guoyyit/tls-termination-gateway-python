"""Graceful shutdown, connection limits, slow-client timeouts."""

from __future__ import annotations

import asyncio
import ssl
import time

import pytest

from conftest import Backend, TlsClient, audit_types, client_ctx, start_gateway
from gateway.audit import AuditEventType


async def test_inflight_request_drains_within_grace_period(cert_layout):
    backend = await Backend(delay=0.3).start()
    gw = await start_gateway(cert_layout, backend.port, shutdown_grace_period=5.0)
    try:
        client = await TlsClient.connect(gw.port, sni="localhost", layout=cert_layout)
        client.writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        await client.writer.drain()
        await asyncio.sleep(0.05)  # request is now in flight at the backend

        stop_task = asyncio.create_task(gw.server.stop())
        # the in-flight request must still complete normally
        head = await asyncio.wait_for(client.reader.readuntil(b"\r\n\r\n"), timeout=5)
        assert b"200 OK" in head
        await asyncio.wait_for(stop_task, timeout=5)
        assert gw.server.active_connections == 0
    finally:
        await backend.stop()


async def test_new_connections_refused_once_stopping(cert_layout, backend):
    gw = await start_gateway(cert_layout, backend.port)
    await gw.server.stop()
    ctx = client_ctx(cert_layout)
    with pytest.raises((ConnectionRefusedError, OSError)):
        await asyncio.open_connection("127.0.0.1", gw.port, ssl=ctx,
                                      server_hostname="localhost")


async def test_force_close_after_grace_period_expires(cert_layout):
    backend = await Backend(delay=30.0).start()  # never answers in time
    gw = await start_gateway(cert_layout, backend.port, shutdown_grace_period=0.2)
    try:
        client = await TlsClient.connect(gw.port, sni="localhost", layout=cert_layout)
        client.writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        await client.writer.drain()
        await asyncio.sleep(0.05)

        started = time.monotonic()
        await asyncio.wait_for(gw.server.stop(), timeout=10)
        elapsed = time.monotonic() - started
        assert elapsed < 5, f"stop took too long: {elapsed:.1f}s"

        # the unfinished connection was force-closed
        with pytest.raises((ConnectionError, asyncio.IncompleteReadError, ssl.SSLError)):
            await asyncio.wait_for(client.reader.readuntil(b"\r\n\r\n"), timeout=2)
    finally:
        await backend.stop()


async def test_connection_limit_rejects_excess_connections(cert_layout, backend):
    gw = await start_gateway(cert_layout, backend.port, max_connections=1)
    try:
        first = await TlsClient.connect(gw.port, sni="localhost", layout=cert_layout)
        await asyncio.sleep(0.05)  # let the server register the connection
        assert gw.server.active_connections == 1

        # second connection is rejected before any TLS work
        ctx = client_ctx(cert_layout)
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            await asyncio.open_connection(
                "127.0.0.1", gw.port, ssl=ctx, server_hostname="localhost"
            )
        rejected = [
            e for e in gw.audit.events()
            if e.event_type is AuditEventType.CONNECTION_REJECTED
        ]
        assert rejected and rejected[-1].reason == "connection limit reached"

        # after freeing a slot, new connections work again
        await first.close()
        for _ in range(50):
            if gw.server.active_connections == 0:
                break
            await asyncio.sleep(0.02)
        second = await TlsClient.connect(gw.port, sni="localhost", layout=cert_layout)
        status, _, _ = await second.request("localhost")
        assert status == 200
        await second.close()
    finally:
        await gw.server.stop()


async def test_slow_client_is_disconnected_and_audited(cert_layout, backend):
    gw = await start_gateway(cert_layout, backend.port, slow_client_timeout=0.3)
    try:
        client = await TlsClient.connect(gw.port, sni="localhost", layout=cert_layout)
        # send nothing; the server must give up after slow_client_timeout
        data = await asyncio.wait_for(client.reader.read(-1), timeout=5)
        assert data == b""
        slow = [
            e for e in gw.audit.events()
            if e.event_type is AuditEventType.SLOW_CLIENT_TIMEOUT
        ]
        assert slow
        await client.close()
    finally:
        await gw.server.stop()
