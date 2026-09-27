"""Session resumption / connection reuse / rotation integration tests."""

from __future__ import annotations

import asyncio
import socket
import ssl

from tls_gateway.config import VHostConfig


async def _ok_handler(reader, writer, vhost):
    body = b"ok"
    writer.write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n"
        + body
    )
    await writer.drain()


def _blocking_tls12(port, ctx, session=None):
    raw = socket.create_connection(("127.0.0.1", port))
    tls = ctx.wrap_socket(raw, server_hostname="a.example", session=session)
    reused, new_session = tls.session_reused, tls.session
    tls.sendall(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
    tls.recv(64)
    tls.close()
    return reused, new_session


async def test_session_resumption_then_rotation_invalidation(build, material):
    gateway, store, sessions, audit, failures, port = await _start(build, material)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    loop = asyncio.get_running_loop()

    first, sess1 = await loop.run_in_executor(None, _blocking_tls12, port, ctx)
    assert first is False
    await asyncio.sleep(0.1)
    assert len(sessions) == 1

    resumed, sess2 = await loop.run_in_executor(
        None, _blocking_tls12, port, ctx, sess1
    )
    assert resumed is True  # connection reuse via resumable session

    # Rotating session keys wipes the bounded cache and rebuilds contexts,
    # deriving fresh ticket/session keys: the old session must not resume.
    epoch = await gateway.rotate_session_keys()
    assert epoch == 1 and len(sessions) == 0
    after, _ = await loop.run_in_executor(
        None, _blocking_tls12, port, ctx, sess2
    )
    assert after is False
    await gateway.shutdown()


async def test_pipelined_requests_on_one_connection(build, material):
    gateway, store, sessions, audit, failures, port = await _start(build, material)
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            port,
            ssl=__import__("tests.conftest", fromlist=["client_context"]).client_context(),
            server_hostname="a.example",
        )
        for _ in range(3):
            writer.write(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        await writer.drain()
        data = b""
        while data.count(b"200 OK") < 3:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=4)
            if not chunk:
                break
            data += chunk
        assert data.count(b"200 OK") == 3
        writer.close()
    finally:
        await gateway.shutdown()


async def _start(build, material):
    from tls_gateway.gateway import TLSTerminationGateway

    config, store, sessions, audit, failures = build(
        [VHostConfig("a.example", material["a_c"], material["a_k"])]
    )
    gateway = TLSTerminationGateway(config, store, sessions, audit, _ok_handler)
    await gateway.start()
    port = gateway._server.sockets[0].getsockname()[1]
    return gateway, store, sessions, audit, failures, port
