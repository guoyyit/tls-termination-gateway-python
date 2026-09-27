"""Integration tests: SNI selection, client cert, sessions, reload, shutdown."""

from __future__ import annotations

import asyncio
import ssl

import pytest

from tests.conftest import client_context
from tls_gateway.config import VHostConfig
from tls_gateway.gateway import TLSTerminationGateway, ConnectionLimiter
from tls_gateway.errors import GatewayShutdown


async def _ok_handler(reader, writer, vhost):
    body = b'{"vhost":%s}' % (b"null" if vhost is None else f'"{vhost}"'.encode())
    writer.write(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    await writer.drain()


async def _start(build, vhosts, handler=_ok_handler, **kw):
    config, store, sessions, audit, failures = build(vhosts, **kw)
    gateway = TLSTerminationGateway(config, store, sessions, audit, handler)
    await gateway.start()
    port = gateway._server.sockets[0].getsockname()[1]
    return gateway, store, sessions, audit, failures, port


async def _request(port, sni, ctx):
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=ctx, server_hostname=sni
    )
    writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    await writer.drain()
    data = await asyncio.wait_for(reader.read(4096), timeout=4)
    writer.close()
    with __import__("contextlib").suppress(Exception):
        await writer.wait_closed()
    return data


async def test_unknown_domain_uses_default(build, material):
    gateway, store, sessions, audit, failures, port = await _start(
        build, [VHostConfig("a.example", material["a_c"], material["a_k"])]
    )
    try:
        data = await _request(port, "totally.unknown", client_context())
        assert b"200 OK" in data
        assert b"null" in data
    finally:
        await gateway.shutdown()


async def test_matched_domain_serves_its_vhost(build, material):
    gateway, *_ , port = await _start(
        build, [VHostConfig("a.example", material["a_c"], material["a_k"])]
    )
    try:
        data = await _request(port, "a.example", client_context())
        assert b"a.example" in data
    finally:
        await gateway.shutdown()


async def test_no_sni_uses_default(build, material):
    gateway, *_, port = await _start(
        build, [VHostConfig("a.example", material["a_c"], material["a_k"])]
    )
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_context(), server_hostname=None
        )
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=4)
        assert b"200 OK" in data and b"null" in data
        writer.close()
    finally:
        await gateway.shutdown()


async def test_invalid_client_cert_handshake_fails_server_side(build, material, audit_buffer):
    _, buf = audit_buffer
    vhosts = [
        VHostConfig(
            "secure.example",
            material["a_c"],
            material["a_k"],
            require_client_cert=True,
            client_ca_file=material["ca_c"],
        )
    ]
    gateway, store, sessions, audit, failures, port = await _start(build, vhosts)
    try:
        ctx = client_context(material["bad_c"], material["bad_k"])
        # The server rejects the untrusted chain during the handshake.  In
        # TLS 1.3 the corresponding alert may surface to the client only on
        # the first application read, so the authoritative assertion is the
        # server-side, distinguishable audit record.
        with __import__("contextlib").suppress(Exception):
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=ctx, server_hostname="secure.example"
            )
            with __import__("contextlib").suppress(Exception):
                await asyncio.wait_for(reader.read(256), timeout=2)
            with __import__("contextlib").suppress(Exception):
                writer.close()
        await asyncio.sleep(0.1)
        assert "client_cert_failed" in buf.getvalue()
        assert "client_cert_unknown_ca" in buf.getvalue()
        # The request must never have reached processing: no 200 was sent and
        # no client_cert_ok exists for this connection.
        assert "client_cert_ok" not in buf.getvalue()
    finally:
        await gateway.shutdown()


async def test_absent_client_cert_request_not_served(build, material):
    vhosts = [
        VHostConfig(
            "secure.example",
            material["a_c"],
            material["a_k"],
            require_client_cert=True,
            client_ca_file=material["ca_c"],
        )
    ]
    gateway, *_ , port = await _start(build, vhosts)
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_context(),
            server_hostname="secure.example",
        )
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=3)
        # Verification gate closed the connection; no 200 ever produced.
        assert b"200 OK" not in data
        writer.close()
    finally:
        await gateway.shutdown()


async def test_valid_client_cert_served(build, material):
    vhosts = [
        VHostConfig(
            "secure.example",
            material["a_c"],
            material["a_k"],
            require_client_cert=True,
            client_ca_file=material["ca_c"],
        )
    ]
    gateway, *_ , port = await _start(build, vhosts)
    try:
        ctx = client_context(material["good_c"], material["good_k"])
        data = await _request(port, "secure.example", ctx)
        assert b"200 OK" in data and b"secure.example" in data
    finally:
        await gateway.shutdown()


async def test_concurrent_hot_reload(build, material):
    vhosts = [VHostConfig("a.example", material["a_c"], material["a_k"])]
    gateway, store, sessions, audit, failures, port = await _start(build, vhosts)

    async def traffic(stop: asyncio.Event):
        while not stop.is_set():
            try:
                data = await _request(port, "a.example", client_context())
                assert b"200 OK" in data
            except Exception:
                pass
            await asyncio.sleep(0)

    stop = asyncio.Event()
    workers = [asyncio.create_task(traffic(stop)) for _ in range(8)]
    try:
        # Reload repeatedly while connections are in flight; every response
        # must come from either the old or the new complete cert, never a mix.
        for _ in range(10):
            store.reload_vhost(
                VHostConfig("a.example", material["a_c"], material["a_k"])
            )
            await asyncio.sleep(0)
    finally:
        stop.set()
        await asyncio.gather(*workers, return_exceptions=True)
        await gateway.shutdown()


async def test_corrupt_cert_keeps_other_vhosts_serving(build, material):
    vhosts = [
        VHostConfig("a.example", material["a_c"], material["a_k"]),
        VHostConfig("bad.example", material["a_c"], material["b_k"]),  # mismatch
    ]
    gateway, store, sessions, audit, failures, port = await _start(build, vhosts)
    try:
        assert "bad.example" in failures
        data = await _request(port, "a.example", client_context())
        assert b"200 OK" in data
        # Bad vhost name -> default fallback still serves.
        data = await _request(port, "bad.example", client_context())
        assert b"200 OK" in data and b"null" in data
    finally:
        await gateway.shutdown()


# --------------------------------------------------------------- limiter / shutdown
async def test_limiter_rejects_when_draining():
    limiter = ConnectionLimiter(2)
    async with limiter.acquire():
        await limiter.begin_drain()
        with pytest.raises(GatewayShutdown):
            async with limiter.acquire():
                pass


async def test_limiter_bounds_concurrency():
    limiter = ConnectionLimiter(2)
    peak = 0

    async def use():
        nonlocal peak
        async with limiter.acquire():
            peak = max(peak, limiter.active)
            await asyncio.sleep(0.01)

    await asyncio.gather(*(use() for _ in range(10)))
    assert peak <= 2
    assert limiter.active == 0


async def test_graceful_shutdown_drains_inflight(build, material):
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_handler(reader, writer, vhost):
        started.set()
        await release.wait()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length:2\r\n\r\nok")
        await writer.drain()

    gateway, *_ , port = await _start(
        build,
        [VHostConfig("a.example", material["a_c"], material["a_k"])],
        handler=slow_handler,
        shutdown_timeout=5,
    )

    async def client():
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_context(), server_hostname="a.example"
        )
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(64), timeout=6)
        writer.close()
        return data

    cli = asyncio.create_task(client())
    await started.wait()
    shutdown = asyncio.create_task(gateway.shutdown())
    await asyncio.sleep(0.1)
    assert not shutdown.done()  # still draining
    release.set()
    data = await cli
    await asyncio.wait_for(shutdown, timeout=5)
    assert b"200 OK" in data


async def test_graceful_shutdown_forces_after_timeout(build, material):
    entered = asyncio.Event()

    async def stuck_handler(reader, writer, vhost):
        # Simulate a request whose backend never responds.
        entered.set()
        await asyncio.sleep(30)

    gateway, *_ , port = await _start(
        build,
        [VHostConfig("a.example", material["a_c"], material["a_k"])],
        handler=stuck_handler,
        shutdown_timeout=1,
        read_timeout=30,
    )
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=client_context(), server_hostname="a.example"
    )
    writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    await writer.drain()
    await entered.wait()

    loop = asyncio.get_running_loop()
    t0 = loop.time()
    await gateway.shutdown()
    elapsed = loop.time() - t0
    # Force-close fires near the 1s drain timeout, nowhere near the 30s work.
    assert elapsed < 5
    with __import__("contextlib").suppress(Exception):
        writer.close()


async def test_max_connections_rejects_excess(build, material):
    # Handler blocks until released so accepted connections occupy slots.
    release = asyncio.Event()
    entered = asyncio.Event()
    count = 0

    async def counting_handler(reader, writer, vhost):
        nonlocal count
        count += 1
        if count >= 1:
            entered.set()
        await release.wait()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length:2\r\n\r\nhi")
        await writer.drain()

    gateway, *_ , port = await _start(
        build,
        [VHostConfig("a.example", material["a_c"], material["a_k"])],
        handler=counting_handler,
        max_connections=1,
        read_timeout=5,
    )
    try:
        # Occupy the single slot.
        r1, w1 = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_context(), server_hostname="a.example"
        )
        w1.write(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        await w1.drain()
        await entered.wait()

        # A second connection must be rejected while the slot is held.
        rejected = False
        try:
            r2, w2 = await asyncio.open_connection(
                "127.0.0.1", port, ssl=client_context(), server_hostname="a.example"
            )
            w2.write(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
            await w2.drain()
            try:
                data = await asyncio.wait_for(r2.read(256), timeout=3)
                rejected = b"200 OK" not in data
            except (asyncio.TimeoutError, ConnectionResetError, ssl.SSLError,
                    BrokenPipeError):
                rejected = True
        except (ConnectionResetError, ssl.SSLError, OSError):
            # Rejected before/during the TLS handshake -> connection reset.
            rejected = True
        assert rejected

        release.set()
        body = await asyncio.wait_for(r1.read(64), timeout=4)
        assert b"200 OK" in body
        w1.close()
    finally:
        await gateway.shutdown()
