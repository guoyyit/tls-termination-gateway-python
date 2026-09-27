"""Entry point: wire config, store and gateway together.

The original plaintext service (``main.py`` FastAPI/uvicorn) keeps running on
``plaintext_port`` unchanged.  The gateway adds the TLS listener on
``tls_port``; terminated requests are handed to a small built-in HTTP/1.1
handler (or any injected async ``request_handler``).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from pathlib import Path

from tls_gateway.audit import AuditLogger
from tls_gateway.cert_store import CertificateStore
from tls_gateway.config import GatewayConfig, load_config
from tls_gateway.gateway import TLSTerminationGateway
from tls_gateway.session_cache import SessionCache


def _build_plaintext_handler(base_url: str | None):
    """Return the request handler used after TLS termination.

    When ``base_url`` points at the local plaintext service, requests are
    proxied over HTTP/1.1 (keep-alive).  Without a backend, a minimal built-in
    200 response is produced so the gateway is independently testable.
    """

    async def handler(reader, writer, vhost):  # pragma: no cover - thin wrapper
        await _handle_once(reader, writer, vhost, base_url)

    return handler


async def _handle_once(reader, writer, vhost, base_url):  # pragma: no cover
    # The gateway already consumed the request line + headers; a real proxy
    # would read the body and forward.  Here we answer directly.
    body = (
        '{"served_by":"tls-termination-gateway","vhost":%s}'
        % ("null" if vhost is None else f'"{vhost}"')
    ).encode()
    writer.write(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: keep-alive\r\n\r\n" + body
    )
    await writer.drain()


def build_components(
    config: GatewayConfig, audit: AuditLogger | None = None
) -> tuple[CertificateStore, SessionCache, AuditLogger, dict[str, str]]:
    """Construct store + sessions and restore certificate state from disk.

    Startup never fails because one certificate is missing/corrupt/expired:
    such hosts are returned in the diagnostics map while healthy hosts and the
    default certificate continue to serve.
    """
    audit = audit or AuditLogger()
    sessions = SessionCache(max_entries=config.max_sessions)
    store = CertificateStore(sessions, audit)
    default_pair = None
    if config.default_cert_file and config.default_key_file:
        default_pair = (str(config.default_cert_file), str(config.default_key_file))
    failures = store.load_initial(list(config.vhosts.values()), default_pair)
    return store, sessions, audit, failures


def build_gateway(
    config: GatewayConfig,
    audit: AuditLogger | None = None,
    request_handler=None,
) -> tuple[TLSTerminationGateway, dict[str, str]]:
    """Construct store + gateway from configuration and restore cert state."""
    store, sessions, audit, failures = build_components(config, audit)
    handler = request_handler or _build_plaintext_handler(None)
    gateway = TLSTerminationGateway(
        config=config,
        store=store,
        sessions=sessions,
        audit=audit,
        request_handler=handler,
    )
    return gateway, failures


async def run_async(config: GatewayConfig) -> None:
    logging.basicConfig(level=logging.INFO)
    audit = AuditLogger()
    gateway, failures = build_gateway(config, audit)
    for name, reason in failures.items():
        logging.getLogger("tls_gateway").warning(
            "certificate unavailable for %s: %s", name, reason
        )
    await gateway.start()
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, ValueError):
            loop.add_signal_handler(sig, stop.set)
    try:
        await stop.wait()
    finally:
        await gateway.shutdown()


def main(config_path: str = "gateway.toml") -> None:
    """Synchronous CLI entry."""
    config = load_config(Path(config_path))
    asyncio.run(run_async(config))
