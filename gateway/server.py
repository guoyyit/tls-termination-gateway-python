"""Asyncio TLS gateway server.

Responsibilities:
  * terminate TLS using SNI-based per-vhost certificates (via VHostRegistry)
  * enforce the concurrent-connection cap, rejecting excess connections
  * enforce the slow-client timeout on the TLS handshake and on reads
  * enforce per-vhost client-certificate policy before any proxying
  * proxy decrypted traffic to the plain-HTTP backend (keep-alive works
    naturally because bytes are relayed until either side closes)
  * rotate session-cache keys periodically
  * stop gracefully: refuse new connections, drain in-flight ones within
    the grace period, then force-close the rest
"""

from __future__ import annotations

import asyncio
import ssl

from .audit import AuditEvent, AuditEventType, AuditLogger
from .certs import CertStore
from .clientauth import ClientCAStore
from .config import ClientAuthMode, GatewayConfig
from .session_cache import BoundedSessionCache
from .vhosts import VHostRegistry

_CHUNK = 65536


class TLSGatewayServer:
    """Terminates TLS, enforces per-vhost policy, proxies to the backend."""

    def __init__(
        self,
        config: GatewayConfig,
        registry: VHostRegistry,
        session_cache: BoundedSessionCache,
        audit: AuditLogger,
    ) -> None:
        self._config = config
        self._registry = registry
        self._sessions = session_cache
        self._audit = audit
        self._server: asyncio.AbstractServer | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self._active = 0
        self._stopping = False
        self._drained = asyncio.Event()
        self._drained.set()
        self._stopped = asyncio.Event()
        self._rotation_task: asyncio.Task | None = None
        self._client_cas = ClientCAStore()

    # -- lifecycle ------------------------------------------------------

    async def start(self) -> None:
        # build the bootstrap context now so a missing default cert is
        # surfaced (or degraded) before we bind the socket
        self._registry.bootstrap_context()
        self._server = await asyncio.start_server(
            self._on_connection, self._config.host, self._config.port
        )
        self._rotation_task = asyncio.create_task(self._rotate_keys_periodically())

    @property
    def sockets(self):
        return self._server.sockets if self._server is not None else []

    @property
    def active_connections(self) -> int:
        return self._active

    async def serve_forever(self) -> None:
        await self._stopped.wait()

    async def stop(self) -> None:
        """Refuse new connections, drain in-flight ones, then force-close."""
        if self._stopping:
            await self._stopped.wait()
            return
        self._stopping = True
        if self._rotation_task is not None:
            self._rotation_task.cancel()
        if self._server is not None:
            self._server.close()  # stop accepting; new connections are refused
        try:
            await asyncio.wait_for(
                self._drained.wait(), timeout=self._config.shutdown_grace_period
            )
        except asyncio.TimeoutError:
            # grace period expired: force-close whatever is still open
            for writer in list(self._writers):
                writer.transport.abort()
        if self._server is not None:
            # waits for the listening socket *and* the remaining connection
            # handlers (aborted above) to unwind
            await self._server.wait_closed()
        self._stopped.set()

    # -- connection handling ---------------------------------------------

    async def _on_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        if self._stopping or self._active >= self._config.max_connections:
            self._audit.record(
                AuditEvent(
                    AuditEventType.CONNECTION_REJECTED,
                    "connection rejected",
                    reason="server stopping" if self._stopping else "connection limit reached",
                    detail={"peer": str(peer)},
                )
            )
            await self._close(writer)
            return

        self._active += 1
        self._drained.clear()
        self._writers.add(writer)
        try:
            if await self._upgrade_to_tls(writer):
                await self._serve(reader, writer)
        finally:
            self._writers.discard(writer)
            self._active -= 1
            if self._active == 0:
                self._drained.set()
            await self._close(writer)

    async def _upgrade_to_tls(
        self, writer: asyncio.StreamWriter
    ) -> bool:
        """Perform the server-side TLS handshake; False means give up."""
        loop = asyncio.get_running_loop()
        context = self._registry.bootstrap_context()
        try:
            transport = await loop.start_tls(
                writer.transport,
                writer._protocol,  # streams protocol stays; transport is wrapped
                context,
                server_side=True,
                ssl_handshake_timeout=self._config.slow_client_timeout,
            )
        except ssl.SSLCertVerificationError as exc:
            # e.g. a vhost requires a client cert and the client sent a bad one
            self._audit.record(
                AuditEvent(
                    AuditEventType.CLIENT_CERT_INVALID,
                    "client certificate verification failed",
                    reason=exc.verify_message,
                    detail={"verify_code": exc.verify_code},
                )
            )
            return False
        except (asyncio.TimeoutError, TimeoutError):
            self._audit.record(
                AuditEvent(
                    AuditEventType.SLOW_CLIENT_TIMEOUT,
                    "TLS handshake timed out",
                    reason="handshake timeout",
                )
            )
            return False
        except (ssl.SSLError, OSError):
            return False  # not a TLS client, or handshake aborted by peer
        writer._transport = transport
        return True

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        sslobj = writer.get_extra_info("ssl_object")
        hostname = self._registry.selected_hostname(sslobj)
        vhost = self._registry.config_for(hostname)
        peer_der = sslobj.getpeercert(binary_form=True) if sslobj is not None else None

        if vhost.client_auth is not ClientAuthMode.NONE:
            if peer_der is None:
                if vhost.client_auth is ClientAuthMode.REQUIRED:
                    self._audit.record(
                        AuditEvent(
                            AuditEventType.CLIENT_CERT_MISSING,
                            "client certificate required but not provided",
                            hostname=hostname,
                            reason="client certificate required",
                        )
                    )
                    await self._write_http_error(
                        writer,
                        403,
                        "client certificate required",
                        "missing_client_certificate",
                    )
                    return
            else:
                reason = None
                if vhost.client_ca_path is not None:
                    reason = self._client_cas.verify(peer_der, vhost.client_ca_path)
                if reason is not None:
                    self._audit.record(
                        AuditEvent(
                            AuditEventType.CLIENT_CERT_INVALID,
                            "client certificate rejected by virtual host policy",
                            hostname=hostname,
                            reason=reason,
                        )
                    )
                    await self._write_http_error(
                        writer,
                        403,
                        "client certificate not trusted",
                        "untrusted_client_certificate",
                    )
                    return
                self._audit.record(
                    AuditEvent(
                        AuditEventType.CLIENT_CERT_OK,
                        "client certificate accepted",
                        hostname=hostname,
                        detail={"subject": (writer.get_extra_info("peercert") or {}).get("subject", ())},
                    )
                )

        try:
            backend_reader, backend_writer = await asyncio.open_connection(
                self._config.backend_host, self._config.backend_port
            )
        except OSError:
            await self._write_http_error(writer, 502, "bad gateway", "backend_unavailable")
            return
        try:
            await self._proxy(reader, writer, backend_reader, backend_writer, hostname)
        finally:
            await self._close(backend_writer)

    async def _proxy(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        backend_reader: asyncio.StreamReader,
        backend_writer: asyncio.StreamWriter,
        hostname: str | None,
    ) -> None:
        async def client_to_backend() -> None:
            while True:
                try:
                    data = await asyncio.wait_for(
                        client_reader.read(_CHUNK), self._config.slow_client_timeout
                    )
                except (asyncio.TimeoutError, TimeoutError):
                    self._audit.record(
                        AuditEvent(
                            AuditEventType.SLOW_CLIENT_TIMEOUT,
                            "client read timed out",
                            hostname=hostname,
                            reason="slow client timeout",
                        )
                    )
                    return
                if not data:
                    return
                backend_writer.write(data)
                await backend_writer.drain()

        async def backend_to_client() -> None:
            while True:
                data = await backend_reader.read(_CHUNK)
                if not data:
                    return
                client_writer.write(data)
                await client_writer.drain()

        tasks = [
            asyncio.create_task(client_to_backend()),
            asyncio.create_task(backend_to_client()),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:  # surface unexpected errors as connection close
            if not task.cancelled() and task.exception() is not None:
                raise task.exception()

    # -- helpers ----------------------------------------------------------

    async def _write_http_error(
        self, writer: asyncio.StreamWriter, status: int, message: str, reason: str
    ) -> None:
        body = f'{{"error": "{message}", "reason": "{reason}"}}'.encode()
        head = (
            f"HTTP/1.1 {status} {message}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"X-Gateway-Error: {reason}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        try:
            writer.write(head + body)
            await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass

    async def _close(self, writer: asyncio.StreamWriter) -> None:
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError, RuntimeError):
            pass

    async def _rotate_keys_periodically(self) -> None:
        interval = self._config.session_key_rotation_interval
        try:
            while True:
                await asyncio.sleep(interval)
                generation = self._sessions.rotate_keys()
                self._audit.record(
                    AuditEvent(
                        AuditEventType.SESSION_KEYS_ROTATED,
                        "session keys rotated; cached sessions invalidated",
                        detail={"generation": generation},
                    )
                )
        except asyncio.CancelledError:
            return


def build_gateway(config: GatewayConfig, audit: AuditLogger) -> TLSGatewayServer:
    """Load certificates from disk and assemble the gateway.

    Every vhost load result is audited; broken vhosts are skipped so the
    gateway keeps serving the hostnames whose certificates are usable.
    """
    store = CertStore()
    all_configs = list(config.vhosts)
    if config.default_vhost is not None and all(
        c.hostname != config.default_vhost.hostname for c in all_configs
    ):
        all_configs.append(config.default_vhost)
    errors = store.load_initial(all_configs)
    for cfg in all_configs:
        err = errors.get(cfg.hostname)
        bundle = store.get(cfg.hostname)
        if err is None and bundle is not None:
            audit.record(
                AuditEvent(
                    AuditEventType.CERT_LOADED,
                    "certificate loaded",
                    hostname=cfg.hostname,
                    detail={
                        "fingerprint": bundle.fingerprint,
                        "not_after": bundle.not_after,
                    },
                )
            )
        else:
            audit.record(
                AuditEvent(
                    AuditEventType.CERT_LOAD_FAILED,
                    "certificate failed to load; virtual host disabled",
                    hostname=cfg.hostname,
                    reason=str(err),
                )
            )
    if config.default_vhost is None:
        raise ValueError("gateway config requires a default_vhost")
    registry = VHostRegistry(
        store,
        default_hostname=config.default_vhost.hostname,
        default_config=config.default_vhost,
        vhost_configs={c.hostname: c for c in all_configs},
        audit=audit,
    )
    cache = BoundedSessionCache(config.session_cache_size, config.session_ttl)
    return TLSGatewayServer(config, registry, cache, audit)
