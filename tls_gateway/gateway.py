"""TLS termination gateway: SNI dispatch, limits, timeouts, graceful stop.

Two access paths coexist:

* the **plaintext** listener preserves the original, unencrypted serving path
  (the existing ASGI / uvicorn listener is untouched);
* the **TLS** listener performs local termination.  It accepts *raw* TCP and
  drives the TLS handshake with ``loop.start_tls`` itself, so handshake
  failures (including client-certificate verification failures) are observed
  server-side, classified into a stable reason and audited.

Lifecycle guarantees
--------------------
* ``max_connections`` bounds concurrent accepted connections; once the limit
  is reached late connections are closed immediately (audited).
* ``handshake_timeout`` bounds the TLS handshake; ``read_timeout`` bounds each
  read on an accepted connection (slow-client protection).
* ``shutdown()`` stops accepting, rejects late new connections, drains
  in-flight requests up to ``shutdown_timeout`` and then force-closes the
  remainder.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import Awaitable, Callable

from tls_gateway.audit import AuditEvent, AuditLogger, new_correlation_id
from tls_gateway.cert_store import (
    CertificateStore,
    _HANDSHAKE_KEY,
    classify_client_cert_error,
    save_handshake_state,
    take_handshake_state_by_key,
)
from tls_gateway.config import GatewayConfig
from tls_gateway.errors import GatewayShutdown
from tls_gateway.session_cache import SessionCache, SessionInfo

RequestHandler = Callable[
    [asyncio.StreamReader, asyncio.StreamWriter, str | None], Awaitable[None]
]


class ConnectionLimiter:
    """Bounded async slot limiter with explicit draining state."""

    def __init__(self, max_connections: int) -> None:
        if max_connections <= 0:
            raise ValueError("max_connections must be positive")
        self._max = max_connections
        self._sem = asyncio.Semaphore(max_connections)
        self._active = 0
        self._draining = False
        self._cond = asyncio.Condition()

    @property
    def draining(self) -> bool:
        return self._draining

    @property
    def active(self) -> int:
        return self._active

    @property
    def capacity(self) -> int:
        return self._max

    async def begin_drain(self) -> None:
        """Reject all future :meth:`acquire` calls immediately."""
        async with self._cond:
            self._draining = True
            self._cond.notify_all()

    @contextlib.asynccontextmanager
    async def acquire(self):
        """Acquire one connection slot; raises ``GatewayShutdown`` if draining."""
        async with self._cond:
            if self._draining:
                raise GatewayShutdown("gateway is draining")
        await self._sem.acquire()
        try:
            async with self._cond:
                if self._draining:
                    raise GatewayShutdown("gateway is draining")
                self._active += 1
            try:
                yield
            finally:
                async with self._cond:
                    self._active -= 1
                    self._cond.notify_all()
        finally:
            self._sem.release()

    def try_acquire(self) -> bool:
        """Immediately take a slot without yielding to the event loop.

        Returns ``False`` when draining or at capacity, so the caller can
        reject a new connection at once instead of queueing it.  Safe because
        the asyncio event loop is single-threaded and this does not await.
        """
        if self._draining or self._sem._value <= 0:  # type: ignore[attr-defined]
            return False
        self._sem._value -= 1  # type: ignore[attr-defined]
        self._active += 1
        return True

    def release_slot(self) -> None:
        self._active -= 1
        self._sem.release()

    async def wait_idle(self) -> None:
        async with self._cond:
            await self._cond.wait_for(lambda: self._active == 0)

    async def wait_drained(self, timeout: float) -> bool:
        """Wait until no connections remain. Returns ``False`` on timeout."""
        try:
            await asyncio.wait_for(self.wait_idle(), timeout=timeout)
            return True
        except (TimeoutError, asyncio.TimeoutError):
            return False


class TLSTerminationGateway:
    """Owns the TLS listener, certificate store and connection lifecycle."""

    def __init__(
        self,
        config: GatewayConfig,
        store: CertificateStore,
        sessions: SessionCache,
        audit: AuditLogger,
        request_handler: RequestHandler | None = None,
    ) -> None:
        self._config = config
        self._store = store
        self._sessions = sessions
        self._audit = audit
        self._request_handler = request_handler
        self._limiter = ConnectionLimiter(config.max_connections)
        self._server: asyncio.AbstractServer | None = None
        self._conns: dict[asyncio.StreamWriter, dict] = {}
        self._tasks: set[asyncio.Task] = set()
        self._conns_lock = asyncio.Lock()

    # ------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        """Open the raw TCP listener that drives TLS itself."""
        if self._store.front_context is None:
            raise RuntimeError(
                "no default certificate available; TLS listener cannot start"
            )
        self._server = await asyncio.start_server(
            self._accept,
            host=self._config.tls_host,
            port=self._config.tls_port,
        )

    async def __aenter__(self) -> "TLSTerminationGateway":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.shutdown()

    async def shutdown(self) -> None:
        """Stop accepting, drain in-flight work, force-close after timeout."""
        if self._server is not None:
            self._server.close()
        await self._limiter.begin_drain()
        # Note: Server.wait_closed() is intentionally not awaited here: on
        # modern asyncio it blocks until *all* client sockets close, which is
        # exactly the drain/force decision we drive ourselves below.
        drained = await self._limiter.wait_drained(self._config.shutdown_timeout)
        if not drained:
            await self._force_close_all()
        self._audit.emit(
            AuditEvent.GATEWAY_STOPPED,
            vhost=None,
            correlation_id=new_correlation_id(),
            reason="drained" if drained else "forced",
            active_connections=self._limiter.active,
        )

    async def _force_close_all(self) -> None:
        async with self._conns_lock:
            writers = list(self._conns)
            tasks = list(self._tasks)
        # Cancel in-flight request handling so blocked backends/reads release
        # promptly, then drop the transports.
        for task in tasks:
            task.cancel()
        for writer in writers:
            with contextlib.suppress(Exception):
                writer.close()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ------------------------------------------------------------ accept loop
    async def _accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        cid = new_correlation_id()
        # Bound concurrency immediately: if at capacity or draining, do not
        # even drive a TLS handshake; reject/close at once (audited).
        if not self._limiter.try_acquire():
            reason = "draining" if self._limiter.draining else "max_connections"
            self._audit.emit(
                AuditEvent.CONNECTION_REJECTED,
                vhost=None,
                correlation_id=cid,
                reason=reason,
            )
            self._safe_close(writer)
            return

        # Placeholder state; rebound to the inner SSL object by the SNI cb.
        state: dict[str, str | None] = {
            "correlation_id": cid,
            "vhost": None,
            "sni": None,
        }
        key = id(state)
        save_handshake_state(key, state)
        token = _HANDSHAKE_KEY.set(key)
        try:
            await self._handle(reader, writer, state, key)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one bad connection must not kill loop
            self._safe_close(writer)
        finally:
            _HANDSHAKE_KEY.reset(token)
            take_handshake_state_by_key(key)
            self._limiter.release_slot()

    # ------------------------------------------------------- per-connection
    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        state: dict[str, str | None],
        key: int,
    ) -> None:
        front = self._store.front_context
        assert front is not None
        transport = writer.transport
        protocol = transport.get_protocol()
        loop = asyncio.get_running_loop()

        try:
            tls_transport = await asyncio.wait_for(
                loop.start_tls(transport, protocol, front, server_side=True),
                timeout=self._config.handshake_timeout,
            )
        except (TimeoutError, asyncio.TimeoutError):
            self._audit_handshake_failure(state, key, writer, "handshake_timeout")
            self._safe_close(writer)
            return
        except ssl.SSLError as exc:
            reason = classify_client_cert_error(exc)
            self._audit_handshake_failure(state, key, writer, reason)
            self._safe_close(writer)
            return
        except OSError:
            self._safe_close(writer)
            return

        sslobj = tls_transport.get_extra_info("ssl_object")
        # The SNI callback rebound state to the inner SSL object; resolve it.
        final_state = self._resolve_state(sslobj, key)
        vhost = final_state.get("vhost")
        cid = final_state["correlation_id"]

        # start_tls swaps the protocol's transport to the TLS layer.  The
        # original reader already receives decrypted app data; rebuild the
        # writer on the TLS transport so responses are encrypted.
        tls_writer = asyncio.StreamWriter(
            tls_transport, protocol, reader, asyncio.get_running_loop()
        )

        info = {"vhost": vhost, "correlation_id": cid}
        async with self._conns_lock:
            self._conns[tls_writer] = info
            self._tasks.add(asyncio.current_task())
        try:
            await self._serve(reader, tls_writer, cid, vhost, sslobj)
        finally:
            async with self._conns_lock:
                self._conns.pop(tls_writer, None)
                self._tasks.discard(asyncio.current_task())
            self._safe_close(tls_writer)

    @staticmethod
    def _resolve_state(sslobj, placeholder_key: int) -> dict[str, str | None]:
        if sslobj is not None:
            rebound = take_handshake_state_by_key(id(sslobj._sslobj))
            if rebound is not None:
                return rebound
        remaining = take_handshake_state_by_key(placeholder_key)
        return remaining or {"correlation_id": new_correlation_id(), "vhost": None}

    def _audit_handshake_failure(
        self, state: dict[str, str | None], key: int, writer, reason: str
    ) -> None:
        # The SNI callback may have rebound the state to the inner SSL object
        # id before verification failed; remove whichever copy remains.
        inner = state.get("inner_key")
        if inner is not None:
            take_handshake_state_by_key(int(inner))
        take_handshake_state_by_key(key)
        vhost = state.get("vhost")
        peer = writer.get_extra_info("peername")
        event = (
            AuditEvent.CLIENT_CERT_FAILED
            if reason.startswith("client_cert")
            else AuditEvent.CONNECTION_REJECTED
        )
        self._audit.emit(
            event,
            vhost=vhost,
            correlation_id=state["correlation_id"],
            reason=reason,
            peer=str(peer) if peer else None,
        )

    @staticmethod
    def _safe_close(writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(Exception):
            writer.close()

    async def _serve(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        cid: str,
        vhost: str | None,
        sslobj: ssl.SSLObject,
    ) -> None:
        entry = self._store.snapshot.select(vhost)
        require = bool(entry and entry.require_client_cert)
        peer_der = b""
        with contextlib.suppress(Exception):
            peer_der = sslobj.getpeercert(binary_form=True) or b""
        if require:
            # CERT_REQUIRED enforced this during the handshake; the guard is
            # defence in depth and yields a clear, distinguishable record.
            if not peer_der:
                self._audit.emit(
                    AuditEvent.CLIENT_CERT_FAILED,
                    vhost=vhost,
                    correlation_id=cid,
                    reason="client_cert_absent",
                )
                return
            self._audit.emit(
                AuditEvent.CLIENT_CERT_OK,
                vhost=vhost,
                correlation_id=cid,
            )

        if self._request_handler is None:
            # Still record the negotiated session for observability even when
            # no application handler is wired in.
            self._record_session(sslobj, vhost)
            return

        # Connection reuse: serve sequential requests until close / timeout.
        session_recorded = False
        while True:
            try:
                line = await asyncio.wait_for(
                    reader.readline(), timeout=self._config.read_timeout
                )
            except (TimeoutError, asyncio.TimeoutError):
                self._audit.emit(
                    AuditEvent.CONNECTION_REJECTED,
                    vhost=vhost,
                    correlation_id=cid,
                    reason="read_timeout",
                )
                return
            except ssl.SSLError:
                return
            if not line:
                return
            if not line.startswith(
                (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ")
            ):
                return
            # The negotiated session id/ticket is only populated by OpenSSL
            # once handshake messages are fully processed; record it on the
            # first application data so resumed sessions are observable.
            if not session_recorded:
                self._record_session(sslobj, vhost)
                session_recorded = True
            if not await self._consume_headers(reader):
                return
            async with self._conns_lock:
                if writer in self._conns:
                    self._conns[writer].setdefault("requests", 0)
                    self._conns[writer]["requests"] += 1
            await self._request_handler(reader, writer, vhost)
            if writer.is_closing():
                return

    async def _consume_headers(self, reader: asyncio.StreamReader) -> bool:
        while True:
            try:
                line = await asyncio.wait_for(
                    reader.readline(), timeout=self._config.read_timeout
                )
            except (TimeoutError, asyncio.TimeoutError):
                return False
            if line in (b"\r\n", b"\n", b""):
                return line != b""

    def _record_session(self, sslobj: ssl.SSLObject, vhost: str | None) -> None:
        try:
            session = sslobj.session
            sid = bytes(session.id).hex()
            has_ticket = bool(getattr(session, "has_ticket", False))
        except Exception:
            return
        if not sid:
            return
        self._sessions.put(
            SessionInfo(
                session_id=sid,
                vhost=vhost or "*default*",
                epoch=self._sessions.epoch,
                has_ticket=has_ticket,
            )
        )

    # --------------------------------------------------------------- rotation
    async def rotate_session_keys(self) -> int:
        """Rotate session secrets and invalidate every resumable session.

        The bounded registry epoch advances and all SSL contexts are rebuilt;
        OpenSSL derives fresh stateless ticket keys for the new contexts, so
        old tickets/session IDs cannot resume.  A host whose file vanished is
        skipped (already audited) without blocking rotation of the others.
        """
        epoch = self._sessions.rotate()
        snap = self._store.snapshot
        if snap.default is not None:
            with contextlib.suppress(Exception):
                self._store.reload_default(
                    snap.default.cert_file, snap.default.key_file
                )
        from pathlib import Path

        from tls_gateway.config import VHostConfig

        for name, entry_ in list(snap.vhosts.items()):
            try:
                self._store.reload_vhost(
                    VHostConfig(
                        name=name,
                        cert_file=Path(entry_.cert_file),
                        key_file=Path(entry_.key_file),
                        require_client_cert=entry_.require_client_cert,
                    )
                )
            except Exception:  # noqa: BLE001 - rotation continues per host
                continue
        self._audit.emit(
            AuditEvent.SESSION_ROTATED,
            vhost=None,
            correlation_id=new_correlation_id(),
            epoch=epoch,
        )
        return epoch
