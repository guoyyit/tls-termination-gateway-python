"""Shared fixtures: certificates, backend responder, TLS client helper."""

from __future__ import annotations

import asyncio
import hashlib
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

import certgen  # noqa: E402

from gateway.audit import AuditLogger  # noqa: E402
from gateway.config import ClientAuthMode, GatewayConfig, VHostConfig  # noqa: E402
from gateway.server import build_gateway  # noqa: E402


@dataclass
class CertLayout:
    base: Path
    ca_cert: Path
    ca_key: Path

    def vhost(self, hostname: str, **kwargs) -> VHostConfig:
        return VHostConfig(
            hostname=hostname,
            cert_path=self.base / f"{hostname}.crt.pem",
            key_path=self.base / f"{hostname}.key.pem",
            **kwargs,
        )

    def make_vhost(self, hostname: str, suffix: str = "", **kwargs) -> VHostConfig:
        """Generate a fresh leaf for hostname and return its VHostConfig."""
        from cryptography import x509

        ca = x509.load_pem_x509_certificate(self.ca_cert.read_bytes())
        crt, key = certgen.make_leaf(
            self.base, hostname, ca, self.ca_key, name_suffix=suffix
        )
        return VHostConfig(hostname=hostname, cert_path=crt, key_path=key, **kwargs)


@pytest.fixture(scope="session")
def cert_layout(tmp_path_factory) -> CertLayout:
    base = tmp_path_factory.mktemp("certs")
    ca_cert, ca_key, ca = certgen.make_ca(base)
    certgen.make_leaf(base, "localhost", ca, ca_key)
    certgen.make_leaf(base, "www.example.com", ca, ca_key)
    certgen.make_leaf(base, "api.example.com", ca, ca_key)
    return CertLayout(base=base, ca_cert=ca_cert, ca_key=ca_key)


class Backend:
    """Minimal HTTP backend used to verify proxying."""

    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.server: asyncio.AbstractServer | None = None
        self.requests: list[dict] = []
        self.port = 0
        self.tasks: set[asyncio.Task] = set()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self.tasks.add(task)
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                if not line:
                    return
                headers = {}
                while True:
                    line = await asyncio.wait_for(reader.readline(), timeout=5)
                    if line in (b"\r\n", b"\n", b""):
                        break
                    k, _, v = line.decode().partition(":")
                    headers[k.strip().lower()] = v.strip()
                self.requests.append(headers)
                if self.delay:
                    await asyncio.sleep(self.delay)
                body = b'{"backend": true, "host": "' + headers.get(
                    "host", ""
                ).encode() + b'"}'
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
                )
                await writer.drain()
                if headers.get("connection", "").lower() == "close":
                    return
        except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            return
        finally:
            if task is not None:
                self.tasks.discard(task)
            try:
                writer.close()
            except Exception:
                pass

    async def start(self) -> "Backend":
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        # cancel in-flight handlers first: Server.wait_closed() (3.12+)
        # waits for connection handlers and would otherwise block on them
        for task in list(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()


@pytest.fixture()
async def backend():
    b = await Backend().start()
    yield b
    await b.stop()


@dataclass
class ClientResult:
    status: int
    headers: dict
    body: bytes
    cert_fingerprint: str | None


def client_ctx(
    layout: CertLayout,
    *,
    client_cert: tuple[Path, Path] | None = None,
    trust_ca: Path | None = None,
) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(trust_ca or layout.ca_cert))
    ctx.check_hostname = False
    if client_cert is not None:
        ctx.load_cert_chain(str(client_cert[0]), str(client_cert[1]))
    return ctx


async def https_request(
    port: int,
    *,
    sni: str | None,
    layout: CertLayout,
    path: str = "/",
    host_header: str | None = None,
    client_cert: tuple[Path, Path] | None = None,
    ctx: ssl.SSLContext | None = None,
) -> ClientResult:
    ctx = ctx or client_ctx(layout, client_cert=client_cert)
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=ctx, server_hostname=sni
    )
    try:
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True)
        fingerprint = hashlib.sha256(der).hexdigest() if der else None
        host = host_header or sni or "localhost"
        writer.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        lines = head.decode().split("\r\n")
        status = int(lines[0].split()[1])
        headers = {}
        for line in lines[1:-2]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", 0))
        body = (
            await asyncio.wait_for(reader.readexactly(length), timeout=10)
            if length
            else b""
        )
        return ClientResult(status, headers, body, fingerprint)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


@dataclass
class RunningGateway:
    server: object
    audit: AuditLogger
    port: int
    config: GatewayConfig


async def start_gateway(
    layout: CertLayout,
    backend_port: int,
    *,
    vhosts: tuple[VHostConfig, ...] = (),
    default: VHostConfig | None = None,
    **overrides,
) -> RunningGateway:
    audit = AuditLogger()
    config = GatewayConfig(
        port=0,
        backend_port=backend_port,
        default_vhost=default or layout.vhost("localhost"),
        vhosts=vhosts,
        **overrides,
    )
    server = build_gateway(config, audit)
    await server.start()
    port = server.sockets[0].getsockname()[1]
    return RunningGateway(server=server, audit=audit, port=port, config=config)


def audit_types(audit: AuditLogger) -> list:
    return [e.event_type for e in audit.events()]


class TlsClient:
    """A persistent TLS client connection for keep-alive / reload tests."""

    def __init__(self, reader, writer, fingerprint: str | None) -> None:
        self.reader = reader
        self.writer = writer
        self.fingerprint = fingerprint

    @classmethod
    async def connect(
        cls,
        port: int,
        *,
        sni: str | None,
        layout: CertLayout,
        client_cert: tuple[Path, Path] | None = None,
    ) -> "TlsClient":
        ctx = client_ctx(layout, client_cert=client_cert)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=ctx, server_hostname=sni
        )
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        fp = hashlib.sha256(der).hexdigest() if der else None
        return cls(reader, writer, fp)

    async def request(self, host: str, path: str = "/", keep_alive: bool = True):
        connection = "keep-alive" if keep_alive else "close"
        self.writer.write(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: {connection}\r\n\r\n".encode()
        )
        await self.writer.drain()
        head = await asyncio.wait_for(self.reader.readuntil(b"\r\n\r\n"), timeout=10)
        lines = head.decode().split("\r\n")
        status = int(lines[0].split()[1])
        headers = {}
        for line in lines[1:-2]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", 0))
        body = (
            await asyncio.wait_for(self.reader.readexactly(length), timeout=10)
            if length
            else b""
        )
        return status, headers, body

    async def close(self) -> None:
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass
