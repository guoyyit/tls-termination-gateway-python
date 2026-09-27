"""Application entry point.

The existing plain-HTTP FastAPI listener is kept as-is (uvicorn on
GATEWAY_BACKEND_PORT, default 8000). The TLS termination gateway is added
alongside it on GATEWAY_PORT (default 8443) and proxies decrypted traffic
to the backend listener.
"""

import asyncio
import os
import signal
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from gateway.audit import AuditLogger
from gateway.config import ClientAuthMode, GatewayConfig, VHostConfig
from gateway.server import build_gateway

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


def _client_auth(value: str) -> ClientAuthMode:
    return ClientAuthMode(value.strip().lower())


def gateway_config_from_env() -> GatewayConfig:
    """Build the gateway config from environment variables.

    GATEWAY_CERT_DIR holds one ``<host>.crt.pem`` / ``<host>.key.pem`` pair
    per virtual host; GATEWAY_DEFAULT_HOST picks the default certificate.
    """
    cert_dir = Path(os.environ.get("GATEWAY_CERT_DIR", "certs"))
    default_host = os.environ.get("GATEWAY_DEFAULT_HOST", "localhost")
    client_auth = _client_auth(os.environ.get("GATEWAY_CLIENT_AUTH", "none"))
    client_ca = os.environ.get("GATEWAY_CLIENT_CA")

    def vhost(hostname: str) -> VHostConfig:
        return VHostConfig(
            hostname=hostname,
            cert_path=cert_dir / f"{hostname}.crt.pem",
            key_path=cert_dir / f"{hostname}.key.pem",
            client_auth=client_auth,
            client_ca_path=Path(client_ca) if client_ca else None,
        )

    extra_hosts = [
        h for h in os.environ.get("GATEWAY_VHOSTS", "").split(",") if h.strip()
    ]
    return GatewayConfig(
        host=os.environ.get("GATEWAY_HOST", "127.0.0.1"),
        port=int(os.environ.get("GATEWAY_PORT", "8443")),
        backend_host=os.environ.get("GATEWAY_BACKEND_HOST", "127.0.0.1"),
        backend_port=int(os.environ.get("GATEWAY_BACKEND_PORT", "8000")),
        default_vhost=vhost(default_host),
        vhosts=tuple(vhost(h.strip()) for h in extra_hosts),
        max_connections=int(os.environ.get("GATEWAY_MAX_CONNECTIONS", "1000")),
        slow_client_timeout=float(os.environ.get("GATEWAY_SLOW_CLIENT_TIMEOUT", "10")),
        shutdown_grace_period=float(os.environ.get("GATEWAY_SHUTDOWN_GRACE", "5")),
        session_cache_size=int(os.environ.get("GATEWAY_SESSION_CACHE_SIZE", "1024")),
        session_ttl=float(os.environ.get("GATEWAY_SESSION_TTL", "300")),
        session_key_rotation_interval=float(
            os.environ.get("GATEWAY_SESSION_ROTATION", "3600")
        ),
        audit_log_path=Path(a) if (a := os.environ.get("GATEWAY_AUDIT_LOG")) else None,
    )


async def amain() -> None:
    config = gateway_config_from_env()
    audit = AuditLogger(config.audit_log_path)
    gateway = build_gateway(config, audit)
    await gateway.start()

    backend = uvicorn.Server(
        uvicorn.Config(app, host=config.backend_host, port=config.backend_port)
    )

    loop = asyncio.get_running_loop()
    stopping = False

    def request_stop() -> None:
        nonlocal stopping
        if stopping:
            return
        stopping = True
        backend.should_exit = True
        asyncio.ensure_future(gateway.stop())

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, request_stop)

    await asyncio.gather(backend.serve(), gateway.serve_forever())
    audit.close()


if __name__ == "__main__":
    asyncio.run(amain())
