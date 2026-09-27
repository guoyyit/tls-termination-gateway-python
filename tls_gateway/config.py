"""Gateway configuration model and TOML loader.

Example ``gateway.toml``::

    [server]
    plaintext_host = "127.0.0.1"
    plaintext_port = 8080
    tls_host = "127.0.0.1"
    tls_port = 8443
    max_connections = 1024
    handshake_timeout = 10.0
    read_timeout = 30.0
    shutdown_timeout = 15.0
    max_sessions = 4096

    [default_cert]
    cert = "/etc/tls/default.crt"
    key  = "/etc/tls/default.key"

    [[vhosts]]
    name = "a.example"
    cert = "/etc/tls/a.crt"
    key  = "/etc/tls/a.key"
    require_client_cert = true
    client_ca = "/etc/tls/client-ca.crt"
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class VHostConfig:
    """Configuration for one virtual host (keyed by its SNI hostname)."""

    name: str
    cert_file: Path
    key_file: Path
    require_client_cert: bool = False
    client_ca_file: Path | None = None


@dataclass(frozen=True)
class GatewayConfig:
    """Top-level gateway configuration."""

    vhosts: dict[str, VHostConfig] = field(default_factory=dict)
    default_cert_file: Path | None = None
    default_key_file: Path | None = None
    plaintext_host: str = "127.0.0.1"
    plaintext_port: int = 8080
    tls_host: str = "127.0.0.1"
    tls_port: int = 8443
    max_connections: int = 1024
    handshake_timeout: float = 10.0
    read_timeout: float = 30.0
    shutdown_timeout: float = 15.0
    max_sessions: int = 4096


def load_config(path: str | Path) -> GatewayConfig:
    """Load gateway configuration from a TOML file."""
    path = Path(path)
    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    server = data.get("server", {})
    default = data.get("default_cert")
    vhosts: dict[str, VHostConfig] = {}
    for raw in data.get("vhosts", []):
        require = bool(raw.get("require_client_cert", False))
        ca = raw.get("client_ca")
        cfg = VHostConfig(
            name=raw["name"],
            cert_file=Path(raw["cert"]),
            key_file=Path(raw["key"]),
            require_client_cert=require,
            client_ca_file=Path(ca) if ca else None,
        )
        if require and cfg.client_ca_file is None:
            raise ValueError(
                f"vhost {cfg.name!r} requires a client cert but no client_ca given"
            )
        vhosts[cfg.name] = cfg

    default_cert = Path(default["cert"]) if default else None
    default_key = Path(default["key"]) if default else None
    if (default_cert is None) != (default_key is None):
        raise ValueError("default_cert requires both cert and key")

    return GatewayConfig(
        vhosts=vhosts,
        default_cert_file=default_cert,
        default_key_file=default_key,
        plaintext_host=str(server.get("plaintext_host", "127.0.0.1")),
        plaintext_port=int(server.get("plaintext_port", 8080)),
        tls_host=str(server.get("tls_host", "127.0.0.1")),
        tls_port=int(server.get("tls_port", 8443)),
        max_connections=int(server.get("max_connections", 1024)),
        handshake_timeout=float(server.get("handshake_timeout", 10.0)),
        read_timeout=float(server.get("read_timeout", 30.0)),
        shutdown_timeout=float(server.get("shutdown_timeout", 15.0)),
        max_sessions=int(server.get("max_sessions", 4096)),
    )
