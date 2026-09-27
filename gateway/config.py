"""Configuration types for the TLS termination gateway."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path


class ClientAuthMode(enum.Enum):
    """How a virtual host treats client certificates."""

    NONE = "none"          # do not request a client certificate
    OPTIONAL = "optional"  # request but allow absence
    REQUIRED = "required"  # request and require a valid certificate


@dataclass(frozen=True)
class VHostConfig:
    """Configuration for a single virtual host."""

    hostname: str
    cert_path: Path
    key_path: Path
    client_auth: ClientAuthMode = ClientAuthMode.NONE
    client_ca_path: Path | None = None  # CA bundle used to verify client certs


@dataclass(frozen=True)
class GatewayConfig:
    """Top-level gateway configuration."""

    host: str = "127.0.0.1"
    port: int = 8443
    backend_host: str = "127.0.0.1"
    backend_port: int = 8000
    default_vhost: VHostConfig | None = None
    vhosts: tuple[VHostConfig, ...] = ()
    max_connections: int = 1000
    slow_client_timeout: float = 10.0
    shutdown_grace_period: float = 5.0
    session_cache_size: int = 1024
    session_ttl: float = 300.0
    session_key_rotation_interval: float = 3600.0
    audit_log_path: Path | None = None
