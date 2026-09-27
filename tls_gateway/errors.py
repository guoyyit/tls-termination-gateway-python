"""Stable, diagnostic error types for the TLS termination gateway."""


class GatewayError(Exception):
    """Base class for gateway errors."""


class CertificateError(GatewayError):
    """Base class for certificate loading / validation errors."""


class CertificateNotFound(CertificateError):
    """Certificate or key file is missing on disk."""


class CertificateInvalid(CertificateError):
    """Certificate or private key is corrupt, unreadable, or mismatched."""


class CertificateExpired(CertificateError):
    """Certificate is expired or not yet valid."""


class ClientCertError(GatewayError):
    """Base class for client certificate verification failures.

    The ``reason`` is a stable, machine-readable code that is safe to put in
    audit records and TLS alerts.  No request-sensitive data is included.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason if not detail else f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


class GatewayShutdown(GatewayError):
    """Raised when new work is rejected because the gateway is shutting down."""
