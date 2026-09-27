"""On-the-fly certificate generation for tests (no committed key material)."""

from __future__ import annotations

import datetime as dt
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _write_key(path: Path) -> rsa.RSAPrivateKey:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return key


def self_signed(
    d: Path,
    name: str,
    common_name: str,
    *,
    is_ca: bool = False,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
) -> tuple[Path, Path]:
    """Create a self-signed cert; returns (cert_path, key_path)."""
    cert_p, key_p = d / f"{name}.crt", d / f"{name}.key"
    key = _write_key(key_p)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - dt.timedelta(days=1))
        .not_valid_after(not_after or now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    cert_p.write_bytes(
        builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    )
    return cert_p, key_p


def client_cert(
    d: Path, name: str, ca_cert: Path, ca_key: Path, *, common_name: str = "client"
) -> tuple[Path, Path]:
    """Issue a client certificate signed by the given CA."""
    key = _write_key(d / f"{name}.key")
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    ca = x509.load_pem_x509_certificate(ca_cert.read_bytes())
    ca_priv = serialization.load_pem_private_key(ca_key.read_bytes(), password=None)
    now = dt.datetime.now(dt.timezone.utc)
    # serial_number needs a unique int; uuid4 int may exceed 160 bits rarely;
    # mask to 159 bits to stay in the valid serial range.
    serial = uuid.uuid4().int & ((1 << 159) - 1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_priv, hashes.SHA256())
    )
    cert_p = d / f"{name}.crt"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_p, d / f"{name}.key"
