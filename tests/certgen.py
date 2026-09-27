"""Test helper: generate CA / server / client certificates on disk."""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_ONE_DAY = datetime.timedelta(days=1)


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _pem_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def make_ca(base: Path, name: str = "Test CA") -> tuple[Path, Path, x509.Certificate]:
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(name))
        .issuer_name(_name(name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _ONE_DAY)
        .not_valid_after(now + 365 * _ONE_DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = _write(base / f"{name}.crt.pem", cert.public_bytes(serialization.Encoding.PEM))
    key_path = _write(base / f"{name}.key.pem", _pem_key(key))
    return cert_path, key_path, cert


def make_leaf(
    base: Path,
    hostname: str,
    ca_cert: x509.Certificate,
    ca_key_path: Path,
    *,
    days_valid: int = 30,
    not_before_offset_days: int = -1,
    client: bool = False,
    name_suffix: str = "",
) -> tuple[Path, Path]:
    key = _key()
    ca_key = serialization.load_pem_private_key(Path(ca_key_path).read_bytes(), password=None)
    now = datetime.datetime.now(datetime.timezone.utc)
    usage = (
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])
        if client
        else x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(hostname))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=not_before_offset_days))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(usage, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
    )
    if not client:
        san: list[x509.GeneralName] = [x509.DNSName(hostname)]
        if hostname in ("localhost", "127.0.0.1"):
            san.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    else:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    cert_path = _write(
        base / f"{hostname}{name_suffix}.crt.pem",
        cert.public_bytes(serialization.Encoding.PEM),
    )
    key_path = _write(base / f"{hostname}{name_suffix}.key.pem", _pem_key(key))
    return cert_path, key_path
