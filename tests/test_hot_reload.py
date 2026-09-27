"""Hot reload: atomic swap, no interruption, no mismatched intermediate state."""

from __future__ import annotations

import asyncio

import pytest

import certgen
from conftest import TlsClient, start_gateway
from gateway.audit import AuditEventType
from gateway.certs import CertLoadError
from gateway.config import VHostConfig


def _new_cert(layout, hostname: str, suffix: str) -> VHostConfig:
    from cryptography import x509

    ca = x509.load_pem_x509_certificate(layout.ca_cert.read_bytes())
    crt, key = certgen.make_leaf(layout.base, hostname, ca, layout.ca_key, name_suffix=suffix)
    return VHostConfig(hostname=hostname, cert_path=crt, key_path=key)


async def test_reload_applies_to_new_connections_old_keep_serving(cert_layout, backend):
    gw = await start_gateway(
        cert_layout, backend.port, vhosts=(cert_layout.vhost("www.example.com"),)
    )
    try:
        store = gw.server._registry._store
        old_fp = store.get("www.example.com").fingerprint

        # an established connection before the reload
        old_client = await TlsClient.connect(gw.port, sni="www.example.com", layout=cert_layout)
        assert old_client.fingerprint == old_fp
        status, _, _ = await old_client.request("www.example.com")
        assert status == 200

        # hot reload
        new_cfg = _new_cert(cert_layout, "www.example.com", ".v2")
        bundle = gw.server._registry.reload(new_cfg)
        assert bundle.version == 1
        assert store.get("www.example.com").fingerprint == bundle.fingerprint != old_fp

        # new connections see only the new certificate
        new_client = await TlsClient.connect(gw.port, sni="www.example.com", layout=cert_layout)
        assert new_client.fingerprint == bundle.fingerprint
        status, _, _ = await new_client.request("www.example.com")
        assert status == 200

        # the pre-existing connection is uninterrupted and still works
        status, _, _ = await old_client.request("www.example.com")
        assert status == 200

        reloaded = [
            e for e in gw.audit.events() if e.event_type is AuditEventType.CERT_RELOADED
        ]
        assert reloaded and reloaded[-1].detail["version"] == 1

        await old_client.close()
        await new_client.close()
    finally:
        await gw.server.stop()


async def test_concurrent_reloads_and_handshakes_never_mismatch(cert_layout, backend):
    gw = await start_gateway(
        cert_layout, backend.port, vhosts=(cert_layout.vhost("api.example.com"),)
    )
    try:
        store = gw.server._registry._store
        versions = {store.get("api.example.com").fingerprint}
        configs = [_new_cert(cert_layout, "api.example.com", f".r{i}") for i in range(3)]

        stop = asyncio.Event()
        failures: list[BaseException] = []
        seen: set[str] = set()

        async def hammer() -> None:
            while not stop.is_set():
                try:
                    client = await TlsClient.connect(
                        gw.port, sni="api.example.com", layout=cert_layout
                    )
                    seen.add(client.fingerprint)
                    await client.close()
                except BaseException as exc:  # noqa: BLE001
                    failures.append(exc)

        hammers = [asyncio.create_task(hammer()) for _ in range(8)]
        for cfg in configs:
            await asyncio.sleep(0.02)
            bundle = gw.server._registry.reload(cfg)
            versions.add(bundle.fingerprint)
        stop.set()
        await asyncio.gather(*hammers)

        assert not failures, failures
        # every served certificate was a complete, valid version
        assert seen <= versions and seen
        # and the final version is the one now served
        client = await TlsClient.connect(gw.port, sni="api.example.com", layout=cert_layout)
        assert client.fingerprint == store.get("api.example.com").fingerprint
        await client.close()
    finally:
        await gw.server.stop()


async def test_failed_reload_keeps_previous_certificate(cert_layout, backend):
    gw = await start_gateway(
        cert_layout, backend.port, vhosts=(cert_layout.vhost("www.example.com"),)
    )
    try:
        store = gw.server._registry._store
        old_fp = store.get("www.example.com").fingerprint

        # mismatched key -> reload must fail and keep the old bundle
        other = _new_cert(cert_layout, "www.example.com", ".other")
        bad_cfg = VHostConfig(
            hostname="www.example.com",
            cert_path=other.cert_path,
            key_path=cert_layout.vhost("api.example.com").key_path,
        )
        with pytest.raises(CertLoadError):
            gw.server._registry.reload(bad_cfg)
        assert store.get("www.example.com").fingerprint == old_fp

        client = await TlsClient.connect(gw.port, sni="www.example.com", layout=cert_layout)
        assert client.fingerprint == old_fp
        status, _, _ = await client.request("www.example.com")
        assert status == 200
        await client.close()
    finally:
        await gw.server.stop()
