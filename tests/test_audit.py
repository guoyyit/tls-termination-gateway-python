"""Audit records: stable, correlatable, and free of sensitive material."""

from __future__ import annotations

import json

import pytest

from conftest import https_request, start_gateway
from gateway.audit import AuditEvent, AuditEventType, AuditLogger


async def test_audit_events_are_stamped_and_sequenced(cert_layout, backend):
    gw = await start_gateway(cert_layout, backend.port)
    try:
        await https_request(gw.port, sni="localhost", layout=cert_layout)
        await https_request(gw.port, sni="unknown.example.org", layout=cert_layout)
        events = gw.audit.events()
        assert events, "expected audit events"
        seqs = [e.seq for e in events]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
        assert all(e.timestamp for e in events)
        # every event has a stable, known type
        assert all(isinstance(e.event_type, AuditEventType) for e in events)
    finally:
        await gw.server.stop()


async def test_audit_file_sink_writes_jsonl(cert_layout, backend, tmp_path):
    log_path = tmp_path / "audit.jsonl"
    from gateway.config import GatewayConfig
    from gateway.server import build_gateway

    audit = AuditLogger(log_path)
    config = GatewayConfig(
        port=0, backend_port=backend.port, default_vhost=cert_layout.vhost("localhost")
    )
    server = build_gateway(config, audit)
    await server.start()
    port = server.sockets[0].getsockname()[1]
    try:
        await https_request(port, sni="localhost", layout=cert_layout)
    finally:
        await server.stop()
        audit.close()
    lines = log_path.read_text().strip().splitlines()
    assert lines
    for line in lines:
        record = json.loads(line)  # every line is valid JSON
        assert {"seq", "timestamp", "event_type", "message"} <= record.keys()
    assert any(r["event_type"] == "cert_loaded" for r in map(json.loads, lines))


async def test_audit_never_contains_private_key_material(cert_layout, backend):
    gw = await start_gateway(cert_layout, backend.port)
    try:
        await https_request(gw.port, sni="localhost", layout=cert_layout)
        key_pem = cert_layout.vhost("localhost").key_path.read_text()
        key_body = key_pem.replace("-----BEGIN PRIVATE KEY-----", "").replace(
            "-----END PRIVATE KEY-----", ""
        ).replace("\n", "")[:64]
        for event in gw.audit.events():
            blob = json.dumps(event.to_dict())
            assert "PRIVATE KEY" not in blob
            assert key_body not in blob
    finally:
        await gw.server.stop()


def test_audit_event_types_cover_required_scenarios():
    # the scenarios called out by the requirements must have stable types
    required = {
        "cert_loaded",
        "cert_load_failed",
        "cert_reloaded",
        "cert_selected",
        "cert_default_used",
        "client_cert_missing",
        "client_cert_invalid",
        "client_cert_ok",
        "session_keys_rotated",
        "connection_rejected",
        "slow_client_timeout",
    }
    assert required <= {e.value for e in AuditEventType}
