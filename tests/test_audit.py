import json

from tls_gateway.audit import AuditEvent


def test_redacts_non_whitelisted_fields(audit_buffer):
    audit, buf = audit_buffer
    audit.emit(
        AuditEvent.CLIENT_CERT_FAILED,
        vhost="a.example",
        correlation_id="cid-1",
        reason="client_cert_unknown_ca",
        client_subject_cn="alice",
        private_key="BEGIN PRIVATE KEY SECRET",
        request_body="password=hunter2",
    )
    raw = buf.getvalue()
    assert "SECRET" not in raw
    assert "hunter2" not in raw
    record = json.loads(raw.strip())
    assert record["event"] == "client_cert_failed"
    assert record["correlation_id"] == "cid-1"
    assert record["reason"] == "client_cert_unknown_ca"
    assert record["extra"]["client_subject_cn"] == "alice"


def test_cert_events_are_structured(audit_buffer):
    audit, buf = audit_buffer
    audit.emit(
        AuditEvent.CERT_LOADED,
        vhost="a.example",
        correlation_id="cid-2",
        fingerprint="ab12",
        not_after=1.0,
    )
    record = json.loads(buf.getvalue().strip())
    assert record["event"] == "cert_loaded"
    assert record["extra"]["fingerprint"] == "ab12"
