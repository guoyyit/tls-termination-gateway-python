from pathlib import Path

import pytest

from tls_gateway.config import VHostConfig
from tls_gateway.errors import CertificateExpired
from tls_gateway.cert_store import (
    CertificateStore,
    classify_client_cert_error,
)
from tls_gateway.session_cache import SessionCache
from tls_gateway.audit import AuditLogger


def _store():
    return CertificateStore(SessionCache(), AuditLogger())


def test_cert_load_rejects_key_mismatch(material):
    store = _store()
    failures = store.load_initial(
        [VHostConfig("a.example", material["a_c"], material["b_k"])],
        (str(material["default_c"]), str(material["default_k"])),
    )
    assert "a.example" in failures
    assert "do not match" in failures["a.example"]


def test_startup_isolates_bad_vhosts_and_keeps_default(material):
    store = _store()
    vhosts = [
        VHostConfig("a.example", material["a_c"], material["a_k"]),
        VHostConfig("exp.example", material["expired_c"], material["expired_k"]),
        VHostConfig("gone.example", Path("/no/such.crt"), Path("/no/such.key")),
        VHostConfig("mismatch.example", material["a_c"], material["b_k"]),
    ]
    failures = store.load_initial(
        vhosts, (str(material["default_c"]), str(material["default_k"]))
    )
    assert set(failures) == {"exp.example", "gone.example", "mismatch.example"}
    snap = store.snapshot
    # Healthy host and default still serve.
    assert "a.example" in snap.vhosts
    assert snap.default is not None
    assert store.front_context is not None


def test_selection_order(material):
    store = _store()
    store.load_initial(
        [VHostConfig("a.example", material["a_c"], material["a_k"]),
         VHostConfig("b.example", material["b_c"], material["b_k"])],
        (str(material["default_c"]), str(material["default_k"])),
    )
    snap = store.snapshot
    assert snap.select("a.example").fingerprint != snap.select("b.example").fingerprint
    # Unknown SNI and absent SNI both resolve to the default cert.
    assert snap.select("unknown.example") is snap.default
    assert snap.select(None) is snap.default


def test_hot_reload_is_atomic_and_keeps_old_on_failure(material):
    store = _store()
    store.load_initial(
        [VHostConfig("a.example", material["a_c"], material["a_k"])],
        (str(material["default_c"]), str(material["default_k"])),
    )
    old = store.snapshot.select("a.example")
    new_entry = store.reload_vhost(
        VHostConfig("a.example", material["b_c"], material["b_k"])
    )
    assert new_entry is store.snapshot.select("a.example")
    assert new_entry.fingerprint != old.fingerprint
    # Established connections still reference the old immutable entry.
    assert old.context is not new_entry.context

    with pytest.raises(Exception):
        store.reload_vhost(
            VHostConfig("a.example", Path("/missing.crt"), material["b_k"])
        )
    assert store.snapshot.select("a.example") is new_entry


def test_expired_cert_raises_distinct_error(material):
    from tls_gateway.cert_store import _check_validity
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(material["expired_c"].read_bytes())
    with pytest.raises(CertificateExpired):
        _check_validity(cert)


def test_classify_client_cert_reasons():
    assert (
        classify_client_cert_error(
            Exception("[SSL: PEER_DID_NOT_RETURN_A_CERTIFICATE] nope")
        )
        == "client_cert_absent"
    )
    assert (
        classify_client_cert_error(Exception("certificate has expired"))
        == "client_cert_expired"
    )
    assert (
        classify_client_cert_error(
            Exception("unable to get local issuer certificate")
        )
        == "client_cert_unknown_ca"
    )
    assert classify_client_cert_error(Exception("weird")) == "client_cert_failed"
