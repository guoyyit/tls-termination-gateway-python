from tls_gateway.config import load_config


def test_load_full_config(tmp_path, material):
    cfg_file = tmp_path / "g.toml"
    cfg_file.write_text(
        f'''
[server]
tls_port = 9443
max_connections = 7

[default_cert]
cert = "{material["default_c"]}"
key = "{material["default_k"]}"

[[vhosts]]
name = "a.example"
cert = "{material["a_c"]}"
key = "{material["a_k"]}"

[[vhosts]]
name = "secure.example"
cert = "{material["a_c"]}"
key = "{material["a_k"]}"
require_client_cert = true
client_ca = "{material["ca_c"]}"
'''
    )
    cfg = load_config(cfg_file)
    assert cfg.tls_port == 9443
    assert cfg.max_connections == 7
    assert set(cfg.vhosts) == {"a.example", "secure.example"}
    assert cfg.vhosts["secure.example"].require_client_cert is True
    assert cfg.vhosts["secure.example"].client_ca_file == material["ca_c"]


def test_client_cert_requires_ca(tmp_path, material):
    cfg_file = tmp_path / "g.toml"
    cfg_file.write_text(
        f'''
[[vhosts]]
name = "s.example"
cert = "{material["a_c"]}"
key = "{material["a_k"]}"
require_client_cert = true
'''
    )
    import pytest

    with pytest.raises(ValueError):
        load_config(cfg_file)
