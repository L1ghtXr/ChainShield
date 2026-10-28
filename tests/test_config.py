"""Configuration parsing and validation tests."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from chainshield.config import Config, ProxyHop, load_config, save_config


def test_proxy_hop_validate_ok():
    h = ProxyHop(type="socks5", host="127.0.0.1", port=9050)
    assert h.validate() == []


def test_proxy_hop_validate_bad_port():
    h = ProxyHop(type="socks5", host="127.0.0.1", port=0)
    assert any("port" in e.lower() for e in h.validate())


def test_proxy_hop_validate_bad_type():
    h = ProxyHop(type="ftp", host="x", port=1)
    assert any("type" in e.lower() for e in h.validate())


def test_proxy_redacted_hides_password():
    h = ProxyHop(type="http", host="p.example", port=8080, username="u", password="secret")
    r = h.redacted()
    assert "secret" not in r
    assert "***" in r
    assert "u" in r


def test_config_validate_policy():
    cfg = Config(chain_policy="invalid")
    errs = cfg.validate()
    assert any("chain_policy" in e for e in errs)


def test_save_load_roundtrip(tmp_path: Path):
    cfg = Config(
        chain_policy="fail_closed",
        proxies=[ProxyHop(type="socks5", host="10.0.0.1", port=1080, username="a", password="b")],
        require_verification=False,
    )
    path = tmp_path / "config.toml"
    save_config(cfg, path)
    assert path.exists()
    loaded = load_config(path)
    assert loaded.chain_policy == "fail_closed"
    assert len(loaded.proxies) == 1
    assert loaded.proxies[0].host == "10.0.0.1"
    assert loaded.proxies[0].password == "b"
    assert loaded.require_verification is False


def test_load_missing_returns_default(tmp_path: Path):
    cfg = load_config(tmp_path / "nope.toml")
    assert isinstance(cfg, Config)
    assert cfg.proxies == []
