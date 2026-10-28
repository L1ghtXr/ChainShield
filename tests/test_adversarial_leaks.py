"""Adversarial tests: fail-closed, env bypass neutralization, no credential leak."""

from __future__ import annotations

import os

from chainshield.apps import requires_strict_reject
from chainshield.config import Config, ProxyHop
from chainshield.events import EventBus
from chainshield.forwarder import LocalChainForwarder
from chainshield.proxy import connect_through_chain
from chainshield.routing import EngineSelector, run_protected
from chainshield.capabilities import CapabilityRegistry
from chainshield.platform import detect_platform
from chainshield.state import AppState, ProtectionState
from chainshield.tunnel import TunnelAdapter


def test_no_proxy_env_neutralized_in_forwarder():
    hops = [ProxyHop(type="socks5", host="127.0.0.1", port=1)]
    cfg = Config(proxies=hops)
    fwd = LocalChainForwarder(hops, cfg)
    host, port = fwd.start()
    try:
        env = fwd.proxy_env()
        assert env.get("NO_PROXY") == ""
        assert env.get("no_proxy") == ""
        assert "secret" not in str(env)
        assert env["ALL_PROXY"].startswith("socks5://127.0.0.1:")
        assert env["CHAINSHIELD_PROTECTION_LEVEL"] == "A"
    finally:
        fwd.stop()


def test_run_strips_parent_no_proxy(monkeypatch):
    """Parent NO_PROXY must not survive into protected child env setup."""
    hops = [ProxyHop(type="socks5", host="127.0.0.1", port=1)]
    cfg = Config(proxies=hops, chain_policy="strict")
    # Health check will fail (port 1) — still validates early fail-closed path
    p = detect_platform()
    reg = CapabilityRegistry(p)
    reg.refresh()
    ev = EventBus()
    sel = EngineSelector(p, reg, ev, TunnelAdapter(p, ev))
    st = AppState()
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("HTTP_PROXY", "http://evil.example:1")
    rc = run_protected(["curl", "https://example.com"], cfg, st, sel, ev)
    assert rc == 1  # fail-closed on dead hop
    assert st.protection == ProtectionState.ERROR


def test_strict_rejects_unsupported_tools():
    assert requires_strict_reject("nmap")
    assert requires_strict_reject("ping")
    p = detect_platform()
    reg = CapabilityRegistry(p)
    reg.refresh()
    ev = EventBus()
    sel = EngineSelector(p, reg, ev, TunnelAdapter(p, ev))
    cfg = Config(
        proxies=[ProxyHop(type="socks5", host="127.0.0.1", port=9050)],
        chain_policy="strict",
    )
    plan = sel.select(cfg, ["nmap", "-sS", "1.2.3.4"], require_protection=True)
    assert plan.ok is False


def test_empty_proxy_list_fail_closed():
    p = detect_platform()
    reg = CapabilityRegistry(p)
    reg.refresh()
    ev = EventBus()
    sel = EngineSelector(p, reg, ev, TunnelAdapter(p, ev))
    plan = sel.select(Config(proxies=[]), ["curl", "https://x"], require_protection=True)
    assert plan.ok is False


def test_intermediate_hop_failure_no_socket():
    hops = [
        ProxyHop(type="socks5", host="127.0.0.1", port=1),
        ProxyHop(type="socks5", host="127.0.0.1", port=2),
    ]
    result = connect_through_chain(
        hops, "example.com", 443, connect_timeout=0.5, handshake_timeout=1, policy="strict"
    )
    assert result.success is False
    assert result.final_socket is None


def test_credentials_not_in_forwarder_env():
    hops = [
        ProxyHop(
            type="socks5",
            host="10.9.8.7",
            port=1080,
            username="alice",
            password="super-secret-password",
        )
    ]
    fwd = LocalChainForwarder(hops, Config(proxies=hops))
    fwd.start()
    try:
        blob = " ".join(fwd.proxy_env().values())
        assert "super-secret-password" not in blob
        assert "alice" not in blob
        assert "10.9.8.7" not in blob
    finally:
        fwd.stop()
