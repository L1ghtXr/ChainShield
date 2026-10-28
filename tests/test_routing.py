"""Engine selection and fail-closed behavior."""

from __future__ import annotations

from chainshield.capabilities import CapabilityRegistry
from chainshield.config import Config, ProxyHop
from chainshield.events import EventBus
from chainshield.platform import detect_platform
from chainshield.routing import EngineSelector
from chainshield.tunnel import TunnelAdapter


def _selector():
    p = detect_platform()
    reg = CapabilityRegistry(p)
    reg.refresh()
    ev = EventBus()
    tun = TunnelAdapter(p, ev)
    return EngineSelector(p, reg, ev, tun)


def test_select_no_proxy_requires_protection():
    sel = _selector()
    cfg = Config(proxies=[])
    plan = sel.select(cfg, ["curl", "https://example.com"], require_protection=True)
    assert plan.ok is False


def test_select_with_proxy_ok():
    sel = _selector()
    cfg = Config(proxies=[ProxyHop(type="socks5", host="127.0.0.1", port=9050)])
    plan = sel.select(cfg, ["curl", "https://example.com"], require_protection=True)
    assert plan.ok is True
    assert plan.coverage == "application"
    assert plan.env  # proxy env set


def test_select_nmap_strict_rejects():
    sel = _selector()
    cfg = Config(
        proxies=[ProxyHop(type="socks5", host="127.0.0.1", port=9050)],
        chain_policy="strict",
    )
    plan = sel.select(cfg, ["nmap", "-sS", "1.2.3.4"], require_protection=True)
    assert plan.ok is False
    assert any("nmap" in u.lower() or "raw" in u.lower() for u in plan.unsupported) or "Unsupported" in plan.reason


def test_direct_when_not_required():
    sel = _selector()
    cfg = Config(proxies=[])
    plan = sel.select(cfg, require_protection=False)
    assert plan.ok is True
    assert plan.engine == "direct"
