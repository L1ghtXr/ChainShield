"""Platform and capability detection."""

from __future__ import annotations

from chainshield.capabilities import CapStatus, CapabilityRegistry
from chainshield.platform import detect_platform


def test_detect_platform_fields():
    p = detect_platform()
    assert p.system
    assert isinstance(p.is_termux, bool)
    assert isinstance(p.limitations, list)


def test_registry_refresh():
    p = detect_platform()
    reg = CapabilityRegistry(p)
    reg.refresh()
    socks = reg.get("proxy_socks5")
    assert socks is not None
    assert socks.status == CapStatus.AVAILABLE
    assert reg.available("proxy_socks5")


def test_ld_preload_termux_unavailable_or_unverif():
    p = detect_platform()
    reg = CapabilityRegistry(p)
    reg.refresh()
    ld = reg.get("ld_preload")
    assert ld is not None
    # On this CI Linux host it may be UNVERIFIED; on Termux UNAVAILABLE
    assert ld.status in (CapStatus.UNAVAILABLE, CapStatus.UNVERIFIED)


def test_firewall_default_not_available_without_root():
    p = detect_platform()
    reg = CapabilityRegistry(p)
    reg.refresh()
    fw = reg.get("firewall")
    assert fw is not None
    if not p.is_root:
        assert fw.status == CapStatus.UNAVAILABLE
