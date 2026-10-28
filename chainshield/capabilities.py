"""Capability registry — availability requires validation, not mere presence."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from chainshield.platform import PlatformInfo, safe_which


class CapStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    PARTIAL = "PARTIAL"
    UNVERIFIED = "UNVERIFIED"
    ERROR = "ERROR"


@dataclass
class Capability:
    id: str
    name: str
    os_support: list[str]
    dependencies: list[str]
    permissions: list[str]
    protocols: list[str]
    limitations: list[str] = field(default_factory=list)
    status: CapStatus = CapStatus.UNVERIFIED
    detail: str = ""

    def summary(self) -> str:
        return f"{self.id}: {self.status.value}" + (f" — {self.detail}" if self.detail else "")


class CapabilityRegistry:
    def __init__(self, platform: PlatformInfo):
        self.platform = platform
        self.capabilities: dict[str, Capability] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.capabilities["proxy_socks5"] = Capability(
            id="proxy_socks5",
            name="SOCKS5 client",
            os_support=["Linux", "Android"],
            dependencies=["Python 3 sockets"],
            permissions=[],
            protocols=["TCP"],
            limitations=["UDP ASSOCIATE: single-hop SOCKS5 only; multi-hop UDP not supported"],
        )
        self.capabilities["proxy_socks5_udp"] = Capability(
            id="proxy_socks5_udp",
            name="SOCKS5 UDP ASSOCIATE",
            os_support=["Linux", "Android"],
            dependencies=["SOCKS5 proxy with UDP ASSOCIATE"],
            permissions=[],
            protocols=["UDP"],
            limitations=[
                "Single hop only",
                "Requires proxy that implements UDP ASSOCIATE",
                "Multi-hop UDP chaining is not supported",
                "Local forwarder does not relay UDP ASSOCIATE to children",
            ],
        )
        self.capabilities["proxy_socks4"] = Capability(
            id="proxy_socks4",
            name="SOCKS4 client",
            os_support=["Linux", "Android"],
            dependencies=["Python 3 sockets"],
            permissions=[],
            protocols=["TCP"],
        )
        self.capabilities["proxy_http_connect"] = Capability(
            id="proxy_http_connect",
            name="HTTP CONNECT proxy",
            os_support=["Linux", "Android"],
            dependencies=["Python 3 sockets"],
            permissions=[],
            protocols=["TCP"],
        )
        self.capabilities["proxy_chain"] = Capability(
            id="proxy_chain",
            name="Multi-hop proxy chain",
            os_support=["Linux", "Android"],
            dependencies=["proxy_socks5", "proxy_http_connect"],
            permissions=[],
            protocols=["TCP"],
            limitations=[
                "Only sequential TCP CONNECT/SOCKS handshakes",
                "No arbitrary UDP chaining",
            ],
        )
        self.capabilities["app_proxy_env"] = Capability(
            id="app_proxy_env",
            name="Application proxy environment variables",
            os_support=["Linux", "Android"],
            dependencies=[],
            permissions=[],
            protocols=["HTTP", "HTTPS", "TCP (if app respects proxy)"],
            limitations=[
                "Only applications that honor HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/SOCKS_PROXY",
                "Does not intercept arbitrary processes",
            ],
        )
        self.capabilities["public_ip_verify"] = Capability(
            id="public_ip_verify",
            name="Public egress IP verification",
            os_support=["Linux", "Android"],
            dependencies=["HTTPS client"],
            permissions=["network"],
            protocols=["HTTPS"],
        )
        self.capabilities["dns_diagnostic"] = Capability(
            id="dns_diagnostic",
            name="DNS resolver diagnostic",
            os_support=["Linux", "Android"],
            dependencies=[],
            permissions=[],
            protocols=["DNS"],
            limitations=["Cannot prove absence of leaks without controlled resolver path"],
        )
        self.capabilities["ld_preload"] = Capability(
            id="ld_preload",
            name="LD_PRELOAD process interception",
            os_support=["Linux"],
            dependencies=["libproxychains or equivalent", "dynamic linker"],
            permissions=[],
            protocols=["TCP"],
            limitations=["Not available in Termux/Android without custom build"],
        )
        self.capabilities["system_tunnel"] = Capability(
            id="system_tunnel",
            name="System VPN / IP tunnel",
            os_support=["Linux", "Android"],
            dependencies=["openvpn|wireguard|VpnService"],
            permissions=["root or VpnService"],
            protocols=["TCP", "UDP", "DNS", "IP"],
            limitations=[
                "ChainShield CLI does not implement Android VpnService",
                "Requires external tunnel process or companion app",
            ],
        )
        self.capabilities["firewall"] = Capability(
            id="firewall",
            name="Firewall rule management",
            os_support=["Linux"],
            dependencies=["iptables or nftables"],
            permissions=["root"],
            protocols=["IP"],
            limitations=["Disabled by default; requires explicit authorization"],
        )
        self.capabilities["live_traffic_observe"] = Capability(
            id="live_traffic_observe",
            name="Live traffic observation",
            os_support=["Linux", "Android"],
            dependencies=[],
            permissions=[],
            protocols=["TCP"],
            limitations=[
                "Observes only connections made through ChainShield adapters",
                "Cannot see system-wide packets without elevated monitor",
            ],
        )

    def refresh(self) -> None:
        """Validate each capability against the current platform."""
        p = self.platform

        def set_cap(cid: str, status: CapStatus, detail: str = "") -> None:
            if cid in self.capabilities:
                self.capabilities[cid].status = status
                self.capabilities[cid].detail = detail

        # Socket-based proxy clients are always implementable in pure Python
        set_cap("proxy_socks5", CapStatus.AVAILABLE, "Pure Python SOCKS5 client")
        set_cap(
            "proxy_socks5_udp",
            CapStatus.PARTIAL,
            "Single-hop UDP ASSOCIATE client; multi-hop and child-process UDP unsupported",
        )
        set_cap("proxy_socks4", CapStatus.AVAILABLE, "Pure Python SOCKS4 client")
        set_cap("proxy_http_connect", CapStatus.AVAILABLE, "Pure Python HTTP CONNECT")
        set_cap("proxy_chain", CapStatus.AVAILABLE, "Sequential TCP hop chaining")
        set_cap(
            "app_proxy_env",
            CapStatus.PARTIAL,
            "Env vars set for child processes; apps must honor them",
        )
        set_cap("public_ip_verify", CapStatus.AVAILABLE, "HTTPS IP-echo endpoints")
        set_cap(
            "dns_diagnostic",
            CapStatus.PARTIAL,
            "Reports configured resolvers; leak proof requires controlled path",
        )

        if p.has_ld_preload and not p.is_termux and not p.is_android:
            set_cap("ld_preload", CapStatus.UNVERIFIED, "Platform supports LD_PRELOAD; no bundled lib")
        else:
            set_cap(
                "ld_preload",
                CapStatus.UNAVAILABLE,
                "Termux/Android or non-Linux: LD_PRELOAD interception not available",
            )

        set_cap(
            "system_tunnel",
            CapStatus.UNAVAILABLE if p.is_termux else CapStatus.UNVERIFIED,
            "External tunnel required; no built-in VpnService client",
        )

        if p.has_iptables and p.is_root:
            set_cap("firewall", CapStatus.UNVERIFIED, "iptables present and root; not auto-enabled")
        else:
            set_cap(
                "firewall",
                CapStatus.UNAVAILABLE,
                "Requires root and iptables/nft; disabled by policy",
            )

        set_cap(
            "live_traffic_observe",
            CapStatus.PARTIAL,
            "Events from proxy adapter and verification only",
        )

    def get(self, cid: str) -> Optional[Capability]:
        return self.capabilities.get(cid)

    def available(self, cid: str) -> bool:
        c = self.capabilities.get(cid)
        return c is not None and c.status in (CapStatus.AVAILABLE, CapStatus.PARTIAL)

    def list_all(self) -> list[Capability]:
        return list(self.capabilities.values())
