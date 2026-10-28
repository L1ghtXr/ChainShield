"""Tunnel adapter — integration boundary only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from chainshield.config import Config
from chainshield.events import EventBus, EventProvenance, EventSource
from chainshield.platform import PlatformInfo


@dataclass
class TunnelStatus:
    active: bool
    tunnel_type: str
    detail: str
    coverage: str  # none | application | device
    available: bool


class TunnelAdapter:
    """
    ChainShield does not implement Android VpnService or kernel tunnels itself.
    This adapter reports status and documents required external integrations.
    """

    def __init__(self, platform: PlatformInfo, events: Optional[EventBus] = None):
        self.platform = platform
        self.events = events

    def status(self, cfg: Config) -> TunnelStatus:
        t = (cfg.tunnel_type or "none").lower()
        if t in ("", "none"):
            return TunnelStatus(
                active=False,
                tunnel_type="none",
                detail="No tunnel configured",
                coverage="none",
                available=False,
            )

        if t == "android_vpn":
            return TunnelStatus(
                active=False,
                tunnel_type=t,
                detail=(
                    "Android device-wide protection requires a companion app "
                    "holding VpnService permission. This CLI cannot obtain that privilege."
                ),
                coverage="none",
                available=False,
            )

        if t in ("openvpn", "wireguard"):
            # Detect if process might be running is out of scope without privileges;
            # report integration boundary.
            return TunnelStatus(
                active=False,
                tunnel_type=t,
                detail=(
                    f"{t} must be started externally. ChainShield can verify egress "
                    "after the tunnel is up, but does not manage the tunnel process."
                ),
                coverage="none",
                available=False,
            )

        return TunnelStatus(
            active=False,
            tunnel_type=t,
            detail=f"Unknown tunnel type: {t}",
            coverage="none",
            available=False,
        )

    def start(self, cfg: Config) -> TunnelStatus:
        st = self.status(cfg)
        if self.events:
            self.events.emit(
                "TUNNEL",
                engine="tunnel_adapter",
                source=EventSource.VPN_ADAPTER.value,
                result="start_not_implemented",
                verification=EventProvenance.UNAVAILABLE.value,
                error=st.detail,
            )
        return st

    def stop(self, cfg: Config) -> TunnelStatus:
        st = self.status(cfg)
        if self.events:
            self.events.emit(
                "TUNNEL",
                engine="tunnel_adapter",
                source=EventSource.VPN_ADAPTER.value,
                result="stop_noop",
                verification=EventProvenance.UNAVAILABLE.value,
            )
        return st
