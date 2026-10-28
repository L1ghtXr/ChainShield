"""Centralized protection state machine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ProtectionState(str, Enum):
    """Global protection state. Never set to PROTECTED from proxy connect alone."""

    INACTIVE = "INACTIVE"
    INITIALIZING = "INITIALIZING"
    PROTECTED = "PROTECTED"
    PARTIALLY_PROTECTED = "PARTIALLY PROTECTED"
    NOT_VERIFIED = "NOT VERIFIED"
    ERROR = "ERROR"


@dataclass
class AppState:
    """Runtime application state."""

    protection: ProtectionState = ProtectionState.INACTIVE
    active_engine: Optional[str] = None
    active_route: list[str] = field(default_factory=list)
    coverage: str = "none"  # none | application | process | device
    last_error: Optional[str] = None
    proxy_healthy: bool = False
    tunnel_active: bool = False
    verified_egress_ip: Optional[str] = None
    verification_status: str = "NOT VERIFIED"
    managed_pids: list[int] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def set_error(self, message: str) -> None:
        self.protection = ProtectionState.ERROR
        self.last_error = message

    def reset_to_inactive(self) -> None:
        self.protection = ProtectionState.INACTIVE
        self.active_engine = None
        self.active_route = []
        self.coverage = "none"
        self.last_error = None
        self.proxy_healthy = False
        self.tunnel_active = False
        self.verified_egress_ip = None
        self.verification_status = "NOT VERIFIED"
        self.managed_pids = []

    def compute_state(
        self,
        *,
        policy_requires_verification: bool = True,
        has_working_proxy: bool = False,
        has_working_tunnel: bool = False,
        egress_verified: bool = False,
        coverage_level: str = "application",
    ) -> ProtectionState:
        """
        Derive protection state from real component health.
        A connected proxy alone never yields PROTECTED.
        """
        if self.last_error and not (has_working_proxy or has_working_tunnel):
            return ProtectionState.ERROR

        if not (has_working_proxy or has_working_tunnel):
            return ProtectionState.INACTIVE

        if coverage_level == "device" and egress_verified and (has_working_tunnel or has_working_proxy):
            return ProtectionState.PROTECTED

        if coverage_level in ("application", "process") and has_working_proxy:
            if egress_verified:
                return ProtectionState.PARTIALLY_PROTECTED
            if policy_requires_verification:
                return ProtectionState.NOT_VERIFIED
            return ProtectionState.PARTIALLY_PROTECTED

        if has_working_proxy or has_working_tunnel:
            return ProtectionState.PARTIALLY_PROTECTED

        return ProtectionState.INACTIVE
