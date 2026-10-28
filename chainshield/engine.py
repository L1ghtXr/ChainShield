"""Application core: lifecycle, state, dispatch helpers."""

from __future__ import annotations

import signal
from typing import Optional

from chainshield.capabilities import CapabilityRegistry
from chainshield.config import Config, default_config_path, load_config, save_config
from chainshield.diagnostics import dns_diagnostic, run_self_tests
from chainshield.events import EventBus, EventProvenance, EventSource
from chainshield.monitor import TrafficMonitor
from chainshield.platform import PlatformInfo, detect_platform
from chainshield.proxy import health_check_chain
from chainshield.routing import EngineSelector, run_protected
from chainshield.state import AppState, ProtectionState
from chainshield.tunnel import TunnelAdapter
from chainshield.verification import verify_public_ip, verify_remote_endpoint


class ChainShieldApp:
    def __init__(self, config_path: Optional[str] = None):
        self.platform: PlatformInfo = detect_platform()
        self.platform.ensure_dirs()
        path = None
        if config_path:
            from pathlib import Path

            path = Path(config_path)
        self.config: Config = load_config(path, self.platform)
        self.state = AppState()
        self.events = EventBus(
            max_size=self.config.event_buffer_size,
            log_file=self.config.log_file,
            redact=self.config.redact_secrets,
        )
        self.registry = CapabilityRegistry(self.platform)
        self.registry.refresh()
        self.tunnel = TunnelAdapter(self.platform, self.events)
        self.selector = EngineSelector(
            self.platform, self.registry, self.events, self.tunnel
        )
        self.monitor = TrafficMonitor(self.events)
        self._install_signals()

    def _install_signals(self) -> None:
        def _handler(signum, frame):
            self.events.emit(
                "SIGNAL",
                source=EventSource.CLI.value,
                result=f"signal={signum}",
                verification=EventProvenance.OBSERVED.value,
            )
            # Allow KeyboardInterrupt to propagate for CLI

        try:
            signal.signal(signal.SIGTERM, _handler)
        except Exception:
            pass

    def reload_config(self, path: Optional[str] = None) -> list[str]:
        from pathlib import Path

        p = Path(path) if path else default_config_path(self.platform)
        self.config = load_config(p, self.platform)
        errors = self.config.validate()
        self.events = EventBus(
            max_size=self.config.event_buffer_size,
            log_file=self.config.log_file,
            redact=self.config.redact_secrets,
        )
        self.monitor = TrafficMonitor(self.events)
        return errors

    def start(self) -> str:
        """
        Initialize protection components. Does not claim device-wide protection.
        """
        self.state.protection = ProtectionState.INITIALIZING
        self.events.emit(
            "START",
            engine="core",
            source=EventSource.ENGINE.value,
            result="initializing",
            verification=EventProvenance.OBSERVED.value,
        )

        tunnel_st = self.tunnel.start(self.config)
        proxy_ok = False
        if self.config.proxies:
            health = health_check_chain(self.config, self.events)
            proxy_ok = all(h.get("reachable") for h in health)
            self.state.proxy_healthy = proxy_ok
            if not proxy_ok and self.config.chain_policy in ("strict", "fail_closed"):
                self.state.set_error("One or more proxy hops unreachable")
                return (
                    f"ERROR: proxy health failed under {self.config.chain_policy} policy"
                )
        else:
            self.state.proxy_healthy = False

        self.state.tunnel_active = tunnel_st.active
        self.state.coverage = (
            tunnel_st.coverage
            if tunnel_st.active
            else ("application" if proxy_ok else "none")
        )
        self.state.active_engine = (
            "system_tunnel"
            if tunnel_st.active
            else ("proxy_chain" if proxy_ok else "none")
        )
        self.state.active_route = (
            [self.config.tunnel_type]
            if tunnel_st.active
            else [h.redacted() for h in self.config.proxies]
        )

        # Optional egress verify
        if proxy_ok and self.config.require_verification:
            vr = verify_public_ip(self.config, use_proxy=True, events=self.events)
            self.state.verification_status = vr.status
            self.state.verified_egress_ip = vr.public_ip
            egress_ok = vr.status == "VERIFIED"
        else:
            egress_ok = False
            self.state.verification_status = "NOT VERIFIED"

        self.state.protection = self.state.compute_state(
            policy_requires_verification=self.config.require_verification,
            has_working_proxy=proxy_ok,
            has_working_tunnel=tunnel_st.active,
            egress_verified=egress_ok,
            coverage_level=self.state.coverage,
        )
        self.events.emit(
            "START",
            engine=self.state.active_engine or "none",
            route=self.state.active_route,
            source=EventSource.ENGINE.value,
            result=self.state.protection.value,
            verification=EventProvenance.OBSERVED.value,
        )
        return (
            f"State: {self.state.protection.value}\n"
            f"Engine: {self.state.active_engine}\n"
            f"Coverage: {self.state.coverage}\n"
            f"Route: {' -> '.join(self.state.active_route) if self.state.active_route else 'none'}\n"
            f"Verification: {self.state.verification_status}"
            + (
                f" ({self.state.verified_egress_ip})"
                if self.state.verified_egress_ip
                else ""
            )
        )

    def stop(self) -> str:
        for pid in list(self.state.managed_pids):
            try:
                os_kill = __import__("os").kill
                os_kill(pid, signal.SIGTERM)
            except Exception:
                pass
        self.state.managed_pids.clear()
        self.tunnel.stop(self.config)
        self.state.reset_to_inactive()
        self.events.emit(
            "STOP",
            source=EventSource.ENGINE.value,
            result="inactive",
            verification=EventProvenance.OBSERVED.value,
        )
        return "Protection stopped. State: INACTIVE"

    def status_text(self) -> str:
        lines = [
            f"Protection: {self.state.protection.value}",
            f"Engine: {self.state.active_engine or 'none'}",
            f"Coverage: {self.state.coverage}",
            f"Route: {' -> '.join(self.state.active_route) if self.state.active_route else 'none'}",
            f"Proxy healthy: {self.state.proxy_healthy}",
            f"Tunnel active: {self.state.tunnel_active}",
            f"Verification: {self.state.verification_status}",
        ]
        if self.state.verified_egress_ip:
            lines.append(f"Egress IP: {self.state.verified_egress_ip}")
        if self.state.last_error:
            lines.append(f"Last error: {self.state.last_error}")
        lines.append(f"Platform: {self.platform.system}" + ("/Termux" if self.platform.is_termux else ""))
        if self.platform.limitations:
            lines.append("Limitations:")
            for lim in self.platform.limitations[:5]:
                lines.append(f"  - {lim}")
        return "\n".join(lines)

    def proxy_list(self) -> str:
        if not self.config.proxies:
            return "No proxies configured."
        lines = []
        for i, h in enumerate(self.config.proxies, 1):
            lines.append(f"{i}. {h.redacted()}")
        lines.append(f"Policy: {self.config.chain_policy}")
        return "\n".join(lines)

    def proxy_test(self) -> str:
        if not self.config.proxies:
            return "No proxies configured."
        results = health_check_chain(self.config, self.events)
        lines = []
        for r in results:
            status = "reachable" if r["reachable"] else f"unreachable ({r.get('error', '')})"
            lines.append(f"{r['hop']}: {status}")
        return "\n".join(lines)

    def verify_ip(self, use_proxy: bool = True) -> str:
        vr = verify_public_ip(self.config, use_proxy=use_proxy, events=self.events)
        if vr.status == "VERIFIED":
            self.state.verified_egress_ip = vr.public_ip
            self.state.verification_status = "VERIFIED"
        else:
            self.state.verification_status = vr.status
        lines = [
            f"Public IP: {vr.public_ip or 'n/a'}",
            f"Source: {vr.source_endpoint or 'n/a'}",
            f"Route: {vr.route_description}",
            f"Status: {vr.status}",
            f"Hop count: {getattr(vr, 'hop_count', 0)}",
            f"Chain enforced: {getattr(vr, 'chain_enforced', False)}",
            f"Protection level: {getattr(vr, 'protection_level', 'none')}",
        ]
        if vr.error:
            lines.append(f"Error: {vr.error}")
        lines.append(
            "Note: Observed egress IP for this verification request only. "
            "Not proof that every process or protocol uses the same path. "
            "Level A = application proxying; Level B/C host/device enforcement is not active."
        )
        return "\n".join(lines)

    def diagnostics(self) -> str:
        dns = dns_diagnostic(self.config, self.platform, self.events)
        remote = verify_remote_endpoint(
            self.config,
            use_proxy=bool(self.config.proxies),
            events=self.events,
        )
        caps = run_self_tests(self.registry, self.events)
        lines = ["=== DNS ==="]
        lines.append(f"Resolvers: {', '.join(dns.configured_resolvers) or 'none found'}")
        lines.append(f"Classification: {dns.classification}")
        lines.append(dns.detail)
        for n in dns.observed_notes:
            lines.append(f"  - {n}")
        lines.append("")
        lines.append("=== Remote endpoint ===")
        if remote.status == "UNAVAILABLE" and not self.config.remote_test_endpoint:
            lines.append("Not configured (set verification.remote_test_endpoint)")
        else:
            lines.append(f"Target: {remote.source_endpoint or 'n/a'}")
            lines.append(f"Reported IP: {remote.public_ip or 'n/a'}")
            lines.append(f"Route: {remote.route_description}")
            lines.append(f"Result: {remote.status}")
            if remote.error:
                lines.append(f"Error: {remote.error}")
        lines.append("")
        lines.append("=== Capabilities ===")
        for c in caps:
            lines.append(f"  {c['id']}: {c['status']}" + (f" — {c['detail']}" if c["detail"] else ""))
        lines.append("")
        lines.append("=== Platform limitations ===")
        for lim in self.platform.limitations:
            lines.append(f"  - {lim}")
        return "\n".join(lines)

    def save_config(self) -> None:
        save_config(self.config, default_config_path(self.platform))
