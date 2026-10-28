"""Engine selector and protected command execution."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from chainshield.capabilities import CapabilityRegistry
from chainshield.config import Config
from chainshield.events import EventBus, EventProvenance, EventSource
from chainshield.platform import PlatformInfo
from chainshield.apps import AppSupport, classify_binary, requires_strict_reject
from chainshield.forwarder import LocalChainForwarder
from chainshield.proxy import build_proxy_env, health_check_chain
from chainshield.state import AppState, ProtectionState
from chainshield.tunnel import TunnelAdapter


@dataclass
class RoutePlan:
    engine: str
    route: list[str]
    coverage: str
    unsupported: list[str] = field(default_factory=list)
    verification_status: str = "NOT VERIFIED"
    env: dict[str, str] = field(default_factory=dict)
    ok: bool = False
    reason: str = ""


# Commands known to commonly respect HTTP(S)_PROXY / ALL_PROXY
PROXY_AWARE_HINTS = {
    "curl",
    "wget",
    "httpie",
    "http",
    "aria2c",
    "git",
    "pip",
    "pip3",
    "npm",
    "yarn",
    "cargo",
    "go",
    "python",
    "python3",
    "ruby",
    "php",
}


class EngineSelector:
    def __init__(
        self,
        platform: PlatformInfo,
        registry: CapabilityRegistry,
        events: EventBus,
        tunnel: TunnelAdapter,
    ):
        self.platform = platform
        self.registry = registry
        self.events = events
        self.tunnel = tunnel

    def select(
        self,
        cfg: Config,
        command: Optional[list[str]] = None,
        *,
        require_protection: bool = True,
    ) -> RoutePlan:
        unsupported: list[str] = []
        tunnel_st = self.tunnel.status(cfg)

        if tunnel_st.active and tunnel_st.coverage == "device":
            return RoutePlan(
                engine="system_tunnel",
                route=[cfg.tunnel_type],
                coverage="device",
                ok=True,
                verification_status="NOT VERIFIED",
                reason="External tunnel reported active",
            )

        if not cfg.proxies:
            if require_protection:
                return RoutePlan(
                    engine="none",
                    route=[],
                    coverage="none",
                    ok=False,
                    reason="No proxies configured and no active tunnel; cannot provide protection",
                    unsupported=["No protection path available"],
                )
            return RoutePlan(
                engine="direct",
                route=["direct"],
                coverage="none",
                ok=True,
                reason="Direct (no protection requested)",
            )

        # Validate hops
        for hop in cfg.proxies:
            errs = hop.validate()
            if errs:
                return RoutePlan(
                    engine="proxy_chain",
                    route=[],
                    coverage="none",
                    ok=False,
                    reason="; ".join(errs),
                )

        route = [h.redacted() for h in cfg.proxies]
        # Placeholder env; run_protected replaces with local forwarder when starting.
        env = build_proxy_env(cfg.proxies)

        if command:
            binary = os.path.basename(command[0])
            profile = classify_binary(binary)
            if profile.support != AppSupport.PROXY_ENV and require_protection:
                unsupported.append(
                    f"Command '{binary}': {profile.notes or profile.support.value}. "
                    "Traffic may bypass the local forwarder."
                )
            if requires_strict_reject(binary):
                unsupported.append(
                    f"'{binary}' is classified unsupported for TCP proxy-chain protection "
                    f"(protocols: {', '.join(profile.protocols)})"
                )
                if cfg.chain_policy in ("strict", "fail_closed") and require_protection:
                    return RoutePlan(
                        engine="proxy_chain",
                        route=route,
                        coverage="none",
                        ok=False,
                        unsupported=unsupported,
                        reason=f"Unsupported application for protected routing: {binary}",
                    )
            if "UDP" in profile.protocols and profile.support != AppSupport.PROXY_ENV:
                unsupported.append(
                    "UDP paths are not provided by the TCP local forwarder; "
                    "single-hop SOCKS5 UDP ASSOCIATE is available only via native APIs"
                )

        engine = "local_chain_forwarder" if command else "proxy_chain"
        reason = (
            "Application-level routing via localhost SOCKS5 forwarder "
            f"through {len(cfg.proxies)} configured hop(s)"
            if command
            else "Proxy chain available for native CONNECT paths"
        )
        return RoutePlan(
            engine=engine,
            route=route,
            coverage="application",
            env=env,
            ok=True,
            unsupported=unsupported,
            verification_status="NOT VERIFIED",
            reason=reason,
        )


def run_protected(
    command: list[str],
    cfg: Config,
    state: AppState,
    selector: EngineSelector,
    events: EventBus,
) -> int:
    """
    Run a command under the selected protection path.
    Fail closed when policy requires protection and route is invalid.
    """
    if not command:
        print("No command specified")
        return 2

    plan = selector.select(cfg, command, require_protection=True)
    if not plan.ok:
        print(f"Refusing to run unprotected: {plan.reason}")
        for u in plan.unsupported:
            print(f"  - {u}")
        events.emit(
            "RUN",
            application=command[0],
            engine=plan.engine,
            source=EventSource.ENGINE.value,
            result="rejected",
            verification=EventProvenance.OBSERVED.value,
            error=plan.reason,
        )
        return 1

    for u in plan.unsupported:
        print(f"Warning: {u}")

    # Health-check hops before launch when proxies present
    if cfg.proxies:
        health = health_check_chain(cfg, events)
        failed = [h for h in health if not h.get("reachable")]
        if failed and cfg.chain_policy in ("strict", "fail_closed"):
            print("Proxy health check failed (fail-closed):")
            for h in failed:
                print(f"  {h['hop']}: {h.get('error', 'unreachable')}")
            state.protection = ProtectionState.ERROR
            state.last_error = "proxy health check failed"
            return 1
        state.proxy_healthy = all(h.get("reachable") for h in health)

    forwarder = None
    env = os.environ.copy()
    # Remove variables that can force direct connections despite ALL_PROXY.
    for bypass_key in (
        "NO_PROXY",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "SOCKS_PROXY",
        "socks_proxy",
        "FTP_PROXY",
        "ftp_proxy",
    ):
        env.pop(bypass_key, None)
    if cfg.proxies:
        try:
            forwarder = LocalChainForwarder(cfg.proxies, cfg, events)
            host, port = forwarder.start()
            env.update(forwarder.proxy_env())
            # Ensure empty NO_PROXY remains set (some clients treat missing vs empty differently)
            env["NO_PROXY"] = ""
            env["no_proxy"] = ""
            plan.env = {k: v for k, v in forwarder.proxy_env().items()}
            plan.engine = "local_chain_forwarder"
            print(f"Local chain forwarder: socks5://{host}:{port} ({len(cfg.proxies)} hop(s))")
            print("Protection level: A (application proxying via local forwarder)")
        except OSError as e:
            print(f"Failed to start local chain forwarder: {e}")
            state.protection = ProtectionState.ERROR
            state.last_error = str(e)
            return 1
    else:
        env.update(plan.env)

    events.emit(
        "RUN",
        application=command[0],
        engine=plan.engine,
        route=plan.route,
        source=EventSource.ENGINE.value,
        result="start",
        verification=EventProvenance.OBSERVED.value,
        details={"coverage": plan.coverage},
    )

    state.active_engine = plan.engine
    state.active_route = plan.route
    state.coverage = plan.coverage
    state.protection = state.compute_state(
        policy_requires_verification=cfg.require_verification,
        has_working_proxy=bool(cfg.proxies) and state.proxy_healthy,
        has_working_tunnel=False,
        egress_verified=False,
        coverage_level=plan.coverage,
    )

    # Resolve binary
    binary = command[0]
    if not os.path.isabs(binary):
        found = shutil.which(binary)
        if not found:
            print(f"Command not found: {binary}")
            if forwarder is not None:
                try:
                    forwarder.stop()
                except Exception:
                    pass
            return 127
        command = [found] + command[1:]

    binary_name = os.path.basename(command[0])
    proxy_aware = binary_name in PROXY_AWARE_HINTS

    try:
        # start_new_session allows signaling the process group on interrupt
        proc = subprocess.Popen(
            command,
            env=env,
            stdin=None,
            stdout=None,
            stderr=None,
            start_new_session=True,
        )
        state.managed_pids.append(proc.pid)
        try:
            rc = proc.wait()
        except KeyboardInterrupt:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError, AttributeError):
                try:
                    proc.send_signal(signal.SIGTERM)
                except OSError:
                    pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError, AttributeError):
                    try:
                        proc.kill()
                    except OSError:
                        pass
            rc = 130
        finally:
            if proc.pid in state.managed_pids:
                state.managed_pids.remove(proc.pid)
            if forwarder is not None:
                try:
                    forwarder.stop()
                except Exception:
                    pass

        events.emit(
            "RUN",
            application=command[0],
            engine=plan.engine,
            route=plan.route,
            source=EventSource.ENGINE.value,
            result=f"exit={rc}",
            verification=EventProvenance.OBSERVED.value,
            details={
                "coverage": plan.coverage,
                "proxy_aware_hint": proxy_aware,
            },
        )
        print(f"Exit code: {rc}")
        print(f"Coverage: {plan.coverage} via {plan.engine}")
        print(f"Route: {' -> '.join(plan.route) if plan.route else 'none'}")
        if proxy_aware:
            print(
                "Proxy-aware hint: yes — application is known to commonly "
                "honor HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/SOCKS_PROXY."
            )
        else:
            print(
                "Proxy-aware hint: no — binary is not on the known list. "
                "Environment variables were set, but ChainShield cannot guarantee "
                "this process used the proxy path (no system-wide interception)."
            )
        if plan.unsupported:
            print("Limitations:")
            for u in plan.unsupported:
                print(f"  - {u}")
        return rc
    except OSError as e:
        print(f"Failed to execute: {e}")
        if forwarder is not None:
            try:
                forwarder.stop()
            except Exception:
                pass
        return 1
