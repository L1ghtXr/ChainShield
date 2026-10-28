"""DNS and general diagnostics — truthful classification only."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from chainshield.config import Config
from chainshield.events import EventBus, EventProvenance, EventSource
from chainshield.platform import PlatformInfo


@dataclass
class DNSReport:
    configured_resolvers: list[str] = field(default_factory=list)
    observed_notes: list[str] = field(default_factory=list)
    classification: str = "INCONCLUSIVE"  # INCONCLUSIVE | NOT VERIFIED | ERROR
    detail: str = ""


def read_resolv_conf() -> list[str]:
    resolvers = []
    paths = [Path("/etc/resolv.conf")]
    # Termux may use different paths
    prefix = os.environ.get("PREFIX")
    if prefix:
        paths.append(Path(prefix) / "etc" / "resolv.conf")
    for p in paths:
        try:
            if p.exists():
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            resolvers.append(parts[1])
        except OSError:
            continue
    return resolvers


def dns_diagnostic(
    cfg: Config,
    platform: PlatformInfo,
    events: Optional[EventBus] = None,
) -> DNSReport:
    """
    Report configured resolvers. Do not claim leak without evidence of bypass.
    """
    resolvers = read_resolv_conf()
    notes = []
    if not resolvers:
        notes.append("Could not read nameserver entries from resolv.conf")
    else:
        notes.append(f"Found {len(resolvers)} nameserver(s) in resolv.conf")

    if platform.is_termux:
        notes.append(
            "Termux DNS path is managed by Android; ChainShield cannot force "
            "DNS through proxy without an app that honors proxy DNS or a VPN service"
        )

    # Attempt a simple getaddrinfo to confirm resolver works at all
    try:
        socket.getaddrinfo("example.com", 80, type=socket.SOCK_STREAM)
        notes.append("system getaddrinfo(example.com) succeeded")
    except socket.gaierror as e:
        notes.append(f"system getaddrinfo failed: {e}")
        report = DNSReport(
            configured_resolvers=resolvers,
            observed_notes=notes,
            classification="ERROR",
            detail=str(e),
        )
        if events:
            events.emit(
                "DNS",
                protocol="DNS",
                engine="diagnostics",
                source=EventSource.DIAGNOSTIC_TEST.value,
                result="error",
                verification=EventProvenance.OBSERVED.value,
                error=str(e),
            )
        return report

    classification = "NOT VERIFIED"
    detail = (
        "Resolvers listed; no controlled experiment proved that DNS queries "
        "traverse the configured protection path. Classification is NOT VERIFIED."
    )
    if events:
        events.emit(
            "DNS",
            protocol="DNS",
            engine="diagnostics",
            source=EventSource.DIAGNOSTIC_TEST.value,
            result=classification,
            verification=EventProvenance.INFERRED.value,
            details={"resolvers": resolvers},
        )

    return DNSReport(
        configured_resolvers=resolvers,
        observed_notes=notes,
        classification=classification,
        detail=detail,
    )


def run_self_tests(registry, events: Optional[EventBus] = None) -> list[dict]:
    """Lightweight capability self-checks (no fabricated network success)."""
    results = []
    for cap in registry.list_all():
        results.append(
            {
                "id": cap.id,
                "status": cap.status.value,
                "detail": cap.detail or "",
            }
        )
    if events:
        events.emit(
            "SELFTEST",
            engine="diagnostics",
            source=EventSource.DIAGNOSTIC_TEST.value,
            result=f"{len(results)} capabilities reported",
            verification=EventProvenance.OBSERVED.value,
        )
    return results
