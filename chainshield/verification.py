"""Public IP and remote endpoint verification — real network only."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from chainshield.config import Config, ProxyHop
from chainshield.events import EventBus, EventProvenance, EventSource
from chainshield.proxy import connect_through_chain, ProxyError


@dataclass
class IPVerifyResult:
    status: str  # VERIFIED | NOT VERIFIED | ERROR | PARTIAL | INCONCLUSIVE
    public_ip: Optional[str] = None
    source_endpoint: str = ""
    route_description: str = "direct"
    error: str = ""
    raw_response: str = ""
    hop_count: int = 0
    chain_enforced: bool = False
    protection_level: str = "none"  # none | A | B | C


def _parse_ip(text: str) -> Optional[str]:
    text = text.strip()
    # Plain IP
    try:
        ipaddress.ip_address(text.split()[0])
        return text.split()[0]
    except ValueError:
        pass
    # JSON-ish
    m = re.search(
        r'"(?:ip|client_ip|origin|query)"\s*:\s*"([^"]+)"',
        text,
        re.I,
    )
    if m:
        candidate = m.group(1).strip()
        try:
            ipaddress.ip_address(candidate.split(",")[0].strip())
            return candidate.split(",")[0].strip()
        except ValueError:
            pass
    # First IPv4/IPv6-looking token
    m = re.search(
        r"\b(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+:+[0-9a-fA-F:]+)\b",
        text,
    )
    if m:
        try:
            ipaddress.ip_address(m.group(0))
            return m.group(0)
        except ValueError:
            pass
    return None


def _https_get_direct(url: str, timeout: float = 12.0) -> str:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "ChainShield/0.1"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _https_get_via_proxy_chain(
    url: str,
    hops: list[ProxyHop],
    cfg: Config,
    events: Optional[EventBus] = None,
) -> tuple[str, list[str]]:
    """
    Minimal HTTPS GET through proxy chain using CONNECT then TLS.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ProxyError("Only HTTPS verification endpoints are supported")
    host = parsed.hostname
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    result = connect_through_chain(
        hops,
        host,
        port,
        connect_timeout=cfg.connect_timeout,
        handshake_timeout=cfg.handshake_timeout,
        policy=cfg.chain_policy,
        events=events,
    )
    if not result.success or not result.final_socket:
        raise ProxyError(result.error or "chain failed")

    sock = result.final_socket
    try:
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(sock, server_hostname=host)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: ChainShield/0.1\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        tls.sendall(req.encode())
        data = b""
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        tls.close()
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise

    text = data.decode("utf-8", errors="replace")
    if "\r\n\r\n" in text:
        body = text.split("\r\n\r\n", 1)[1]
    else:
        body = text
    return body, result.route


def verify_public_ip(
    cfg: Config,
    *,
    use_proxy: bool = True,
    events: Optional[EventBus] = None,
) -> IPVerifyResult:
    """
    Request a real IP-echo endpoint. Never invent an IP.
    """
    endpoints = list(cfg.ip_echo_endpoints)
    if not endpoints:
        return IPVerifyResult(status="ERROR", error="No IP echo endpoints configured")

    last_error = ""
    for url in endpoints:
        try:
            if use_proxy and cfg.proxies:
                body, route = _https_get_via_proxy_chain(url, cfg.proxies, cfg, events)
                route_desc = " -> ".join(route) if route else "proxy chain"
            else:
                body = _https_get_direct(url)
                route_desc = "direct"

            ip = _parse_ip(body)
            if not ip:
                last_error = f"Could not parse IP from {url}"
                if events:
                    events.emit(
                        "VERIFY",
                        protocol="HTTPS",
                        destination=url,
                        engine="verification",
                        source=EventSource.REMOTE_VERIFICATION.value,
                        result="parse_failed",
                        verification=EventProvenance.OBSERVED.value,
                        error=last_error,
                    )
                continue

            used_chain = bool(use_proxy and cfg.proxies)
            hop_count = len(cfg.proxies) if used_chain else 0
            # Domain-form CONNECT means destination hostname was not necessarily
            # resolved locally for the final hop; still report honestly.
            status = "VERIFIED"
            if events:
                events.emit(
                    "VERIFY",
                    protocol="HTTPS",
                    destination=url,
                    engine="verification",
                    route=route_desc.split(" -> ") if " -> " in route_desc else [route_desc],
                    source=EventSource.REMOTE_VERIFICATION.value,
                    result=f"ip={ip}",
                    verification=EventProvenance.VERIFIED.value,
                    details={"hop_count": hop_count, "chain_enforced": used_chain},
                )
            return IPVerifyResult(
                status=status,
                public_ip=ip,
                source_endpoint=url,
                route_description=route_desc,
                raw_response=body[:200],
                hop_count=hop_count,
                chain_enforced=used_chain,
                protection_level="A" if used_chain else "none",
            )
        except Exception as e:
            last_error = str(e)
            if events:
                events.emit(
                    "VERIFY",
                    protocol="HTTPS",
                    destination=url,
                    engine="verification",
                    source=EventSource.REMOTE_VERIFICATION.value,
                    result="error",
                    verification=EventProvenance.OBSERVED.value,
                    error=str(e),
                )
            continue

    return IPVerifyResult(
        status="ERROR",
        error=last_error or "All endpoints failed",
        route_description="proxy chain" if (use_proxy and cfg.proxies) else "direct",
        hop_count=len(cfg.proxies) if (use_proxy and cfg.proxies) else 0,
        chain_enforced=False,
        protection_level="A" if (use_proxy and cfg.proxies) else "none",
    )


def verify_remote_endpoint(
    cfg: Config,
    *,
    use_proxy: bool = True,
    events: Optional[EventBus] = None,
) -> IPVerifyResult:
    """
    Optional diagnostic against a user-configured endpoint that returns client_ip.
    """
    url = (cfg.remote_test_endpoint or "").strip()
    if not url:
        return IPVerifyResult(
            status="UNAVAILABLE",
            error="No remote_test_endpoint configured",
        )
    try:
        if use_proxy and cfg.proxies:
            body, route = _https_get_via_proxy_chain(url, cfg.proxies, cfg, events)
            route_desc = " -> ".join(route)
        else:
            body = _https_get_direct(url)
            route_desc = "direct"
        ip = _parse_ip(body)
        if not ip:
            return IPVerifyResult(
                status="UNAVAILABLE",
                source_endpoint=url,
                route_description=route_desc,
                error="Endpoint did not disclose a client IP",
                raw_response=body[:300],
            )
        if events:
            events.emit(
                "VERIFY",
                protocol="HTTPS",
                destination=url,
                engine="verification",
                source=EventSource.REMOTE_VERIFICATION.value,
                result=f"client_ip={ip}",
                verification=EventProvenance.VERIFIED.value,
            )
        return IPVerifyResult(
            status="VERIFIED",
            public_ip=ip,
            source_endpoint=url,
            route_description=route_desc,
            raw_response=body[:300],
        )
    except Exception as e:
        return IPVerifyResult(status="ERROR", error=str(e), source_endpoint=url)
