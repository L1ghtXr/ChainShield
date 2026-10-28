"""Application capability model — what can be protected and how."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AppSupport(str, Enum):
    PROXY_ENV = "proxy_env"  # honors ALL_PROXY / SOCKS_PROXY / HTTP(S)_PROXY
    EXPLICIT_ARGS = "explicit_args"  # needs CLI flags (not auto-applied)
    FORWARDER_OK = "forwarder_ok"  # works via local SOCKS forwarder if proxy-aware
    PLATFORM_ROUTING = "platform_routing"  # needs VpnService / transparent redirect
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class AppProfile:
    name: str
    support: AppSupport
    protocols: tuple[str, ...]
    notes: str = ""


# Conservative profiles used for honest messaging and strict policy decisions.
PROFILES: dict[str, AppProfile] = {
    "curl": AppProfile("curl", AppSupport.PROXY_ENV, ("TCP", "HTTP", "HTTPS"), "Honors ALL_PROXY/SOCKS_PROXY"),
    "wget": AppProfile("wget", AppSupport.PROXY_ENV, ("TCP", "HTTP", "HTTPS")),
    "git": AppProfile("git", AppSupport.PROXY_ENV, ("TCP", "HTTP", "HTTPS")),
    "httpie": AppProfile("httpie", AppSupport.PROXY_ENV, ("TCP", "HTTP", "HTTPS")),
    "http": AppProfile("http", AppSupport.PROXY_ENV, ("TCP", "HTTP", "HTTPS")),
    "python": AppProfile("python", AppSupport.PROXY_ENV, ("TCP",), "Only if libraries honor proxy env"),
    "python3": AppProfile("python3", AppSupport.PROXY_ENV, ("TCP",), "Only if libraries honor proxy env"),
    "nmap": AppProfile("nmap", AppSupport.UNSUPPORTED, ("TCP", "UDP", "RAW"), "Raw/UDP scanning not covered by SOCKS CONNECT"),
    "masscan": AppProfile("masscan", AppSupport.UNSUPPORTED, ("TCP", "UDP", "RAW")),
    "hping3": AppProfile("hping3", AppSupport.UNSUPPORTED, ("TCP", "UDP", "RAW")),
    "tcpdump": AppProfile("tcpdump", AppSupport.UNSUPPORTED, ("RAW",)),
    "ping": AppProfile("ping", AppSupport.UNSUPPORTED, ("ICMP",), "ICMP not covered by TCP proxy chains"),
    "dig": AppProfile("dig", AppSupport.EXPLICIT_ARGS, ("UDP", "TCP", "DNS"), "Needs +tcp or explicit proxy; UDP DNS may leak"),
    "nslookup": AppProfile("nslookup", AppSupport.UNSUPPORTED, ("UDP", "DNS"), "Typically uses system DNS/UDP"),
}


def classify_binary(name: str) -> AppProfile:
    base = name.lower()
    if base in PROFILES:
        return PROFILES[base]
    return AppProfile(
        name=base,
        support=AppSupport.PROXY_ENV,  # optimistic default with strong warning elsewhere
        protocols=("TCP",),
        notes="Unknown binary: treated as possibly proxy-aware; not guaranteed",
    )


def requires_strict_reject(name: str) -> bool:
    profile = classify_binary(name)
    return profile.support == AppSupport.UNSUPPORTED
