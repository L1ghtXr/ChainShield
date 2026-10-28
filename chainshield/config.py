"""Configuration loading, validation, and persistence."""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # Python 3.10
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError as e:
        raise ModuleNotFoundError(
            "ChainShield on Python < 3.11 requires the 'tomli' package. "
            "Install with: pip install 'tomli>=2.0.0'"
        ) from e

# Minimal TOML writer (stdlib has no dump in 3.11+)
def _toml_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _write_toml(data: dict, path: Path) -> None:
    lines: list[str] = []

    def emit(key: str, value: Any, prefix: str = "") -> None:
        full = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            lines.append(f"\n[{full}]")
            for k, v in value.items():
                emit(k, v, full)
        elif isinstance(value, list):
            if all(isinstance(x, dict) for x in value):
                for item in value:
                    lines.append(f"\n[[{full}]]")
                    for k, v in item.items():
                        if isinstance(v, str):
                            lines.append(f'{k} = "{_toml_escape(v)}"')
                        elif isinstance(v, bool):
                            lines.append(f"{k} = {'true' if v else 'false'}")
                        elif isinstance(v, (int, float)):
                            lines.append(f"{k} = {v}")
                        elif v is None:
                            lines.append(f'{k} = ""')
                        else:
                            lines.append(f'{k} = "{_toml_escape(str(v))}"')
            else:
                items = ", ".join(
                    f'"{_toml_escape(str(x))}"' if isinstance(x, str) else str(x).lower()
                    if isinstance(x, bool)
                    else str(x)
                    for x in value
                )
                lines.append(f"{key} = [{items}]")
        elif isinstance(value, str):
            lines.append(f'{key} = "{_toml_escape(value)}"')
        elif isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, (int, float)):
            lines.append(f"{key} = {value}")
        elif value is None:
            lines.append(f'{key} = ""')

    for k, v in data.items():
        if isinstance(v, dict):
            lines.append(f"\n[{k}]")
            for sk, sv in v.items():
                if isinstance(sv, dict):
                    lines.append(f"\n[{k}.{sk}]")
                    for ssk, ssv in sv.items():
                        emit(ssk, ssv)
                elif isinstance(sv, list) and sv and isinstance(sv[0], dict):
                    for item in sv:
                        lines.append(f"\n[[{k}.{sk}]]")
                        for ik, iv in item.items():
                            if isinstance(iv, str):
                                lines.append(f'{ik} = "{_toml_escape(iv)}"')
                            elif isinstance(iv, bool):
                                lines.append(f"{ik} = {'true' if iv else 'false'}")
                            elif isinstance(iv, (int, float)):
                                lines.append(f"{ik} = {iv}")
                            else:
                                lines.append(f'{ik} = "{_toml_escape(str(iv))}"')
                else:
                    emit(sk, sv)
        else:
            emit(k, v)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).lstrip() + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


@dataclass
class ProxyHop:
    type: str  # socks5 | socks4 | http
    host: str
    port: int
    username: str = ""
    password: str = ""

    def redacted(self) -> str:
        auth = f"{self.username}:***@" if self.username else ""
        return f"{self.type}://{auth}{self.host}:{self.port}"

    def validate(self) -> list[str]:
        errors = []
        if self.type not in ("socks5", "socks4", "http"):
            errors.append(f"Unsupported proxy type: {self.type}")
        if not self.host or not re.match(r"^[\w.\-\[\]:]+$", self.host):
            errors.append(f"Invalid proxy host: {self.host!r}")
        if not (1 <= self.port <= 65535):
            errors.append(f"Invalid proxy port: {self.port}")
        return errors


@dataclass
class Config:
    # Protection policy
    chain_policy: str = "strict"  # strict | fail_closed | manual
    require_verification: bool = True
    coverage_claim: str = "application"  # never claim device without tunnel proof

    # Proxy chain
    proxies: list[ProxyHop] = field(default_factory=list)
    connect_timeout: float = 10.0
    handshake_timeout: float = 15.0
    health_check_timeout: float = 8.0

    # Verification
    ip_echo_endpoints: list[str] = field(
        default_factory=lambda: [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
        ]
    )
    remote_test_endpoint: str = ""  # user-owned JSON endpoint returning client_ip
    dns_test_enabled: bool = True

    # Monitor
    event_buffer_size: int = 500
    log_file: str = ""
    redact_secrets: bool = True

    # Tunnel (integration boundary only)
    tunnel_type: str = "none"  # none | openvpn | wireguard | android_vpn
    tunnel_config_path: str = ""

    # UI
    color: bool = True
    narrow_width: int = 60

    def validate(self) -> list[str]:
        errors = []
        if self.chain_policy not in ("strict", "fail_closed", "manual"):
            errors.append(f"Invalid chain_policy: {self.chain_policy}")
        for i, hop in enumerate(self.proxies):
            for e in hop.validate():
                errors.append(f"proxy[{i}]: {e}")
        if self.connect_timeout <= 0 or self.handshake_timeout <= 0:
            errors.append("Timeouts must be positive")
        return errors

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        proxies_raw = data.get("proxies") or data.get("proxy", {}).get("chain") or []
        proxies = []
        for p in proxies_raw:
            if isinstance(p, dict):
                proxies.append(
                    ProxyHop(
                        type=str(p.get("type", "socks5")).lower(),
                        host=str(p.get("host", "")),
                        port=int(p.get("port", 0)),
                        username=str(p.get("username", "") or ""),
                        password=str(p.get("password", "") or ""),
                    )
                )
        general = data.get("general", {})
        proxy_sec = data.get("proxy", {})
        verify = data.get("verification", {})
        monitor = data.get("monitor", {})
        tunnel = data.get("tunnel", {})
        ui = data.get("ui", {})

        return cls(
            chain_policy=str(proxy_sec.get("chain_policy", general.get("chain_policy", "strict"))),
            require_verification=bool(
                general.get("require_verification", True)
            ),
            coverage_claim=str(general.get("coverage_claim", "application")),
            proxies=proxies,
            connect_timeout=float(proxy_sec.get("connect_timeout", 10.0)),
            handshake_timeout=float(proxy_sec.get("handshake_timeout", 15.0)),
            health_check_timeout=float(proxy_sec.get("health_check_timeout", 8.0)),
            ip_echo_endpoints=list(
                verify.get(
                    "ip_echo_endpoints",
                    [
                        "https://api.ipify.org",
                        "https://ifconfig.me/ip",
                        "https://icanhazip.com",
                    ],
                )
            ),
            remote_test_endpoint=str(verify.get("remote_test_endpoint", "")),
            dns_test_enabled=bool(verify.get("dns_test_enabled", True)),
            event_buffer_size=int(monitor.get("event_buffer_size", 500)),
            log_file=str(monitor.get("log_file", "")),
            redact_secrets=bool(monitor.get("redact_secrets", True)),
            tunnel_type=str(tunnel.get("type", "none")),
            tunnel_config_path=str(tunnel.get("config_path", "")),
            color=bool(ui.get("color", True)),
            narrow_width=int(ui.get("narrow_width", 60)),
        )


def default_config_path(platform_info) -> Path:
    return platform_info.config_dir / "config.toml"


def load_config(path: Optional[Path] = None, platform_info=None) -> Config:
    if path is None:
        if platform_info is None:
            from chainshield.platform import detect_platform

            platform_info = detect_platform()
        path = default_config_path(platform_info)

    if not path.exists():
        return Config()

    raw = path.read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))
    # Support flat or nested
    if "proxy" in data and "chain" in data.get("proxy", {}):
        pass
    elif "proxies" in data:
        data = {"proxy": {"chain": data["proxies"]}, **{k: v for k, v in data.items() if k != "proxies"}}
    cfg = Config.from_dict(data)
    return cfg


def save_config(cfg: Config, path: Path) -> None:
    data = {
        "general": {
            "require_verification": cfg.require_verification,
            "coverage_claim": cfg.coverage_claim,
            "chain_policy": cfg.chain_policy,
        },
        "proxy": {
            "chain_policy": cfg.chain_policy,
            "connect_timeout": cfg.connect_timeout,
            "handshake_timeout": cfg.handshake_timeout,
            "health_check_timeout": cfg.health_check_timeout,
            "chain": [
                {
                    "type": p.type,
                    "host": p.host,
                    "port": p.port,
                    "username": p.username,
                    "password": p.password,
                }
                for p in cfg.proxies
            ],
        },
        "verification": {
            "ip_echo_endpoints": cfg.ip_echo_endpoints,
            "remote_test_endpoint": cfg.remote_test_endpoint,
            "dns_test_enabled": cfg.dns_test_enabled,
        },
        "monitor": {
            "event_buffer_size": cfg.event_buffer_size,
            "log_file": cfg.log_file,
            "redact_secrets": cfg.redact_secrets,
        },
        "tunnel": {
            "type": cfg.tunnel_type,
            "config_path": cfg.tunnel_config_path,
        },
        "ui": {
            "color": cfg.color,
            "narrow_width": cfg.narrow_width,
        },
    }
    _write_toml(data, path)


def example_config_text() -> str:
    return '''# ChainShield example configuration
# Copy to ~/.config/chainshield/config.toml (Linux) or ~/.config/chainshield/config.toml (Termux)

[general]
require_verification = true
coverage_claim = "application"  # application | process | device (device needs real tunnel)
chain_policy = "strict"         # strict | fail_closed | manual

[proxy]
chain_policy = "strict"
connect_timeout = 10.0
handshake_timeout = 15.0
health_check_timeout = 8.0

# Ordered proxy hops. Credentials are stored; never printed in logs when redact_secrets=true.
# [[proxy.chain]]
# type = "socks5"
# host = "127.0.0.1"
# port = 9050
# username = ""
# password = ""

# [[proxy.chain]]
# type = "http"
# host = "proxy.example.com"
# port = 8080
# username = "user"
# password = "secret"

[verification]
ip_echo_endpoints = [
  "https://api.ipify.org",
  "https://ifconfig.me/ip",
  "https://icanhazip.com",
]
# Optional: your own endpoint that returns {"client_ip": "..."}
remote_test_endpoint = ""
dns_test_enabled = true

[monitor]
event_buffer_size = 500
log_file = ""
redact_secrets = true

[tunnel]
# Integration boundary only. ChainShield does not implement Android VpnService.
type = "none"  # none | openvpn | wireguard | android_vpn
config_path = ""

[ui]
color = true
narrow_width = 60
'''
