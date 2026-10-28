"""Platform detection and Termux/Linux differences."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PlatformInfo:
    system: str
    release: str
    machine: str
    is_termux: bool
    is_android: bool
    is_linux: bool
    is_root: bool
    termux_prefix: Optional[str] = None
    home: Path = field(default_factory=lambda: Path.home())
    config_dir: Path = field(default_factory=lambda: Path.home() / ".config" / "chainshield")
    data_dir: Path = field(default_factory=lambda: Path.home() / ".local" / "share" / "chainshield")
    has_ld_preload: bool = False
    has_iptables: bool = False
    has_ip_route: bool = False
    has_curl: bool = False
    has_python_ssl: bool = True
    limitations: list[str] = field(default_factory=list)

    def ensure_dirs(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.config_dir, 0o700)
        except OSError:
            pass


def detect_platform() -> PlatformInfo:
    system = platform.system()
    release = platform.release()
    machine = platform.machine()
    is_linux = system == "Linux"
    is_android = False
    is_termux = False
    termux_prefix = os.environ.get("PREFIX")
    limitations: list[str] = []

    # Termux detection
    if os.environ.get("TERMUX_VERSION") or (
        termux_prefix and Path(termux_prefix).exists() and "com.termux" in str(Path.home())
    ):
        is_termux = True
        is_android = True
    elif Path("/system/bin/app_process").exists() or Path("/system/build.prop").exists():
        is_android = True

    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False

    info = PlatformInfo(
        system=system,
        release=release,
        machine=machine,
        is_termux=is_termux,
        is_android=is_android,
        is_linux=is_linux,
        is_root=is_root,
        termux_prefix=termux_prefix,
        has_ld_preload=is_linux and not is_termux and not is_android,
        has_iptables=bool(shutil.which("iptables") or shutil.which("iptables-nft")),
        has_ip_route=bool(shutil.which("ip")),
        has_curl=bool(shutil.which("curl")),
    )

    if is_termux:
        info.config_dir = Path.home() / ".config" / "chainshield"
        info.data_dir = Path.home() / ".chainshield"
        info.limitations.extend(
            [
                "No device-wide VpnService without a companion Android app",
                "No LD_PRELOAD interception of arbitrary processes (typical Termux limitation)",
                "No root firewall modification by default",
                "Application-level proxy env and explicit SOCKS/HTTP routing only",
            ]
        )
    elif is_linux and not is_root:
        info.limitations.append("Firewall/route changes require root or explicit authorization")
    if not info.has_ld_preload:
        info.limitations.append("LD_PRELOAD-based transparent proxy interception unavailable")

    return info


def safe_which(name: str) -> Optional[str]:
    return shutil.which(name)


def run_cmd(
    args: list[str],
    *,
    timeout: float = 15.0,
    env: Optional[dict] = None,
    check: bool = False,
) -> subprocess.CompletedProcess:
    """Safe subprocess without shell interpolation."""
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=check,
    )
