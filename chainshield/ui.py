"""Terminal UI — purple theme, responsive columns, real status only."""

from __future__ import annotations

import os
import shutil
import sys
from typing import Callable, Optional

from chainshield import __contributor__, __tagline__, __url__, __version__
from chainshield.engine import ChainShieldApp


# ANSI
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
PURPLE = "\033[95m"
PURPLE_BRIGHT = "\033[38;5;141m"
WHITE = "\033[97m"
GRAY = "\033[90m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"


def colors_enabled(force: Optional[bool] = None) -> bool:
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def c(text: str, *codes: str, enable: bool = True) -> str:
    if not enable:
        return text
    return "".join(codes) + text + RESET


LOGO = r"""
   ____ _           _       ____  _     _      _     _
  / ___| |__   __ _(_)_ __ / ___|| |__ (_) ___| | __| |
 | |   | '_ \ / _` | | '_ \\___ \| '_ \| |/ _ \ |/ _` |
 | |___| | | | (_| | | | | |___) | | | | |  __/ | (_| |
  \____|_| |_|\__,_|_|_| |_|____/|_| |_|_|\___|_|\__,_|
"""


def terminal_width() -> int:
    try:
        return shutil.get_terminal_size((80, 24)).columns
    except Exception:
        return 80


def print_logo(enable_color: bool = True) -> None:
    for line in LOGO.strip("\n").splitlines():
        print(c(line, PURPLE_BRIGHT, BOLD, enable=enable_color))
    print(c(f"   {__tagline__}", WHITE, enable=enable_color))
    print(c(f" {__url__}", GRAY, enable=enable_color))
    print()


def print_menu(enable_color: bool = True, narrow: bool = False) -> None:
    top = (
        f"{c('[H]', PURPLE, BOLD, enable=enable_color)} Help   "
        f"{c('[V]', PURPLE, BOLD, enable=enable_color)} Version   "
        f"{c('[S]', PURPLE, BOLD, enable=enable_color)} Settings"
    )
    print(top)
    print()

    if narrow:
        sections = [
            (
                "Protection",
                [
                    ("01", "Start"),
                    ("02", "Stop"),
                    ("03", "Status"),
                ],
            ),
            (
                "Proxy",
                [
                    ("04", "Configure"),
                    ("05", "Proxy Chain"),
                    ("06", "Tunnel"),
                ],
            ),
            (
                "Diagnostics",
                [
                    ("07", "Live Traffic"),
                    ("08", "Verify IP"),
                    ("09", "Run Tests"),
                ],
            ),
        ]
        for title, items in sections:
            print(c(f"[{title}]", PURPLE, BOLD, enable=enable_color))
            for num, label in items:
                print(f"  {c(num, PURPLE, enable=enable_color)} {label}")
            print()
    else:
        headers = [
            c("[Protection]", PURPLE, BOLD, enable=enable_color),
            c("[Proxy]", PURPLE, BOLD, enable=enable_color),
            c("[Diagnostics]", PURPLE, BOLD, enable=enable_color),
        ]
        col_w = max(22, terminal_width() // 3 - 2)
        print(
            f"{headers[0]:<{col_w + 20}}"
            f"{headers[1]:<{col_w + 20}}"
            f"{headers[2]}"
        )
        rows = [
            (("01", "Start"), ("04", "Configure"), ("07", "Live Traffic")),
            (("02", "Stop"), ("05", "Proxy Chain"), ("08", "Verify IP")),
            (("03", "Status"), ("06", "Tunnel"), ("09", "Run Tests")),
        ]
        for row in rows:
            parts = []
            for num, label in row:
                cell = f"  {c(num, PURPLE, enable=enable_color)} {label}"
                parts.append(cell.ljust(col_w + 18))
            print("".join(parts))
        print()

    print(
        c(f"By L1ghtXr | Contribution: {__contributor__}", GRAY, enable=enable_color)
    )
    print()
    host = "termux" if os.environ.get("TERMUX_VERSION") else "linux"
    prompt = f"┌──(chainshield@{host})-[~]\n└─$ "
    print(c(prompt, PURPLE, enable=enable_color), end="")


def prompt_line(enable_color: bool = True) -> str:
    host = "termux" if os.environ.get("TERMUX_VERSION") else "linux"
    p = c(f"┌──(chainshield@{host})-[~]\n└─$ ", PURPLE, enable=enable_color)
    try:
        return input(p).strip()
    except EOFError:
        return "q"


def show_help(enable_color: bool = True) -> None:
    text = """
Commands (CLI):
  chainshield                 Interactive menu
  chainshield --version       Version
  chainshield status          Protection state
  chainshield start           Initialize protection components
  chainshield stop            Stop and reset state
  chainshield proxy list      List configured proxies
  chainshield proxy test      Health-check proxy hops
  chainshield run -- <cmd>    Run command under protection policy
  chainshield monitor         Live event monitor
  chainshield verify-ip       Public egress IP check
  chainshield diagnostics     DNS, remote endpoint, capabilities
  chainshield config          Show config path and summary

Menu keys: 01-09, H, V, S, Q to quit

Notes:
  - PROTECTED is never shown merely because a proxy TCP connect succeeds.
  - Application coverage means proxy-aware child processes only.
  - Device-wide Android protection requires a VpnService companion app.
"""
    print(text.strip())


class InteractiveUI:
    def __init__(self, app: ChainShieldApp):
        self.app = app
        self.enable_color = colors_enabled(app.config.color)

    def run(self) -> int:
        narrow = terminal_width() < self.app.config.narrow_width
        print_logo(self.enable_color)
        print_menu(self.enable_color, narrow=narrow)

        actions: dict[str, Callable[[], None]] = {
            "01": self._start,
            "1": self._start,
            "02": self._stop,
            "2": self._stop,
            "03": self._status,
            "3": self._status,
            "04": self._configure,
            "4": self._configure,
            "05": self._proxy_chain,
            "5": self._proxy_chain,
            "06": self._tunnel,
            "6": self._tunnel,
            "07": self._live,
            "7": self._live,
            "08": self._verify,
            "8": self._verify,
            "09": self._tests,
            "9": self._tests,
            "h": lambda: show_help(self.enable_color),
            "H": lambda: show_help(self.enable_color),
            "v": self._version,
            "V": self._version,
            "s": self._settings,
            "S": self._settings,
        }

        while True:
            try:
                choice = prompt_line(self.enable_color)
            except KeyboardInterrupt:
                print()
                return 0
            if not choice:
                continue
            if choice.lower() in ("q", "quit", "exit"):
                return 0
            handler = actions.get(choice)
            if handler:
                print()
                try:
                    handler()
                except KeyboardInterrupt:
                    print("\nInterrupted.")
                except Exception as e:
                    print(c(f"Error: {e}", RED, enable=self.enable_color))
                print()
            else:
                print(c(f"Unknown option: {choice}", YELLOW, enable=self.enable_color))

    def _start(self) -> None:
        print(self.app.start())

    def _stop(self) -> None:
        print(self.app.stop())

    def _status(self) -> None:
        print(self.app.status_text())

    def _configure(self) -> None:
        from chainshield.config import default_config_path, example_config_text

        path = default_config_path(self.app.platform)
        print(f"Config path: {path}")
        print(f"Exists: {path.exists()}")
        print(self.app.proxy_list())
        print()
        print("Edit the TOML file or place config.example.toml content there.")
        print("Example is installed with the package as config.example.toml")

    def _proxy_chain(self) -> None:
        print(self.app.proxy_list())
        print()
        print(self.app.proxy_test())

    def _tunnel(self) -> None:
        st = self.app.tunnel.status(self.app.config)
        print(f"Type: {st.tunnel_type}")
        print(f"Active: {st.active}")
        print(f"Available: {st.available}")
        print(f"Coverage: {st.coverage}")
        print(f"Detail: {st.detail}")

    def _live(self) -> None:
        self.app.monitor.live_print(duration=60.0)

    def _verify(self) -> None:
        use_proxy = bool(self.app.config.proxies)
        print(self.app.verify_ip(use_proxy=use_proxy))

    def _tests(self) -> None:
        print(self.app.diagnostics())

    def _version(self) -> None:
        print(f"ChainShield {__version__}")
        print(__tagline__)
        print(f"By L1ghtXr | Contribution: {__contributor__}")

    def _settings(self) -> None:
        cfg = self.app.config
        print(f"chain_policy: {cfg.chain_policy}")
        print(f"require_verification: {cfg.require_verification}")
        print(f"coverage_claim: {cfg.coverage_claim}")
        print(f"proxies: {len(cfg.proxies)}")
        print(f"color: {cfg.color}")
        print(f"config dir: {self.app.platform.config_dir}")
