"""Command-line interface."""

from __future__ import annotations

import argparse
import sys

from chainshield import __contributor__, __tagline__, __version__
from chainshield.engine import ChainShieldApp
from chainshield.routing import run_protected
from chainshield.ui import InteractiveUI, colors_enabled, print_logo, show_help


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="chainshield",
        description="ChainShield — Layered Network Protection",
    )
    p.add_argument("--version", action="store_true", help="Show version")
    p.add_argument("--config", default=None, help="Path to config.toml")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")

    sub = p.add_subparsers(dest="command")

    sub.add_parser("status", help="Show protection state")
    sub.add_parser("start", help="Initialize protection components")
    sub.add_parser("stop", help="Stop protection")
    sub.add_parser("monitor", help="Live event monitor")
    sub.add_parser("verify-ip", help="Verify public egress IP")
    sub.add_parser("diagnostics", help="Run diagnostics")
    sub.add_parser("config", help="Show configuration summary")
    sub.add_parser("help", help="Show help")

    proxy = sub.add_parser("proxy", help="Proxy management")
    proxy_sub = proxy.add_subparsers(dest="proxy_cmd")
    proxy_sub.add_parser("list", help="List proxies")
    proxy_sub.add_parser("test", help="Test proxy hops")

    run_p = sub.add_parser("run", help="Run command under protection")
    run_p.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Command after -- ",
    )

    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version or (args.command is None and "--version" in (argv or [])):
        print(f"ChainShield {__version__}")
        print(__tagline__)
        print(f"By L1ghtXr | Contribution: {__contributor__}")
        return 0

    app = ChainShieldApp(config_path=args.config)
    if getattr(args, "no_color", False):
        app.config.color = False

    if args.command is None:
        # Interactive
        return InteractiveUI(app).run()

    if args.command == "help":
        show_help(colors_enabled(app.config.color))
        return 0

    if args.command == "status":
        print(app.status_text())
        return 0

    if args.command == "start":
        print(app.start())
        return 0 if app.state.protection.value != "ERROR" else 1

    if args.command == "stop":
        print(app.stop())
        return 0

    if args.command == "monitor":
        app.monitor.live_print(duration=120.0)
        return 0

    if args.command == "verify-ip":
        print(app.verify_ip(use_proxy=bool(app.config.proxies)))
        return 0

    if args.command == "diagnostics":
        print(app.diagnostics())
        return 0

    if args.command == "config":
        from chainshield.config import default_config_path

        path = default_config_path(app.platform)
        print(f"Path: {path}")
        print(f"Exists: {path.exists()}")
        print(f"Policy: {app.config.chain_policy}")
        print(f"Proxies: {len(app.config.proxies)}")
        print(app.proxy_list())
        return 0

    if args.command == "proxy":
        if args.proxy_cmd == "list":
            print(app.proxy_list())
            return 0
        if args.proxy_cmd == "test":
            print(app.proxy_test())
            return 0
        print("Usage: chainshield proxy list|test")
        return 2

    if args.command == "run":
        cmd = list(args.cmd or [])
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            print("Usage: chainshield run -- <command> [args...]")
            return 2
        return run_protected(cmd, app.config, app.state, app.selector, app.events)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
