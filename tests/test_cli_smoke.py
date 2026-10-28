"""CLI entry-point and policy smoke tests (no fabricated network success)."""

from __future__ import annotations

from chainshield.cli import main
from chainshield.state import AppState, ProtectionState


def test_cli_version_exit_zero():
    assert main(["--version"]) == 0


def test_cli_status_exit_zero():
    assert main(["status"]) == 0


def test_cli_run_missing_command():
    assert main(["run"]) == 2
    assert main(["run", "--"]) == 2


def test_cli_run_fail_closed_without_proxy():
    assert main(["run", "--", "true"]) == 1


def test_cli_proxy_subcommands():
    assert main(["proxy", "list"]) == 0
    assert main(["proxy", "test"]) == 0


def test_cli_config_and_diagnostics():
    assert main(["config"]) == 0
    assert main(["diagnostics"]) == 0


def test_protected_state_requires_device_coverage():
    st = AppState()
    assert (
        st.compute_state(
            has_working_proxy=True,
            egress_verified=True,
            coverage_level="application",
        )
        == ProtectionState.PARTIALLY_PROTECTED
    )
    assert (
        st.compute_state(
            has_working_tunnel=True,
            egress_verified=True,
            coverage_level="device",
        )
        == ProtectionState.PROTECTED
    )
