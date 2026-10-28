"""UI layout helpers."""

from __future__ import annotations

from chainshield.ui import colors_enabled, terminal_width


def test_terminal_width_positive():
    assert terminal_width() >= 1


def test_colors_force_off(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert colors_enabled() is False
