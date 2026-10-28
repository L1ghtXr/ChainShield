"""IP parsing and verification helpers (mocked network where needed)."""

from __future__ import annotations

from chainshield.verification import _parse_ip


def test_parse_plain_ip():
    assert _parse_ip("203.0.113.25") == "203.0.113.25"


def test_parse_json_ip():
    assert _parse_ip('{"ip": "198.51.100.10"}') == "198.51.100.10"


def test_parse_client_ip_json():
    assert _parse_ip('{"client_ip": "192.0.2.1"}') == "192.0.2.1"


def test_parse_garbage():
    assert _parse_ip("not an address at all") is None


def test_parse_with_whitespace():
    assert _parse_ip("  8.8.8.8\n") == "8.8.8.8"
