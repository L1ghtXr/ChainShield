"""State machine and event bus tests."""

from __future__ import annotations

from chainshield.events import EventBus, EventProvenance
from chainshield.state import AppState, ProtectionState


def test_state_proxy_alone_not_protected():
    st = AppState()
    result = st.compute_state(
        has_working_proxy=True,
        has_working_tunnel=False,
        egress_verified=False,
        coverage_level="application",
        policy_requires_verification=True,
    )
    assert result == ProtectionState.NOT_VERIFIED


def test_state_proxy_verified_partial():
    st = AppState()
    result = st.compute_state(
        has_working_proxy=True,
        egress_verified=True,
        coverage_level="application",
        policy_requires_verification=True,
    )
    assert result == ProtectionState.PARTIALLY_PROTECTED


def test_state_device_verified_protected():
    st = AppState()
    result = st.compute_state(
        has_working_tunnel=True,
        egress_verified=True,
        coverage_level="device",
        policy_requires_verification=True,
    )
    assert result == ProtectionState.PROTECTED


def test_state_inactive():
    st = AppState()
    assert st.compute_state() == ProtectionState.INACTIVE


def test_event_redaction():
    bus = EventBus(max_size=10, redact=True)
    bus.emit(
        "TEST",
        details={
            "password": "secret",
            "api_key": "k",
            "access_token": "t",
            "host": "x",
        },
    )
    ev = bus.recent(1)[0]
    assert ev.details["password"] == "***"
    assert ev.details["api_key"] == "***"
    assert ev.details["access_token"] == "***"
    assert ev.details["host"] == "x"


def test_event_buffer_bound():
    bus = EventBus(max_size=5)
    for i in range(20):
        bus.emit("N", result=str(i))
    assert len(bus.recent(100)) == 5


def test_event_provenance_values():
    bus = EventBus()
    bus.emit("X", verification=EventProvenance.OBSERVED.value)
    assert bus.recent(1)[0].verification == "OBSERVED"


def test_verified_egress_ip_default_is_none():
    st = AppState()
    assert st.verified_egress_ip is None
    assert not isinstance(st.verified_egress_ip, bool)


def test_event_redacts_credentials_in_urls():
    bus = EventBus(max_size=10, redact=True)
    bus.emit(
        "TEST",
        details={
            "proxy_url": "socks5://user:s3cret@127.0.0.1:9050",
            "host": "127.0.0.1",
        },
    )
    ev = bus.recent(1)[0]
    assert "s3cret" not in ev.details["proxy_url"]
    assert "***" in ev.details["proxy_url"]
    assert "127.0.0.1" in ev.details["proxy_url"]


def test_event_redacts_secret_query_params():
    bus = EventBus(max_size=10, redact=True)
    bus.emit("TEST", details={"url": "https://ex/a?token=abc&keep=1"})
    ev = bus.recent(1)[0]
    assert "token=***" in ev.details["url"]
    assert "keep=1" in ev.details["url"]
