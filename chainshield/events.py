"""Structured traffic and diagnostic events with provenance."""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Deque, Optional


class EventProvenance(str, Enum):
    OBSERVED = "OBSERVED"
    VERIFIED = "VERIFIED"
    INFERRED = "INFERRED"
    UNAVAILABLE = "UNAVAILABLE"


class EventSource(str, Enum):
    PROXY_ADAPTER = "proxy_adapter"
    VPN_ADAPTER = "vpn_adapter"
    SYSTEM_MONITOR = "system_monitor"
    REMOTE_VERIFICATION = "remote_verification"
    DIAGNOSTIC_TEST = "diagnostic_test"
    ENGINE = "engine"
    CLI = "cli"


@dataclass
class Event:
    timestamp: str
    event_type: str
    protocol: str = ""
    destination: str = ""
    application: str = ""
    engine: str = ""
    route: list[str] = field(default_factory=list)
    source: str = EventSource.ENGINE.value
    result: str = ""
    verification: str = EventProvenance.INFERRED.value
    error: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def format_line(self) -> str:
        ts = self.timestamp[11:19] if len(self.timestamp) >= 19 else self.timestamp
        parts = [f"[{ts}]", self.event_type]
        if self.protocol:
            parts.append(self.protocol)
        if self.destination:
            parts.append(f"-> {self.destination}")
        if self.route:
            parts.append("ROUTE " + " -> ".join(self.route))
        if self.result:
            parts.append(self.result)
        if self.error:
            parts.append(f"ERR {self.error}")
        return " ".join(parts)

    def to_dict(self) -> dict:
        return asdict(self)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class EventBus:
    """Bounded in-memory event buffer with optional file logging and redaction."""

    def __init__(
        self,
        max_size: int = 500,
        log_file: str = "",
        redact: bool = True,
    ):
        self._buffer: Deque[Event] = deque(maxlen=max(1, max_size))
        self._lock = threading.RLock()
        self._listeners: list[Callable[[Event], None]] = []
        self._log_path = Path(log_file) if log_file else None
        self._redact = redact

    def emit(
        self,
        event_type: str,
        *,
        protocol: str = "",
        destination: str = "",
        application: str = "",
        engine: str = "",
        route: Optional[list[str]] = None,
        source: str = EventSource.ENGINE.value,
        result: str = "",
        verification: str = EventProvenance.INFERRED.value,
        error: str = "",
        details: Optional[dict] = None,
    ) -> Event:
        if self._redact and details:
            details = self._redact_dict(details)
        ev = Event(
            timestamp=_now_iso(),
            event_type=event_type,
            protocol=protocol,
            destination=destination,
            application=application,
            engine=engine,
            route=list(route or []),
            source=source,
            result=result,
            verification=verification,
            error=error,
            details=details or {},
        )
        with self._lock:
            self._buffer.append(ev)
            if self._log_path:
                try:
                    with self._log_path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(ev.to_dict()) + "\n")
                except OSError:
                    pass
            for listener in self._listeners:
                try:
                    listener(ev)
                except Exception:
                    pass
        return ev

    def _redact_dict(self, d: dict) -> dict:
        out = {}
        secret_keys = {
            "password",
            "pass",
            "passwd",
            "secret",
            "token",
            "authorization",
            "auth",
            "credential",
            "credentials",
            "api_key",
            "apikey",
            "proxy-authorization",
        }
        for k, v in d.items():
            kl = k.lower()
            if kl in secret_keys or "password" in kl or kl.endswith("_token"):
                out[k] = "***"
            elif isinstance(v, dict):
                out[k] = self._redact_dict(v)
            elif isinstance(v, str):
                out[k] = self._redact_str(v)
            else:
                out[k] = v
        return out

    def _redact_str(self, s: str) -> str:
        """Scrub credentials in URLs and common secret query parameters."""
        import re

        s = re.sub(
            r"(://[^:/?#\s]+):([^@/?#\s]+)@",
            r"\1:***@",
            s,
        )
        s = re.sub(
            r"([?&](?:password|passwd|pass|token|access_token|api_key|apikey|secret|auth)=)([^&#\s]*)",
            r"\1***",
            s,
            flags=re.IGNORECASE,
        )
        return s

    def subscribe(self, callback: Callable[[Event], None]) -> None:
        with self._lock:
            self._listeners.append(callback)

    def recent(self, n: int = 50) -> list[Event]:
        with self._lock:
            items = list(self._buffer)
        return items[-n:]

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()
