"""Traffic monitor — only real adapter events, never synthetic traffic."""

from __future__ import annotations

import time
from typing import Optional

from chainshield.events import EventBus


class TrafficMonitor:
    def __init__(self, events: EventBus):
        self.events = events

    def live_print(self, duration: float = 30.0, poll: float = 0.5) -> None:
        """
        Print new events as they appear for a bounded duration.
        Does not generate fake packet lines.
        """
        seen = set()
        for ev in self.events.recent(1000):
            seen.add(id(ev))
        end = time.monotonic() + duration
        print("Live monitor (events from adapters only). Ctrl+C to stop.")
        print("If no connections are made through ChainShield, no lines will appear.")
        try:
            while time.monotonic() < end:
                for ev in self.events.recent(100):
                    if id(ev) not in seen:
                        seen.add(id(ev))
                        print(ev.format_line())
                time.sleep(poll)
        except KeyboardInterrupt:
            print("\nMonitor stopped.")

    def dump_recent(self, n: int = 30) -> list[str]:
        return [e.format_line() for e in self.events.recent(n)]
