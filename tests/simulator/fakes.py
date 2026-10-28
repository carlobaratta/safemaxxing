"""Deterministic stand-ins for the clock and the two network sources.

Correlation is driven entirely by the timestamps carried on events and connections, so with a
controllable clock and scripted sources a whole call can be replayed and asserted to the
millisecond, in microseconds of real time. These mimic only the surface the replay driver
uses: the real `NetworkMonitor`/`PktapCapture` add polling, DNS and subprocess plumbing that
the simulator deliberately leaves out.
"""

from __future__ import annotations

from safemaxxing.models import NetworkConnection, PktapEvent


class FakeMonotonicClock:
    """A clock that only moves when the test moves it; passed to `CorrelationEngine` as `clock`."""

    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def set(self, now: float) -> None:
        self._now = now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class FakeSocketPoller:
    """Delivers scripted sockets once their `first_seen` has passed, as the real poller first
    sees a socket on the poll after it opened. Each connection is returned at most once."""

    def __init__(self, connections: list[NetworkConnection]) -> None:
        self._pending = sorted(connections, key=lambda c: c.first_seen)

    def poll(self, now: float) -> list[NetworkConnection]:
        """The connections whose `first_seen` is at or before `now` and not yet delivered."""
        due = [c for c in self._pending if c.first_seen <= now]
        self._pending = self._pending[len(due) :]
        return due


class FakePktapStream:
    """Delivers scripted pktap packets in timestamp order up to `now`, each at most once."""

    def __init__(self, packets: list[PktapEvent]) -> None:
        self._pending = sorted(packets, key=lambda p: p.timestamp)

    def drain(self, now: float) -> list[PktapEvent]:
        """The packets whose timestamp is at or before `now` and not yet delivered."""
        due = [p for p in self._pending if p.timestamp <= now]
        self._pending = self._pending[len(due) :]
        return due
