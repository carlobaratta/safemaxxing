"""Temporal correlation: sensor access (cause) -> outbound connection (effect)."""

from __future__ import annotations

import dataclasses
import itertools
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from safemaxxing.models import (
    Alert,
    Event,
    Finding,
    NetworkConnection,
    SensorType,
    Severity,
    is_system_path,
)

BASE_SEVERITY: dict[SensorType, Severity] = {
    SensorType.CAMERA: Severity.HIGH,
    SensorType.MICROPHONE: Severity.HIGH,
    SensorType.SCREEN_CAPTURE: Severity.HIGH,
    SensorType.LOCATION: Severity.HIGH,
    SensorType.TCC: Severity.MEDIUM,
}


@dataclass(frozen=True, slots=True)
class CorrelationConfig:
    # Measured on macOS 27: Google Meet in Brave opened its media socket 1.1 s after the
    # microphone permission check, so 0.5 s missed it.
    window_s: float = 2.0
    # The socket can be observed slightly before the log line's timestamp (clock/poll jitter).
    clock_skew_s: float = 0.05
    # `log stream` may deliver entries late; keep items long enough to match out-of-order input.
    late_arrival_s: float = 2.0
    alert_cooldown_s: float = 30.0
    buffer_size: int = 2048
    ignore: frozenset[str] = field(default_factory=frozenset)
    # SIP-protected Apple binaries (cloudd, apsd, FaceTime's helpers...) talk to the network
    # constantly; by default their sockets are not treated as possible exfiltration.
    include_system: bool = False
    include_dns: bool = False

    @property
    def retention_s(self) -> float:
        return self.window_s + self.late_arrival_s


# A DNS lookup is the prelude to a connection, not the exfiltration itself.
DNS_PORTS = frozenset({53, 853, 5353})


def _bundle_related(a: str, b: str) -> bool:
    return a == b or a.startswith(b + ".") or b.startswith(a + ".")


def same_actor(event: Event, conn: NetworkConnection) -> bool:
    if event.pid is not None and event.pid == conn.pid:
        return True
    if event.bundle_id and conn.bundle_id and _bundle_related(event.bundle_id, conn.bundle_id):
        return True
    return (
        event.pid is None and bool(event.process_name) and event.process_name == conn.process_name
    )


class CorrelationEngine:
    def __init__(
        self, config: CorrelationConfig | None = None, clock: Callable[[], float] = time.time
    ) -> None:
        self.config = config or CorrelationConfig()
        self._clock = clock
        self._events: deque[Event] = deque(maxlen=self.config.buffer_size)
        self._connections: deque[NetworkConnection] = deque(maxlen=self.config.buffer_size)
        self._seen: set[tuple[object, ...]] = set()
        self._last_alert: dict[tuple[int, SensorType, str], float] = {}
        self._alerted: dict[tuple[object, ...], Alert] = {}
        self._ids = itertools.count(1)
        self._horizon = 0.0

    @property
    def events(self) -> tuple[Event, ...]:
        return tuple(self._events)

    def _ignored(self, *names: str | None) -> bool:
        return any(n in self.config.ignore for n in names if n)

    def _advance(self, ts: float) -> None:
        if ts <= self._horizon:
            return
        self._horizon = ts
        cutoff = ts - self.config.retention_s
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()
        while self._connections and self._connections[0].first_seen < cutoff:
            self._connections.popleft()
        if len(self._seen) > self.config.buffer_size * 8:
            self._seen.clear()
        if len(self._alerted) > 256:
            self._alerted = {
                k: a for k, a in self._alerted.items() if a.finding.connection.first_seen >= cutoff
            }

    def _matches(self, event: Event, conn: NetworkConnection) -> Finding | None:
        delta = conn.first_seen - event.timestamp
        if not -self.config.clock_skew_s <= delta <= self.config.window_s:
            return None
        if not same_actor(event, conn):
            return None
        return Finding(event=event, connection=conn, delta_s=max(delta, 0.0))

    def _sensors_for(self, conn: NetworkConnection) -> frozenset[SensorType]:
        # Same bounds as `_matches`: an event a few ms after the socket (clock skew) counts.
        return frozenset(e.sensor for e in self._events if self._matches(e, conn) is not None)

    @staticmethod
    def _severity(sensors: frozenset[SensorType]) -> Severity:
        severity = max(BASE_SEVERITY[s] for s in sensors)
        if len(sensors) > 1:
            severity = Severity(min(severity + 1, Severity.CRITICAL))
        return severity

    def _emit(self, findings: list[Finding]) -> list[Alert]:
        alerts: list[Alert] = []
        now = self._clock()
        for finding in findings:
            if finding.key in self._seen:
                continue
            self._seen.add(finding.key)
            ev, conn = finding.event, finding.connection
            existing = self._alerted.get(conn.key)
            if existing is not None:
                if ev.sensor in existing.sensors:
                    continue
                sensors = existing.sensors | {ev.sensor}
                alert = dataclasses.replace(
                    existing,
                    sensors=sensors,
                    severity=max(existing.severity, self._severity(sensors)),
                    updated=True,
                )
            else:
                # Keyed on the connection's process: one access yields indicator, TCC and cmio
                # events with different identities (bundle id, pid, name) for the same socket.
                last = self._last_alert.get((conn.pid, ev.sensor, conn.remote_address))
                if last is not None and now - last < self.config.alert_cooldown_s:
                    continue
                sensors = self._sensors_for(conn) | {ev.sensor}
                alert = Alert(
                    id=next(self._ids),
                    finding=finding,
                    severity=self._severity(sensors),
                    created_at=now,
                    sensors=sensors,
                )
            for sensor in alert.sensors:
                self._last_alert[(conn.pid, sensor, conn.remote_address)] = now
            self._alerted[conn.key] = alert
            alerts.append(alert)
        return alerts

    def ingest_event(self, event: Event) -> list[Alert]:
        if self._ignored(event.bundle_id, event.process_name):
            return []
        if event.system and not self.config.include_system:
            return []
        self._advance(event.timestamp)
        self._events.append(event)
        found = [f for c in self._connections if (f := self._matches(event, c)) is not None]
        return self._emit(found)

    def ingest_connection(self, conn: NetworkConnection) -> list[Alert]:
        if self._ignored(conn.bundle_id, conn.process_name):
            return []
        if not self.config.include_system and is_system_path(conn.exe_path):
            return []
        if not self.config.include_dns and conn.remote_port in DNS_PORTS:
            return []
        self._advance(conn.first_seen)
        self._connections.append(conn)
        found = [f for e in self._events if (f := self._matches(e, conn)) is not None]
        return self._emit(found)
