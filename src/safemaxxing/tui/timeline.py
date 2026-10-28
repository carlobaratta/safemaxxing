"""The millisecond timeline behind an alert: every sensor event of the actor, then the egress.

Pure functions over the domain model, so the timeline can be built and tested without Textual.
The engine keeps events only for its retention period, so the app snapshots them with
`related_events` when the alert arrives, not when the timeline is opened.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from safemaxxing.correlation import CorrelationConfig, same_actor
from safemaxxing.models import PKTAP_STATUS, Event, NetworkConnection, SensorType

# Upper bound on events kept per alert: a flickering indicator must not grow one without end.
MAX_EVENTS = 64


@dataclass(frozen=True, slots=True)
class TimelineStep:
    """One point of the timeline: a sensor event, or the outbound connection that ends it."""

    timestamp: float
    source: str
    actor: str
    detail: str
    sensor: SensorType | None = None

    @property
    def egress(self) -> bool:
        """Whether this step is the connection rather than a sensor event."""
        return self.sensor is None


def related_events(
    conn: NetworkConnection, events: Iterable[Event], config: CorrelationConfig
) -> tuple[Event, ...]:
    """The events of `conn`'s actor inside its correlation window, oldest first.

    Uses the engine's own bounds (`window_s` before the socket, `clock_skew_s` after it), so
    the timeline shows exactly the events that could have raised the alert.
    """
    found = {
        e
        for e in events
        if -config.clock_skew_s <= conn.first_seen - e.timestamp <= config.window_s
        and same_actor(e, conn)
    }
    return tuple(sorted(found, key=lambda e: e.timestamp)[-MAX_EVENTS:])


def merge_events(old: Iterable[Event], new: Iterable[Event]) -> tuple[Event, ...]:
    """Union of two event snapshots, oldest first, capped at `MAX_EVENTS`."""
    return tuple(sorted(set(old) | set(new), key=lambda e: e.timestamp)[-MAX_EVENTS:])


def event_source(event: Event) -> str:
    """Short name of where the event came from: `indicator`, `tcc`, `cmio`, `locationd`..."""
    if event.from_indicator:
        return "indicator"
    tail = event.subsystem.rsplit(".", 1)[-1].lower()
    return tail or "log"


def egress_source(conn: NetworkConnection) -> str:
    """`pktap` for a flow seen on the wire, `socket` for one from the socket table."""
    return "pktap" if conn.status == PKTAP_STATUS else "socket"


def timeline_steps(conn: NetworkConnection, events: Iterable[Event]) -> tuple[TimelineStep, ...]:
    """`events` as steps, oldest first, followed by the egress step for `conn`."""
    steps = [
        TimelineStep(
            timestamp=e.timestamp,
            source=event_source(e),
            actor=f"{e.identity} pid={e.pid}" if e.pid is not None else e.identity,
            detail=e.service or e.message[:80],
            sensor=e.sensor,
        )
        for e in sorted(events, key=lambda e: e.timestamp)
    ]
    host = f" ({conn.hostname})" if conn.hostname else ""
    steps.append(
        TimelineStep(
            timestamp=conn.first_seen,
            source=egress_source(conn),
            actor=f"{conn.bundle_id or conn.process_name} pid={conn.pid}",
            detail=f"{conn.protocol.value} → {conn.remote}{host}",
        )
    )
    return tuple(steps)
