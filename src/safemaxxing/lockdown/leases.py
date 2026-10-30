"""Leases: which apps may reach the network in Paranoia Mode, and for how long after.

A lease is held by one or more *sources*, signals that the user is using the app right now:

* `SENSOR`: Control Center attributes the camera, the microphone or a screen capture to it;
* `FOREGROUND`: it is the frontmost app;
* `MANUAL`: the user granted it from the TUI.

While held, a lease is ACTIVE: new destinations may be learned for it. When its last source
goes away it turns DRAINING: nothing new is learned, but its grants stay, so a camera blink, a
brief Cmd-Tab or the end-of-call signalling are not cut. When the grace period of the sources
it had runs out it is revoked: its grants leave pf at once (`on_revoke`). A source that comes
back while draining makes it ACTIVE again with its grants intact.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from safemaxxing.lockdown.rules import Grant


class LeaseSource(StrEnum):
    """Why an app holds a lease."""

    SENSOR = "sensor"
    FOREGROUND = "foreground"
    MANUAL = "manual"


class LeaseState(StrEnum):
    """ACTIVE learns new destinations; DRAINING only keeps the ones it has."""

    ACTIVE = "active"
    DRAINING = "draining"


# Seconds a lease keeps its grants after its last source of that kind ends. A sensor's grace
# covers the end of a call (hang-up signalling, the "rate this call" page) and a camera
# toggled off and on; it is 15x INDICATOR_MERGE_S, so indicator flicker never reaches it. The
# foreground's is shorter: switching away from an app is a weaker signal than hanging up.
# A manual lease has none: releasing it is an explicit, immediate revocation.
GRACE_S: Mapping[LeaseSource, float] = {
    LeaseSource.SENSOR: 30.0,
    LeaseSource.FOREGROUND: 15.0,
    LeaseSource.MANUAL: 0.0,
}
# A lease asking for more destinations than this is scanning, not calling.
MAX_GRANTS = 512


@dataclass(slots=True)
class Lease:
    """One app's lease. `team_id` is pinned at the first verified grant (see codesign.py)."""

    bundle_id: str
    sources: set[LeaseSource] = field(default_factory=set)
    state: LeaseState = LeaseState.ACTIVE
    grants: set[Grant] = field(default_factory=set)
    team_id: str | None = None
    # Monotonic time the grants go, while DRAINING.
    deadline: float | None = None
    # Sources ever held: the grace period is the longest of theirs.
    _seen: set[LeaseSource] = field(default_factory=set)
    _timer: asyncio.TimerHandle | None = None
    _generation: int = 0


class LeaseBook:
    """Leases by bundle id, with an asynchronous teardown timer per draining lease.

    Called from the event loop only (the sensor callback, the foreground poller, the TUI);
    the timers run on that same loop, so no lock is needed.
    """

    def __init__(
        self,
        on_revoke: Callable[[Lease], Coroutine[object, object, None]],
        grace_s: Mapping[LeaseSource, float] = GRACE_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._on_revoke = on_revoke
        self._grace_s = grace_s
        self._clock = clock
        self._leases: dict[str, Lease] = {}
        # Revocations in flight; kept so they are not garbage-collected mid-run.
        self._tasks: set[asyncio.Task[None]] = set()

    def __iter__(self) -> Iterator[Lease]:
        return iter(list(self._leases.values()))

    def get(self, bundle_id: str) -> Lease | None:
        """The lease, ACTIVE or DRAINING: its grants are still in pf."""
        return self._leases.get(bundle_id)

    def active(self, bundle_id: str) -> Lease | None:
        """The lease only while ACTIVE, the state in which it may learn destinations."""
        lease = self._leases.get(bundle_id)
        return lease if lease is not None and lease.state is LeaseState.ACTIVE else None

    def hold(self, bundle_id: str, source: LeaseSource) -> Lease:
        """`source` now holds `bundle_id`'s lease; a draining lease becomes ACTIVE again."""
        lease = self._leases.get(bundle_id)
        if lease is None:
            lease = self._leases[bundle_id] = Lease(bundle_id)
        lease.sources.add(source)
        lease._seen.add(source)
        if lease.state is LeaseState.DRAINING:
            self._cancel_timer(lease)
            lease.state = LeaseState.ACTIVE
            lease.deadline = None
        return lease

    def release(self, bundle_id: str, source: LeaseSource) -> None:
        """`source` no longer holds the lease; the last one to go starts its grace period."""
        lease = self._leases.get(bundle_id)
        if lease is None or source not in lease.sources:
            return
        lease.sources.discard(source)
        if lease.sources:
            return
        grace = max(self._grace_s[s] for s in lease._seen)
        lease.state = LeaseState.DRAINING
        lease.deadline = self._clock() + grace
        lease._generation += 1
        if grace <= 0:
            self._expire(bundle_id, lease._generation)
            return
        loop = asyncio.get_running_loop()
        lease._timer = loop.call_later(grace, self._expire, bundle_id, lease._generation)

    def set_holders(self, source: LeaseSource, bundle_ids: Iterable[str]) -> None:
        """Make `source` hold exactly `bundle_ids`: hold the new ones, release the others."""
        wanted = set(bundle_ids)
        for bundle_id in wanted:
            self.hold(bundle_id, source)
        for lease in list(self._leases.values()):
            if source in lease.sources and lease.bundle_id not in wanted:
                self.release(lease.bundle_id, source)

    def revoke_now(self, bundle_id: str) -> None:
        """Revoke at once, whatever holds the lease (a failed re-verification)."""
        lease = self._leases.get(bundle_id)
        if lease is not None:
            lease.sources.clear()
            lease._generation += 1
            self._expire(bundle_id, lease._generation)

    def _cancel_timer(self, lease: Lease) -> None:
        if lease._timer is not None:
            lease._timer.cancel()
            lease._timer = None
        lease._generation += 1

    def _expire(self, bundle_id: str, generation: int) -> None:
        lease = self._leases.get(bundle_id)
        # A stale timer: the lease came back (or was revoked) after this one was scheduled.
        if lease is None or lease._generation != generation:
            return
        del self._leases[bundle_id]
        lease._timer = None
        task = asyncio.get_running_loop().create_task(self._on_revoke(lease))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def cancel_all(self) -> list[Lease]:
        """Drop every lease without calling `on_revoke` (leaving lockdown flushes pf itself)."""
        leases = list(self._leases.values())
        for lease in leases:
            self._cancel_timer(lease)
        self._leases.clear()
        return leases
