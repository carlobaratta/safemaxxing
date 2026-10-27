"""Wires sensors and the network monitor into the correlation engine."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterable, AsyncIterator, Callable
from typing import Final, TypeVar

from safemaxxing.correlation import CorrelationConfig, CorrelationEngine
from safemaxxing.models import Alert, Event, NetworkConnection
from safemaxxing.network import HostnameResolver, NetworkMonitor
from safemaxxing.pktap import PktapCapture, PktapFlowTracker, pktap_command, udp_filter
from safemaxxing.sensors import SensorListener

type Update = Event | NetworkConnection | Alert

T = TypeVar("T")
_DONE: Final = object()


class Supervisor:
    """Feeds sensor events and observed connections through a CorrelationEngine."""

    def __init__(
        self,
        events: AsyncIterable[Event],
        connections: AsyncIterable[NetworkConnection],
        engine: CorrelationEngine | None = None,
        monitor: NetworkMonitor | None = None,
        pktap: PktapCapture | None = None,
    ) -> None:
        self._events = events
        self._connections = connections
        self.engine = engine or CorrelationEngine()
        self.monitor = monitor
        # A second connection source: UDP flows the socket table shows without a peer.
        self.pktap = pktap
        self._recent: deque[NetworkConnection] = deque(maxlen=256)

    @classmethod
    def default(
        cls,
        config: CorrelationConfig | None = None,
        poll_interval_s: float = 0.2,
        include_loopback: bool = False,
        resolve_hostnames: bool = True,
        udp_flows: bool = False,
    ) -> Supervisor:
        """Build a Supervisor on the real sensor listener and a polling NetworkMonitor.

        Reverse-DNS hostname resolution is optional via `resolve_hostnames`. `udp_flows` adds
        an always-on pktap capture (needs root) that follows `include_system`, `include_dns`
        and `include_loopback` like the socket table does.
        """
        config = config or CorrelationConfig()
        monitor = NetworkMonitor(
            interval_s=poll_interval_s,
            include_loopback=include_loopback,
            resolver=HostnameResolver() if resolve_hostnames else None,
        )
        return cls(
            events=SensorListener().events(),
            connections=monitor.connections(),
            engine=CorrelationEngine(config),
            monitor=monitor,
            pktap=_pktap_capture(config, include_loopback) if udp_flows else None,
        )

    def active_connections(self) -> tuple[NetworkConnection, ...]:
        """Return the monitor's and pktap's active connections, or the last 256 seen without a
        monitor."""
        if self.monitor is None:
            return tuple(self._recent)
        sockets = self.monitor.active
        if self.pktap is None:
            return sockets
        # A connected UDP socket is in both; the TUI keys its rows on `key`, so keep one.
        seen = {c.key for c in sockets}
        return sockets + tuple(c for c in self.pktap.tracker.active() if c.key not in seen)

    def _ingest_connection(self, conn: NetworkConnection) -> list[Alert]:
        self._recent.append(conn)
        return self.engine.ingest_connection(conn)

    async def stream(self) -> AsyncIterator[Update]:
        """Yield every observed event, connection and resulting alert, in arrival order."""
        queue: asyncio.Queue[object] = asyncio.Queue()

        async def pump(source: AsyncIterable[T], ingest: Callable[[T], list[Alert]]) -> None:
            """Queue `source` items and resulting alerts, then any error, then a done marker."""
            try:
                async for item in source:
                    queue.put_nowait(item)
                    for alert in ingest(item):
                        queue.put_nowait(alert)
            except Exception as exc:
                queue.put_nowait(exc)
            finally:
                queue.put_nowait(_DONE)

        tasks = [
            asyncio.create_task(pump(self._events, self.engine.ingest_event)),
            asyncio.create_task(pump(self._connections, self._ingest_connection)),
        ]
        if self.pktap is not None:
            flows = self.pktap.connections()
            tasks.append(asyncio.create_task(pump(flows, self._ingest_connection)))
        running = len(tasks)
        try:
            while running:
                item = await queue.get()
                if item is _DONE:
                    running -= 1
                elif isinstance(item, Exception):
                    raise item
                elif isinstance(item, Event | NetworkConnection | Alert):
                    yield item
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


def _pktap_capture(config: CorrelationConfig, include_loopback: bool) -> PktapCapture:
    tracker = PktapFlowTracker(
        include_system=config.include_system, include_loopback=include_loopback
    )
    command = pktap_command(bpf_filter=udp_filter(include_dns=config.include_dns))
    return PktapCapture(command=command, tracker=tracker)
