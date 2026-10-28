"""Wires sensors and the network monitor into the correlation engine."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterable, AsyncIterator, Callable
from typing import Final, TypeVar

from safemaxxing.correlation import CorrelationConfig, CorrelationEngine
from safemaxxing.models import Alert, Event, NetworkConnection
from safemaxxing.network import HostnameResolver, NetworkMonitor
from safemaxxing.pktap import PktapCapture, PktapFlowTracker, capture_filter, pktap_command
from safemaxxing.process_tree import ProcessChainResolver
from safemaxxing.sensors import SensorListener
from safemaxxing.throughput import ThroughputDeltaMonitor

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
        resolver: HostnameResolver | None = None,
    ) -> None:
        self._events = events
        self._connections = connections
        self.engine = engine or CorrelationEngine()
        self.monitor = monitor
        # A second connection source: UDP flows the socket table shows without a peer.
        self.pktap = pktap
        # The reverse-DNS cache both sources read from, so the UI can name alerts later.
        self.resolver = resolver
        self._recent: deque[NetworkConnection] = deque(maxlen=256)

    @classmethod
    def default(
        cls,
        config: CorrelationConfig | None = None,
        poll_interval_s: float = 0.2,
        include_loopback: bool = False,
        resolve_hostnames: bool = True,
        udp_flows: bool = False,
        tcp_flows: bool = False,
        throughput: bool = False,
        attribute_children: bool = True,
    ) -> Supervisor:
        """Build a Supervisor on the real sensor listener and a polling NetworkMonitor.

        Reverse-DNS hostname resolution is optional via `resolve_hostnames`. Three pktap
        sources (all needing root, all following `include_system`, `include_dns` and
        `include_loopback` like the socket table) can be added: `udp_flows` for outbound UDP
        the socket table shows without a peer; `tcp_flows` for outbound TCP SYNs, catching a
        socket that opens and closes between two polls; and `throughput`, which re-surfaces a
        pre-established flow when its outbound rate spikes (over TCP only when `tcp_flows` is
        also on, since it needs the TCP packets). `attribute_children` links a socket back to
        the app that spawned its owner or is responsible for it (off macOS, or without the
        privilege to inspect a process, this resolves to a no-op).
        """
        config = config or CorrelationConfig()
        resolver = HostnameResolver() if resolve_hostnames else None
        monitor = NetworkMonitor(
            interval_s=poll_interval_s,
            include_loopback=include_loopback,
            resolver=resolver,
        )
        actor_chain = ProcessChainResolver().chain if attribute_children else None
        pktap = None
        if udp_flows or tcp_flows or throughput:
            pktap = _pktap_capture(
                config, include_loopback, resolver, udp_flows, tcp_flows, throughput
            )
        return cls(
            events=SensorListener().events(),
            connections=monitor.connections(),
            engine=CorrelationEngine(config, actor_chain=actor_chain),
            monitor=monitor,
            pktap=pktap,
            resolver=resolver,
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
        return sockets + tuple(c for c in self.pktap.active() if c.key not in seen)

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


def _pktap_capture(
    config: CorrelationConfig,
    include_loopback: bool,
    resolver: HostnameResolver | None,
    udp_flows: bool,
    tcp_flows: bool,
    throughput: bool,
) -> PktapCapture:
    tracker = PktapFlowTracker(
        include_system=config.include_system, include_loopback=include_loopback
    )
    bpf = capture_filter(
        include_udp=udp_flows,
        include_dns=config.include_dns,
        # Throughput needs the data packets, so every TCP packet; otherwise only the SYNs.
        tcp_syn=tcp_flows and not throughput,
        tcp_data=tcp_flows and throughput,
    )
    command = pktap_command(bpf_filter=bpf)
    monitor = ThroughputDeltaMonitor() if throughput else None
    # Shares the monitor's resolver: one cache, one thread pool, for both sources.
    return PktapCapture(command=command, tracker=tracker, resolver=resolver, throughput=monitor)
