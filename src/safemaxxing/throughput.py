"""Throughput-delta detection for pre-established connections.

A socket opened minutes before a sensor turns on, and kept alive, carries the exfiltration
without any new socket (so `NetworkMonitor` sees nothing new) and without a new flow (so
`PktapFlowTracker`, which emits only a flow's *first* outbound packet, stays quiet). The one
observable is the traffic itself: an idle keep-alive that suddenly pushes data out.

`ThroughputDeltaMonitor` watches the outbound byte rate of each flow, taken from the `length`
of the `pktap` packets the capture already parses -- macOS exposes no per-socket `tx_bytes`,
so the packets are the only count available without a second tool. It learns a per-flow
baseline and, when a flow that has been open at least `min_flow_age_s` pushes a rate well
above its own baseline, surfaces that flow again as a `NetworkConnection` stamped at the
spike. That connection flows into the same `CorrelationEngine.ingest_connection` as every
other egress source, so the "did a sensor fire just before this?" decision -- the before/
after-sensor comparison -- stays in the one place that already makes it, and a spike with no
preceding sensor access is buffered and dropped like any other uncorrelated connection.

The monitor is pure: it is driven entirely by the packets it is fed and their timestamps,
with no clock of its own, so tests replay a fixed packet sequence and assert to the byte.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass, field

from safemaxxing.models import Direction, NetworkConnection, PktapEvent, Protocol

# `NetworkConnection.status` of a flow re-surfaced by a throughput spike rather than its first
# packet; distinct from PKTAP_STATUS so the UI and tests can tell the two pktap sources apart.
THROUGHPUT_STATUS = "PKTAP-TX"

FlowKey = tuple[int, Protocol, str, int, str, int]


@dataclass(frozen=True, slots=True)
class ThroughputConfig:
    """Tunables for spotting an outbound-rate spike on a pre-established flow.

    A closed `interval_s` window of a flow is a spike when its rate clears both a relative bar
    (`spike_factor` times the flow's learned baseline) and an absolute floor
    (`min_spike_bytes_per_s`, so an idle keep-alive whose baseline is near zero does not trip
    on a handful of bytes), the flow has been open at least `min_flow_age_s`, and the flow has
    not already spiked within `cooldown_s`.
    """

    interval_s: float = 1.0
    min_flow_age_s: float = 5.0
    spike_factor: float = 4.0
    min_spike_bytes_per_s: float = 32_768.0
    # EWMA weight of the newest interval in the baseline; the spike interval is folded in too,
    # so a sustained transfer becomes the new normal and only its onset is reported.
    baseline_alpha: float = 0.3
    cooldown_s: float = 10.0
    idle_s: float = 120.0
    max_flows: int = 8192


@dataclass(frozen=True, slots=True)
class ThroughputSpike:
    """A pre-established flow whose outbound rate jumped above its baseline."""

    pid: int
    process_name: str
    protocol: Protocol
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    timestamp: float
    first_seen: float
    rate_bytes_per_s: float
    baseline_bytes_per_s: float

    @property
    def flow_key(self) -> FlowKey:
        """Same shape as `NetworkConnection.key`, so a spike maps onto a known flow."""
        return (
            self.pid,
            self.protocol,
            self.local_address,
            self.local_port,
            self.remote_address,
            self.remote_port,
        )

    def to_connection(
        self,
        process_name: str | None = None,
        exe_path: str | None = None,
        bundle_id: str | None = None,
    ) -> NetworkConnection:
        """The spiking flow as a connection first seen at the spike, so the correlation engine
        treats it like any freshly observed socket; `process_name` replaces the cut kernel name."""
        return NetworkConnection(
            pid=self.pid,
            process_name=process_name or self.process_name,
            protocol=self.protocol,
            local_address=self.local_address,
            local_port=self.local_port,
            remote_address=self.remote_address,
            remote_port=self.remote_port,
            status=THROUGHPUT_STATUS,
            first_seen=self.timestamp,
            exe_path=exe_path,
            bundle_id=bundle_id,
        )


@dataclass(slots=True)
class _Flow:
    """Per-flow accounting: the open interval's bytes and the baseline learned from closed ones."""

    first_seen: float
    last_seen: float
    interval_start: float
    interval_bytes: int
    baseline: float | None = None
    last_emit: float = field(default=-math.inf)


class ThroughputDeltaMonitor:
    """Turns a stream of outbound packets into spikes on pre-established flows.

    `observe` is called with every packet the capture yields and returns a `ThroughputSpike`
    on the interval boundary at which a flow crosses its baseline, else None. Direction and
    relevance are already filtered by the capture; inbound packets only keep a flow from being
    pruned as idle.
    """

    def __init__(self, config: ThroughputConfig | None = None) -> None:
        self.config = config or ThroughputConfig()
        self._flows: dict[FlowKey, _Flow] = {}

    def _prune(self, now: float) -> None:
        horizon = now - self.config.idle_s
        self._flows = {k: f for k, f in self._flows.items() if f.last_seen >= horizon}
        if len(self._flows) >= self.config.max_flows:
            self._flows.clear()

    def observe(self, packet: PktapEvent) -> ThroughputSpike | None:
        """Account `packet`'s bytes and return a spike if its flow just crossed its baseline."""
        key = packet.flow_key
        now = packet.timestamp
        if packet.direction is Direction.INBOUND:
            if (flow := self._flows.get(key)) is not None:
                flow.last_seen = now
            return None
        flow = self._flows.get(key)
        if flow is None:
            if len(self._flows) >= self.config.max_flows:
                self._prune(now)
            self._flows[key] = _Flow(
                first_seen=now, last_seen=now, interval_start=now, interval_bytes=packet.length
            )
            return None
        spike = self._roll(key, flow, packet)
        flow.interval_bytes += packet.length
        flow.last_seen = now
        return spike

    def _roll(self, key: FlowKey, flow: _Flow, packet: PktapEvent) -> ThroughputSpike | None:
        """Close the flow's open interval if `interval_s` has passed, judge it, and fold its
        rate into the baseline. The current packet opens the next interval, counted by caller."""
        now = packet.timestamp
        elapsed = now - flow.interval_start
        if elapsed < self.config.interval_s:
            return None
        rate = flow.interval_bytes / elapsed
        spike = self._judge(flow, rate, packet)
        if spike is not None:
            flow.last_emit = now
        alpha = self.config.baseline_alpha
        if flow.baseline is None:
            flow.baseline = rate
        else:
            flow.baseline = (1 - alpha) * flow.baseline + alpha * rate
        flow.interval_start = now
        flow.interval_bytes = 0
        return spike

    def _judge(self, flow: _Flow, rate: float, packet: PktapEvent) -> ThroughputSpike | None:
        now = packet.timestamp
        if flow.baseline is None:
            return None  # first closed interval only sets the baseline
        if now - flow.first_seen < self.config.min_flow_age_s:
            return None
        if now - flow.last_emit < self.config.cooldown_s:
            return None
        if rate < self.config.min_spike_bytes_per_s:
            return None
        if rate < flow.baseline * self.config.spike_factor:
            return None
        _, protocol, local_ip, local_port, remote_ip, remote_port = packet.flow_key
        return ThroughputSpike(
            pid=packet.pid,
            process_name=packet.process_name,
            protocol=protocol,
            local_address=local_ip,
            local_port=local_port,
            remote_address=remote_ip,
            remote_port=remote_port,
            timestamp=now,
            first_seen=flow.first_seen,
            rate_bytes_per_s=rate,
            baseline_bytes_per_s=flow.baseline,
        )


# How a capture resolves a flow key to the connection it already built (process name, exe,
# bundle id), so a spike re-surfaces that identity rather than only the 16-char kernel name.
ConnectionLookup = Callable[[FlowKey], NetworkConnection | None]
