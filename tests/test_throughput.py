from __future__ import annotations

from safemaxxing.models import Direction, NetworkConnection, PktapEvent, Protocol
from safemaxxing.pktap import PktapCapture, PktapFlowTracker
from safemaxxing.throughput import (
    THROUGHPUT_STATUS,
    ThroughputConfig,
    ThroughputDeltaMonitor,
    ThroughputSpike,
)

# Small, round thresholds so the arithmetic in each test is obvious.
CONFIG = ThroughputConfig(
    interval_s=1.0,
    min_flow_age_s=2.0,
    spike_factor=3.0,
    min_spike_bytes_per_s=1000.0,
    baseline_alpha=0.5,
    cooldown_s=5.0,
)


def pkt(timestamp: float, length: int, direction: Direction = Direction.OUTBOUND) -> PktapEvent:
    return PktapEvent(
        timestamp=timestamp,
        interface="en0",
        pid=5000,
        process_name="keepalive",
        protocol=Protocol.UDP,
        src_ip="10.0.0.5",
        src_port=5555,
        dest_ip="203.0.113.9",
        dest_port=443,
        direction=direction,
        length=length,
    )


def feed(monitor: ThroughputDeltaMonitor, packets: list[PktapEvent]) -> list[ThroughputSpike]:
    return [s for p in packets if (s := monitor.observe(p)) is not None]


def baseline_then_burst() -> list[PktapEvent]:
    """A ~100 B/s keep-alive for three intervals, then a 20 KB/s burst closed at t=4."""
    return [
        pkt(0.0, 100),
        pkt(1.0, 100),  # closes [0,1): rate 100, sets baseline
        pkt(2.0, 100),  # closes [1,2): rate 100, below the 1000 floor -> no spike
        pkt(3.0, 100),  # closes [2,3): rate 100, no spike
        pkt(3.3, 10000),  # accumulates in the open [3,4) interval
        pkt(3.6, 10000),
        pkt(4.0, 100),  # closes [3,4): rate ~20100 -> spike
    ]


def test_first_packets_only_build_a_baseline() -> None:
    monitor = ThroughputDeltaMonitor(CONFIG)
    assert feed(monitor, [pkt(0.0, 100), pkt(1.0, 100), pkt(2.0, 100)]) == []


def test_pre_established_flow_spikes_above_baseline() -> None:
    monitor = ThroughputDeltaMonitor(CONFIG)
    (spike,) = feed(monitor, baseline_then_burst())
    assert spike.timestamp == 4.0
    assert spike.first_seen == 0.0
    assert spike.rate_bytes_per_s > spike.baseline_bytes_per_s * CONFIG.spike_factor
    assert spike.rate_bytes_per_s >= CONFIG.min_spike_bytes_per_s
    assert spike.flow_key == (5000, Protocol.UDP, "10.0.0.5", 5555, "203.0.113.9", 443)


def test_spike_below_absolute_floor_is_ignored() -> None:
    # A flow whose baseline is tiny and whose burst, while 10x the baseline, is still under the
    # floor (a chatty keep-alive, not an upload) must not alert.
    monitor = ThroughputDeltaMonitor(CONFIG)
    packets = [pkt(0.0, 10), pkt(1.0, 10), pkt(2.0, 10), pkt(2.5, 100), pkt(3.0, 10)]
    assert feed(monitor, packets) == []


def test_young_flow_does_not_spike() -> None:
    # Same burst shape but the flow is younger than min_flow_age_s when it would fire.
    monitor = ThroughputDeltaMonitor(
        ThroughputConfig(min_flow_age_s=60.0, min_spike_bytes_per_s=1000)
    )
    assert feed(monitor, baseline_then_burst()) == []


def test_cooldown_suppresses_a_second_spike() -> None:
    monitor = ThroughputDeltaMonitor(CONFIG)
    packets = baseline_then_burst() + [
        pkt(4.3, 10000),
        pkt(4.6, 10000),
        pkt(5.0, 100),  # closes [4,5): another burst, within the 5 s cooldown -> suppressed
    ]
    assert len(feed(monitor, packets)) == 1


def test_inbound_packets_neither_create_nor_spike_a_flow() -> None:
    monitor = ThroughputDeltaMonitor(CONFIG)
    assert feed(monitor, [pkt(t, 50000, Direction.INBOUND) for t in (0.0, 1.0, 2.0, 3.0)]) == []


def test_spike_to_connection_marks_status_and_spike_time() -> None:
    spike = ThroughputSpike(
        pid=5000,
        process_name="keepalive",
        protocol=Protocol.TCP,
        local_address="10.0.0.5",
        local_port=5555,
        remote_address="203.0.113.9",
        remote_port=443,
        timestamp=4.0,
        first_seen=0.0,
        rate_bytes_per_s=20000.0,
        baseline_bytes_per_s=100.0,
    )
    conn = spike.to_connection(process_name="Spy", bundle_id="com.example.spy")
    assert conn.status == THROUGHPUT_STATUS
    assert conn.first_seen == 4.0
    assert conn.process_name == "Spy"
    assert conn.remote == "203.0.113.9:443"


def test_capture_spike_reuses_the_trackers_resolved_identity() -> None:
    # Once a flow's first packet has gone by, the tracker holds its resolved process identity;
    # a later spike must re-surface that, not the 16-char kernel name, stamped at the spike.
    exe = "/Applications/Spy.app/Contents/MacOS/Spy"
    tracker = PktapFlowTracker(
        process_lookup={5000: ("Spy", exe)}.get,
        bundle_lookup={exe: "com.example.spy"}.get,
        broadcasts=frozenset,
    )
    tracker.mute_until(0.0)
    tracker.feed(pkt(0.0, 100))
    capture = PktapCapture(tracker=tracker, throughput=ThroughputDeltaMonitor(CONFIG))
    spike = ThroughputSpike(
        pid=5000,
        process_name="keepalive",
        protocol=Protocol.UDP,
        local_address="10.0.0.5",
        local_port=5555,
        remote_address="203.0.113.9",
        remote_port=443,
        timestamp=9.0,
        first_seen=0.0,
        rate_bytes_per_s=20000.0,
        baseline_bytes_per_s=100.0,
    )
    conn: NetworkConnection = capture._spike_connection(spike)
    assert conn.process_name == "Spy"
    assert conn.bundle_id == "com.example.spy"
    assert conn.status == THROUGHPUT_STATUS
    assert conn.first_seen == 9.0


def test_spike_connection_correlates_with_a_preceding_sensor_event() -> None:
    # The end-to-end point of M1.2: a pre-established socket carries no new-flow signal, but its
    # throughput spike, fed in as a connection, correlates with a microphone access just before.
    from conftest import T0, make_event

    from safemaxxing.correlation import CorrelationEngine
    from safemaxxing.models import SensorType, Severity

    eng = CorrelationEngine()
    eng.ingest_event(make_event(sensor=SensorType.MICROPHONE))
    spike = ThroughputSpike(
        pid=4242,
        process_name="keepalive",
        protocol=Protocol.TCP,
        local_address="10.0.0.5",
        local_port=51544,
        remote_address="203.0.113.9",
        remote_port=443,
        timestamp=T0 + 0.1,
        first_seen=T0 - 600.0,
        rate_bytes_per_s=50000.0,
        baseline_bytes_per_s=200.0,
    )
    (alert,) = eng.ingest_connection(spike.to_connection(bundle_id="com.example.spy"))
    assert alert.severity is Severity.HIGH
    assert "microphone" in alert.sensor_label
