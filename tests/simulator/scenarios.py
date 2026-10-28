"""Named end-to-end scenarios and the driver that replays them through the real engine.

A `Scenario` is pure data: the synthetic log entries, socket-table connections and pktap
packets of one episode, plus the process/bundle lookups pktap needs. `replay` merges them by
timestamp and feeds each through the exact pipeline that runs on a Mac -- `JsonStreamDecoder`,
`SensorEventParser`, `PktapFlowTracker`/`ThroughputDeltaMonitor` and `CorrelationEngine` --
with a `FakeMonotonicClock` as the engine clock, and returns the alerts. Only the subprocess
and polling plumbing is replaced; every heuristic under test is the real one.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

from safemaxxing.correlation import CorrelationConfig, CorrelationEngine
from safemaxxing.models import (
    Alert,
    Direction,
    NetworkConnection,
    PktapEvent,
    Protocol,
)
from safemaxxing.pktap import PktapFlowTracker
from safemaxxing.sensors import JsonStreamDecoder, SensorEventParser, parse_timestamp
from safemaxxing.throughput import THROUGHPUT_STATUS, ThroughputDeltaMonitor

from . import logs
from .fakes import FakeMonotonicClock, FakePktapStream, FakeSocketPoller

T0 = 1_700_000_000.0

ProcessMap = dict[int, tuple[str, str | None]]
BundleMap = dict[str, str]


@dataclass(frozen=True, slots=True)
class Scenario:
    """One episode of macOS activity: its log entries and network observations."""

    name: str
    entries: list[logs.Entry]
    sockets: list[NetworkConnection] = field(default_factory=list)
    packets: list[PktapEvent] = field(default_factory=list)
    processes: ProcessMap = field(default_factory=dict)
    bundles: BundleMap = field(default_factory=dict)


def replay(
    scenario: Scenario,
    config: CorrelationConfig | None = None,
    actor_chain: dict[int, frozenset[int]] | None = None,
    throughput: bool = False,
) -> list[Alert]:
    """Replay `scenario` through the real pipeline and return the alerts, in order.

    `actor_chain` maps a socket owner's pid to the pids accountable for it (M1.3); `throughput`
    turns on the pre-established-flow monitor (M1.2). The clock is advanced to each item's
    timestamp before it is fed, so correlation is judged on the scenario's own timings.
    """
    clock = FakeMonotonicClock(T0 - 1.0)
    engine = CorrelationEngine(
        config,
        clock=clock,
        actor_chain=(lambda pid: (actor_chain or {}).get(pid, frozenset({pid}))),
    )
    parser = SensorEventParser()
    decoder = JsonStreamDecoder()
    poller = FakeSocketPoller(scenario.sockets)
    stream = FakePktapStream(scenario.packets)
    tracker = PktapFlowTracker(
        process_lookup=scenario.processes.get,
        bundle_lookup=scenario.bundles.get,
        broadcasts=frozenset,
    )
    monitor = ThroughputDeltaMonitor() if throughput else None

    decoded = decoder.feed(logs.render(scenario.entries))
    log_queue = sorted(decoded, key=lambda d: parse_timestamp(str(d.get("timestamp", ""))))
    times = sorted(
        {parse_timestamp(str(d.get("timestamp", ""))) for d in decoded}
        | {c.first_seen for c in scenario.sockets}
        | {p.timestamp for p in scenario.packets}
    )

    alerts: list[Alert] = []
    index = 0
    for now in times:
        clock.set(now)
        while index < len(log_queue) and parse_timestamp(str(log_queue[index]["timestamp"])) <= now:
            for event in parser.parse(log_queue[index]):
                alerts += engine.ingest_event(event)
            index += 1
        for conn in poller.poll(now):
            alerts += engine.ingest_connection(conn)
        for packet in stream.drain(now):
            if (flow := tracker.feed(packet)) is not None:
                alerts += engine.ingest_connection(flow)
            if monitor is not None and (spike := monitor.observe(packet)) is not None:
                known = tracker.connection_for(spike.flow_key)
                surfaced = (
                    dataclasses.replace(known, status=THROUGHPUT_STATUS, first_seen=spike.timestamp)
                    if known is not None
                    else spike.to_connection()
                )
                alerts += engine.ingest_connection(surfaced)
    return alerts


def _udp(
    ts: float, pid: int, src: str, sport: int, dst: str, dport: int, length: int
) -> PktapEvent:
    return PktapEvent(
        timestamp=ts,
        interface="en0",
        pid=pid,
        process_name="helper",
        protocol=Protocol.UDP,
        src_ip=src,
        src_port=sport,
        dest_ip=dst,
        dest_port=dport,
        direction=Direction.OUTBOUND,
        length=length,
    )


def _socket(
    ts: float, pid: int, remote: str, port: int, exe: str | None, bundle: str | None
) -> NetworkConnection:
    return NetworkConnection(
        pid=pid,
        process_name="app",
        protocol=Protocol.TCP,
        local_address="10.0.0.5",
        local_port=51544,
        remote_address=remote,
        remote_port=port,
        status="ESTABLISHED",
        first_seen=ts,
        exe_path=exe,
        bundle_id=bundle,
    )


BRAVE_BUNDLE = "com.brave.Browser"
BRAVE_HELPER = "/Applications/Brave Browser.app/Contents/Frameworks/Brave Browser Helper"
BRAVE_HELPER_BUNDLE = "com.brave.Browser.helper"
ZOOM_BINARY = "/Applications/zoom.us.app/Contents/MacOS/zoom.us"
SPY_BINARY = "/Applications/Spy.app/Contents/MacOS/Spy"
PHOTO_BOOTH = "/System/Applications/Photo Booth.app/Contents/MacOS/Photo Booth"


def brave_meet() -> Scenario:
    """A Google Meet call in Brave: camera+mic indicator, then the WebRTC media over UDP (no
    peer in the socket table) that only pktap sees -- the flagship pktap path."""
    helper_pid = 16112
    return Scenario(
        name="brave_meet",
        entries=[
            logs.indicator(T0, [f"cam:{BRAVE_BUNDLE}", f"mic:{BRAVE_BUNDLE}"]),
            logs.cmio_camera(T0 + 0.05, helper_pid, BRAVE_HELPER),
        ],
        packets=[_udp(T0 + 0.188, helper_pid, "10.243.5.87", 64316, "74.125.250.240", 3478, 679)],
        processes={helper_pid: ("Brave Browser Helper", BRAVE_HELPER)},
        bundles={BRAVE_HELPER: BRAVE_HELPER_BUNDLE},
    )


def zoom_native() -> Scenario:
    """The Zoom desktop client: a camera and microphone start, then a TCP socket to a server."""
    pid = 7001
    return Scenario(
        name="zoom_native",
        entries=[
            logs.cmio_camera(T0, pid, ZOOM_BINARY),
            logs.coreaudio_mic(T0 + 0.02, pid),
        ],
        sockets=[_socket(T0 + 0.3, pid, "170.114.52.2", 443, ZOOM_BINARY, "us.zoom.xos")],
    )


def screencapture_cmd_shift_5() -> Scenario:
    """A system screenshot (Cmd+Shift+5): the capturing Apple binary logs its own grant, and the
    socket it opens is a system binary's -- hidden unless --include-system."""
    pid = 9000
    return Scenario(
        name="screencapture",
        entries=[logs.screencapture(T0, pid)],
        sockets=[_socket(T0 + 0.1, pid, "17.253.144.10", 443, "/usr/sbin/screencapture", None)],
    )


def camera_then_curl_upload() -> Scenario:
    """An app reads the camera, then a helper it spawned (`curl`) uploads 450 ms later: the
    socket's owner is a different pid, linked back only by the process chain (M1.3). `curl` is a
    system binary, but the chain overrides the system-path filter for an accountable delegate,
    so this is caught without `include_system`."""
    app_pid, curl_pid = 4242, 5001
    return Scenario(
        name="camera_then_curl_upload",
        entries=[logs.cmio_camera(T0, app_pid, SPY_BINARY)],
        sockets=[_socket(T0 + 0.45, curl_pid, "203.0.113.9", 443, "/usr/bin/curl", None)],
    )


def photo_booth_system_app() -> Scenario:
    """Apple's Photo Booth using the camera then reaching the network: a system binary, so the
    access is hidden unless --include-system."""
    pid = 8100
    return Scenario(
        name="photo_booth",
        entries=[logs.tcc_access(T0, "Camera", pid, "com.apple.PhotoBooth", PHOTO_BOOTH)],
        sockets=[_socket(T0 + 0.2, pid, "17.253.144.10", 443, PHOTO_BOOTH, "com.apple.PhotoBooth")],
    )
