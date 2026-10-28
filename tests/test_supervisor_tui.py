from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import AsyncIterator
from pathlib import Path

from conftest import T0, make_conn, make_event
from test_pktap import MEET_OUT, fake_tcpdump, make_tracker

from safemaxxing.correlation import CorrelationConfig, CorrelationEngine
from safemaxxing.models import PKTAP_STATUS, Alert, Event, NetworkConnection
from safemaxxing.network import NetworkMonitor
from safemaxxing.pktap import PktapCapture, parse_pktap_line
from safemaxxing.supervisor import Supervisor


async def events_source(hold: bool = False) -> AsyncIterator[Event]:
    yield make_event()
    if hold:
        await asyncio.Event().wait()


async def conns_source(hold: bool = False) -> AsyncIterator[NetworkConnection]:
    await asyncio.sleep(0.01)
    yield make_conn()
    if hold:
        await asyncio.Event().wait()


def supervisor(hold: bool = False) -> Supervisor:
    engine = CorrelationEngine(CorrelationConfig(), clock=lambda: T0)
    return Supervisor(events_source(hold), conns_source(hold), engine)


async def test_supervisor_stream_yields_alert() -> None:
    updates = [u async for u in supervisor().stream()]
    alerts = [u for u in updates if isinstance(u, Alert)]
    assert len(alerts) == 1
    assert any(isinstance(u, Event) for u in updates)
    assert any(isinstance(u, NetworkConnection) for u in updates)


async def test_supervisor_propagates_source_errors() -> None:
    async def broken() -> AsyncIterator[Event]:
        raise FileNotFoundError("/usr/bin/log")
        yield make_event()

    sup = Supervisor(broken(), conns_source())
    try:
        async for _ in sup.stream():
            pass
    except FileNotFoundError:
        return
    raise AssertionError("expected FileNotFoundError")


async def no_conns() -> AsyncIterator[NetworkConnection]:
    return
    yield make_conn()


async def test_supervisor_alerts_on_pktap_flow(tmp_path: Path) -> None:
    packet = parse_pktap_line(MEET_OUT)
    assert packet is not None

    async def mic() -> AsyncIterator[Event]:
        yield make_event(timestamp=packet.timestamp - 1.1, pid=6254, bundle_id="com.brave.Browser")

    capture = PktapCapture(
        fake_tcpdump(tmp_path, f"print({MEET_OUT!r})\n"),
        tracker=make_tracker(),
        warmup_s=0,
        max_restarts=0,
    )
    engine = CorrelationEngine(CorrelationConfig(), clock=lambda: packet.timestamp)
    sup = Supervisor(mic(), no_conns(), engine, pktap=capture)
    alerts = [u async for u in sup.stream() if isinstance(u, Alert)]
    assert len(alerts) == 1
    conn = alerts[0].finding.connection
    assert (conn.status, conn.remote) == (PKTAP_STATUS, "74.125.250.240:3478")
    assert (capture.packets, capture.unparsed) == (1, 0)


def test_active_connections_merge_socket_table_and_pktap() -> None:
    packet = parse_pktap_line(MEET_OUT)
    assert packet is not None
    monitor = NetworkMonitor(snapshot=lambda now: [make_conn()])
    monitor.poll_once(T0)
    capture = PktapCapture(tracker=make_tracker(idle_s=1e12))
    capture.tracker.feed(packet)
    sup = Supervisor(events_source(), no_conns(), monitor=monitor, pktap=capture)
    statuses = sorted(c.status for c in sup.active_connections())
    assert statuses == ["ESTABLISHED", PKTAP_STATUS]


def test_active_connections_list_a_socket_seen_by_both_sources_once() -> None:
    packet = parse_pktap_line(MEET_OUT)
    assert packet is not None
    capture = PktapCapture(tracker=make_tracker(idle_s=1e12))
    flow = capture.tracker.feed(packet)
    assert flow is not None
    connected = dataclasses.replace(flow, status="NONE")
    monitor = NetworkMonitor(snapshot=lambda now: [connected])
    monitor.poll_once(T0)
    sup = Supervisor(events_source(), no_conns(), monitor=monitor, pktap=capture)
    assert [c.status for c in sup.active_connections()] == ["NONE"]


def test_default_supervisor_adds_pktap_only_on_request() -> None:
    config = CorrelationConfig(include_dns=True)
    assert Supervisor.default(config, resolve_hostnames=False).pktap is None
    sup = Supervisor.default(config, resolve_hostnames=False, udp_flows=True)
    assert sup.pktap is not None


def test_alert_json_lists_sensors() -> None:
    import json

    from safemaxxing.cli import _alert_json
    from safemaxxing.models import Alert, Finding, SensorType, Severity

    alert = Alert(
        1,
        Finding(make_event(), make_conn(), 0.0),
        Severity.HIGH,
        T0,
        frozenset({SensorType.CAMERA}),
    )
    payload = json.loads(_alert_json(alert))
    assert payload["sensors"] == ["camera"] and payload["severity"] == "high"
