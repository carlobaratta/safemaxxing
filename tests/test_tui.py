from __future__ import annotations

import asyncio
import dataclasses
import io
from collections.abc import Callable, Sequence

import pytest
from conftest import T0, make_conn, make_event
from rich.console import Console, ConsoleRenderable
from rich.text import Text
from test_firewall import FakePf
from test_supervisor_tui import supervisor
from textual.pilot import Pilot
from textual.widgets import DataTable, Static

from safemaxxing.codesign import parse_codesign, signing_identity, signing_target
from safemaxxing.correlation import CorrelationConfig
from safemaxxing.firewall import CommandResult, PfFirewall, ProcessController
from safemaxxing.models import PKTAP_STATUS, Alert, Finding, SensorType, Severity
from safemaxxing.tui.app import SafemaxxingApp
from safemaxxing.tui.badges import mitigation_badges, sensor_pills, severity_badge
from safemaxxing.tui.panels import (
    PfStatus,
    RuntimeStats,
    Selection,
    render_firewall,
    render_inspector,
    render_status,
)
from safemaxxing.tui.screens import TimelineScreen
from safemaxxing.tui.timeline import MAX_EVENTS, merge_events, related_events, timeline_steps

BRAVE_CODESIGN = """\
Executable=/Applications/Brave Browser.app/Contents/MacOS/Brave Browser
Identifier=com.brave.Browser
Authority=Developer ID Application: Brave Software, Inc. (KL8N8XSYF4)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=KL8N8XSYF4
"""


def plain(renderable: object) -> str:
    assert isinstance(renderable, ConsoleRenderable | str), renderable
    console = Console(width=120, record=True, color_system=None, file=io.StringIO())
    console.print(renderable)
    return console.export_text()


# --- badges ---------------------------------------------------------------------------------


def test_severity_badges_line_up() -> None:
    widths = {severity_badge(s).cell_len for s in Severity}
    assert widths == {len(" CRITICAL ")}
    assert severity_badge(Severity.HIGH).plain.strip() == "HIGH"


def test_sensor_pills_are_distinct_and_ordered() -> None:
    pills = sensor_pills([SensorType.MICROPHONE, SensorType.CAMERA, SensorType.MICROPHONE])
    assert pills.plain.split() == ["CAM", "MIC"]
    assert sensor_pills([]).plain == ""


def test_mitigation_badges() -> None:
    assert mitigation_badges(False, False).plain == ""
    assert mitigation_badges(True, True).plain.split() == ["BLOCKED", "SUSPENDED"]


# --- timeline -------------------------------------------------------------------------------


def test_related_events_use_the_engine_window_and_actor() -> None:
    conn = make_conn(first_seen=T0 + 1.0)
    inside = make_event(timestamp=T0)
    too_early = make_event(timestamp=T0 + 1.0 - 2.5)
    skewed = make_event(timestamp=T0 + 1.02, sensor=SensorType.MICROPHONE)
    other = make_event(timestamp=T0, pid=1, bundle_id="com.example.other", process_name="x")
    found = related_events(conn, [skewed, other, too_early, inside], CorrelationConfig())
    assert found == (inside, skewed)


def test_timeline_ends_with_the_egress_and_merges_snapshots() -> None:
    tcc = make_event(timestamp=T0, service="kTCCServiceCamera")
    cmio = make_event(timestamp=T0 + 0.042, subsystem="com.apple.cmio", service=None)
    indicator = make_event(
        timestamp=T0 + 0.05, sensor=SensorType.MICROPHONE, service="indicator:mic"
    )
    conn = make_conn(first_seen=T0 + 0.188, status=PKTAP_STATUS, hostname="relay.example")
    steps = timeline_steps(conn, merge_events([cmio, tcc], [tcc, indicator]))
    assert [s.source for s in steps] == ["tcc", "cmio", "indicator", "pktap"]
    assert [round((s.timestamp - T0) * 1000) for s in steps] == [0, 42, 50, 188]
    assert steps[-1].egress and "relay.example" in steps[-1].detail
    many = [make_event(timestamp=T0 + i) for i in range(MAX_EVENTS + 10)]
    assert len(merge_events(many, [])) == MAX_EVENTS


# --- codesign -------------------------------------------------------------------------------


def test_parse_codesign() -> None:
    assert parse_codesign(BRAVE_CODESIGN, 0) == (
        "Developer ID Application: Brave Software, Inc. (KL8N8XSYF4)"
    )
    assert parse_codesign("/tmp/x: code object is not signed at all\n", 1) == "unsigned"
    assert parse_codesign("Identifier=a.out\nSignature=adhoc\n", 0) == "ad-hoc"
    assert parse_codesign("/tmp: bundle format unrecognized\n", 1) == "unknown"


def test_signing_target_is_the_outermost_app() -> None:
    helper = (
        "/Applications/Brave Browser.app/Contents/Frameworks/Brave Browser Framework.framework/"
        "Helpers/Brave Browser Helper.app/Contents/MacOS/Brave Browser Helper"
    )
    assert signing_target(helper) == "/Applications/Brave Browser.app"
    assert signing_target("/usr/local/bin/tool") == "/usr/local/bin/tool"


async def test_signing_identity_runs_codesign_and_times_out() -> None:
    seen: list[list[str]] = []

    async def runner(argv: Sequence[str], stdin: str | None = None) -> CommandResult:
        seen.append(list(argv))
        return CommandResult(0, "", BRAVE_CODESIGN)

    exe = "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
    assert (await signing_identity(exe, runner)).startswith("Developer ID Application")
    assert seen == [["/usr/bin/codesign", "-dv", "--verbose=2", "/Applications/Brave Browser.app"]]

    async def hung(argv: Sequence[str], stdin: str | None = None) -> CommandResult:
        await asyncio.sleep(5)
        raise AssertionError("not reached")

    assert await signing_identity(exe, hung, timeout_s=0.01) == "unknown"


# --- panels ---------------------------------------------------------------------------------


def test_firewall_panel_states() -> None:
    stats = RuntimeStats(poll_ms=12, poll_interval_ms=200, sockets=40, dns_entries=7)
    text = plain(render_firewall(PfStatus(True, True, ("203.0.113.9",)), stats))
    assert "ENABLED" in text and "ACTIVE" in text and "1 IP" in text
    assert "12 ms / 200 ms · 40 sockets" in text and "off (--udp-flows)" in text
    assert "7 entries" in text
    text = plain(render_firewall(PfStatus(None, None, error="needs root"), RuntimeStats()))
    assert "needs root" in text and "starting" in text and "off (--no-dns)" in text
    capturing = dataclasses.replace(stats, pktap=True, pktap_packets_per_s=151, pktap_restarts=2)
    assert "CAPTURING 151 pkt/s · 2 restarts" in plain(render_firewall(None, capturing))


def test_status_bar_shows_udp_rates_only_with_pktap() -> None:
    stats = RuntimeStats(cpu_percent=0.5, events_per_s=3, alerts=2, dns_entries=128)
    line = render_status(stats).plain
    assert "LIVE" in line and "CPU 0.5%" in line and "DNS 128" in line and "alerts 2" in line
    assert "UDP" not in line
    stopped = dataclasses.replace(stats, pktap=True, pktap_flows_per_s=0.25, live=False)
    assert (
        "STOPPED" in render_status(stopped).plain and "0.2 flows/s" in render_status(stopped).plain
    )


def test_inspector_lists_process_signature_and_sensors() -> None:
    conn = make_conn(exe_path="/Applications/Spy.app/Contents/MacOS/spy", bundle_id="com.ex.spy")
    alert = Alert(
        7,
        Finding(make_event(), conn, 0.087),
        Severity.CRITICAL,
        T0,
        frozenset({SensorType.CAMERA, SensorType.MICROPHONE}),
    )
    text = plain(render_inspector(Selection(conn, alert, (make_event(),)), "unsigned", True, False))
    for expected in (
        "alert #7",
        "pid",
        "4242",
        "com.ex.spy",
        "unsigned",
        "BLOCKED",
        "CAM",
        "87 ms",
    ):
        assert expected in text
    assert "Select an alert" in plain(render_inspector(None, None, False, False))


# --- app ------------------------------------------------------------------------------------


async def wait_for(pilot: Pilot[None], condition: Callable[[], bool]) -> None:
    for _ in range(100):
        if condition():
            return
        await pilot.pause(0.02)
    raise AssertionError("condition not met")


def make_app(
    pf: FakePf | None = None,
    signals: list[tuple[int, int]] | None = None,
    root: bool = False,
) -> SafemaxxingApp:
    sent = signals if signals is not None else []

    async def signer(path: str) -> str:
        return "Developer ID Application: Example (TEAM)"

    return SafemaxxingApp(
        supervisor(hold=True),
        firewall=PfFirewall(runner=pf or FakePf(enabled=True)),
        processes=ProcessController(kill=lambda pid, sig: sent.append((pid, sig))),
        signer=signer,
        root=lambda: root,
    )


def cell(table: DataTable[object], row: str, column: str) -> str:
    value = table.get_cell(row, column)
    return value.plain if isinstance(value, Text) else str(value)


async def test_tui_shows_alert_and_enforces() -> None:
    pf = FakePf(enabled=True)
    signals: list[tuple[int, int]] = []
    app = make_app(pf, signals)
    async with app.run_test() as pilot:
        await wait_for(pilot, lambda: bool(app.alerts))
        table = app.query_one("#feed", DataTable)
        assert table.row_count == 1
        assert app.selection is not None and app.selection.alert is not None
        assert "CAM" in cell(table, "1", "sensors") and "HIGH" in cell(table, "1", "sev")
        await pilot.press("b")
        await pilot.pause()
        assert pf.table == {"203.0.113.9"}
        await pilot.press("s")
        await pilot.pause()
        assert cell(table, "1", "state").split() == ["BLK", "STOP"]
        await pilot.press("k")
        await pilot.click("#yes")
        await pilot.pause()
        assert [pid for pid, _ in signals] == [4242, 4242]
        assert app.suspended == set()
        await pilot.press("c")
        assert table.row_count == 0 and app.selection is None


async def test_tui_updates_merged_alert_in_place() -> None:
    finding = Finding(make_event(sensor=SensorType.MICROPHONE), make_conn(), 0.1)
    first = Alert(1, finding, Severity.HIGH, T0, frozenset({SensorType.MICROPHONE}))
    merged = dataclasses.replace(
        first,
        sensors=frozenset({SensorType.MICROPHONE, SensorType.CAMERA}),
        severity=Severity.CRITICAL,
        updated=True,
    )
    app = make_app()
    async with app.run_test() as pilot:
        await wait_for(pilot, lambda: bool(app.alerts))
        app.action_clear_feed()
        app.add_alert(first)
        app.add_alert(merged)
        table = app.query_one("#feed", DataTable)
        assert table.row_count == 1
        assert cell(table, "1", "sensors").split() == ["CAM", "MIC"]
        assert "CRITICAL" in cell(table, "1", "sev")
        assert app.alerts["1"].severity is Severity.CRITICAL


async def test_filter_hides_rows_and_swallows_action_keys() -> None:
    pf = FakePf(enabled=True)
    signals: list[tuple[int, int]] = []
    app = make_app(pf, signals)
    async with app.run_test() as pilot:
        await wait_for(pilot, lambda: bool(app.alerts))
        table = app.query_one("#feed", DataTable)
        await pilot.press("slash", *"bsk")
        await pilot.pause()
        assert app.filter_text == "bsk" and table.row_count == 0
        assert pf.table == set() and signals == []
        await pilot.press("escape")
        assert app.filter_text == "" and table.row_count == 1
        await pilot.press("slash", *"spy", "enter")
        await pilot.pause()
        assert table.row_count == 1 and table.has_focus
        assert "spy" in str(app.query_one("#feed-pane").border_subtitle)


async def test_enter_opens_the_timeline() -> None:
    app = make_app()
    async with app.run_test() as pilot:
        await wait_for(pilot, lambda: bool(app.alerts))
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, TimelineScreen)
        text = plain(app.screen.query_one("#timeline Static", Static).content)
        assert "+0 ms" in text and "+100 ms" in text and "EGRESS" in text
        await pilot.press("escape")
        assert not isinstance(app.screen, TimelineScreen)
        await pilot.press("space")
        assert isinstance(app.screen, TimelineScreen)


async def test_firewall_poll_marks_blocked_rows_and_signature_is_shown() -> None:
    pf = FakePf(enabled=True)
    pf.anchor_rules = "block drop out quick from any to <safemaxxing_block>\n"
    pf.table = {"203.0.113.9"}
    app = make_app(pf, root=True)
    async with app.run_test() as pilot:
        await wait_for(pilot, lambda: bool(app.alerts) and app.pf_status is not None)
        assert app.pf_status == PfStatus(True, True, ("203.0.113.9",))
        app.tick()
        table = app.query_one("#feed", DataTable)
        assert cell(table, "1", "state") == " BLK "


async def test_inspector_reads_the_signature_once() -> None:
    calls: list[str] = []

    async def signer(path: str) -> str:
        calls.append(path)
        return "Software Signing"

    exe = "/Applications/Spy.app/Contents/MacOS/spy"
    app = make_app()
    app._signer = signer
    async with app.run_test() as pilot:
        await wait_for(pilot, lambda: bool(app.alerts))
        alert = app.alerts["1"]
        conn = dataclasses.replace(alert.finding.connection, exe_path=exe)
        app.add_alert(
            dataclasses.replace(alert, finding=dataclasses.replace(alert.finding, connection=conn))
        )
        app.query_one("#feed", DataTable).move_cursor(row=0)
        app._select_from(app.query_one("#feed", DataTable))
        await wait_for(pilot, lambda: bool(calls))
        app._select_from(app.query_one("#feed", DataTable))
        await pilot.pause()
        assert calls == [exe]
        assert "Software Signing" in plain(app.query_one("#inspector", Static).content)


async def test_timers_firing_during_shutdown_do_not_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    # Textual stops the app's timers only after removing its screens; on a slow runner
    # (macos-15-intel, 2026-10-28) `tick` and `flush_log` fired in between.
    app = make_app()
    close_all = app._close_all

    async def close_then_tick() -> None:
        await close_all()
        app.log_line(Text("late line"))
        app.tick()
        app.flush_log()

    async with app.run_test() as pilot:
        await wait_for(pilot, lambda: bool(app.alerts))
        monkeypatch.setattr(app, "_close_all", close_then_tick)
