from __future__ import annotations

import shlex
import threading
import time
from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

from conftest import T0, make_conn, make_event

from safemaxxing.menubar import (
    ICON_GLYPHS,
    IconState,
    MenuBarConfig,
    MenuModel,
    Update,
    action_label,
    menubar_available,
    pump_updates,
    status_item_on_screen,
    tui_command,
)
from safemaxxing.models import ActionKind, ActionResult, Alert, Finding, SensorType, Severity


def make_alert(
    alert_id: int = 1,
    created_at: float = T0,
    severity: Severity = Severity.HIGH,
    sensors: frozenset[SensorType] | None = None,
    **conn: Any,
) -> Alert:
    finding = Finding(event=make_event(), connection=make_conn(**conn), delta_s=0.1)
    return Alert(
        id=alert_id,
        finding=finding,
        severity=severity,
        created_at=created_at,
        sensors=sensors if sensors is not None else frozenset({SensorType.CAMERA}),
    )


def test_icon_is_idle_initially() -> None:
    assert MenuModel().icon_state(now=T0) is IconState.IDLE


def test_sensor_in_use_then_decays_to_idle() -> None:
    model = MenuModel(MenuBarConfig(sensor_active_s=6.0))
    model.observe(make_event(timestamp=T0))
    assert model.icon_state(now=T0 + 1.0) is IconState.SENSOR
    assert model.active_sensors(now=T0 + 1.0) == {SensorType.CAMERA}
    assert model.icon_state(now=T0 + 7.0) is IconState.IDLE


def test_alert_takes_precedence_then_decays() -> None:
    model = MenuModel(MenuBarConfig(alert_active_s=20.0, sensor_active_s=6.0))
    model.observe(make_event(timestamp=T0))
    model.observe(make_alert(created_at=T0))
    assert model.icon_state(now=T0 + 1.0) is IconState.ALERT
    assert model.icon_state(now=T0 + 25.0) is IconState.IDLE


def test_alert_decays_to_sensor_while_a_sensor_is_still_active() -> None:
    model = MenuModel(MenuBarConfig(alert_active_s=20.0, sensor_active_s=6.0))
    model.observe(make_alert(created_at=T0))
    model.observe(make_event(timestamp=T0 + 20.0))
    assert model.icon_state(now=T0 + 21.0) is IconState.SENSOR


def test_recent_alerts_are_newest_first_and_capped() -> None:
    model = MenuModel(MenuBarConfig(recent_alerts=3))
    for i in range(5):
        model.observe(make_alert(alert_id=i, created_at=T0 + i, remote_address=f"198.51.100.{i}"))
    recent = model.recent_alerts()
    assert [r.id for r in recent] == [4, 3, 2]
    assert recent[0].remote_address == "198.51.100.4"


def test_reemitted_alert_replaces_rather_than_duplicates() -> None:
    model = MenuModel()
    model.observe(make_alert(alert_id=7, severity=Severity.HIGH))
    model.observe(make_alert(alert_id=7, severity=Severity.CRITICAL))
    (row,) = model.recent_alerts()
    assert row.severity is Severity.CRITICAL


def test_recent_alert_carries_its_action_targets() -> None:
    model = MenuModel()
    model.observe(make_alert(alert_id=1, pid=4242, remote_address="203.0.113.9"))
    (row,) = model.recent_alerts()
    assert row.pid == 4242
    assert row.remote_address == "203.0.113.9"


def test_blocked_ips_round_trip() -> None:
    model = MenuModel()
    assert model.blocked_ips() == ()
    model.set_blocked(["1.2.3.4", "5.6.7.8"])
    assert model.blocked_ips() == ("1.2.3.4", "5.6.7.8")


def test_a_connection_alone_does_not_change_the_icon() -> None:
    model = MenuModel()
    model.observe(make_conn(first_seen=T0))
    assert model.icon_state(now=T0) is IconState.IDLE


def test_toggles_default_off_and_every_icon_state_has_a_glyph() -> None:
    model = MenuModel()
    assert not model.auto_block
    assert not model.auto_suspend
    assert set(ICON_GLYPHS) == set(IconState)
    assert isinstance(menubar_available(), bool)


async def _updates(*items: Update, fail: Exception | None = None) -> AsyncIterator[Update]:
    for item in items:
        yield item
    if fail is not None:
        raise fail


async def test_pump_folds_updates_and_hands_alerts_to_the_callback() -> None:
    model = MenuModel()
    seen: list[int] = []

    async def on_alert(alert: Alert) -> None:
        seen.append(alert.id)

    await pump_updates(_updates(make_event(timestamp=T0), make_alert(alert_id=3)), model, on_alert)
    assert seen == [3]
    assert [r.id for r in model.recent_alerts()] == [3]


async def test_a_failed_stream_marks_the_model_stopped_over_any_alert() -> None:
    model = MenuModel()

    async def on_alert(_alert: Alert) -> None:
        return None

    stream = _updates(make_alert(created_at=T0), fail=RuntimeError("log stream exited"))
    await pump_updates(stream, model, on_alert)
    assert model.stopped_reason == "monitoring stopped: log stream exited"
    # Stopped outranks a fresh alert: the icon must never look healthy with no supervisor behind it.
    assert model.icon_state(now=T0) is IconState.STOPPED


async def test_a_stream_that_runs_dry_also_marks_the_model_stopped() -> None:
    model = MenuModel()

    async def on_alert(_alert: Alert) -> None:
        return None

    await pump_updates(_updates(), model, on_alert)
    assert model.stopped_reason is not None
    assert model.icon_state(now=T0) is IconState.STOPPED


async def test_a_failing_alert_action_is_reported_as_a_stop() -> None:
    model = MenuModel()

    async def on_alert(_alert: Alert) -> None:
        raise OSError("pfctl missing")

    await pump_updates(_updates(make_alert()), model, on_alert)
    assert model.stopped_reason == "monitoring stopped: pfctl missing"


def test_auto_actions_claim_each_alert_once_even_when_reemitted() -> None:
    model = MenuModel()
    assert model.claim_enforcement(make_alert(alert_id=1, severity=Severity.HIGH))
    # The same alert escalating must not re-run pfctl or re-signal the process.
    assert not model.claim_enforcement(make_alert(alert_id=1, severity=Severity.CRITICAL))
    assert model.claim_enforcement(make_alert(alert_id=2, severity=Severity.HIGH))


def test_a_low_alert_is_not_claimed_so_it_can_be_acted_on_once_it_escalates() -> None:
    model = MenuModel()
    assert not model.claim_enforcement(make_alert(alert_id=1, severity=Severity.MEDIUM))
    assert model.claim_enforcement(make_alert(alert_id=1, severity=Severity.HIGH))


def test_recent_actions_are_newest_first_and_capped() -> None:
    model = MenuModel(MenuBarConfig(recent_actions=2))
    for i in range(3):
        model.record_action(ActionResult(ActionKind.BLOCK_IP, f"198.51.100.{i}", True))
    assert [r.target for r in model.recent_actions()] == ["198.51.100.2", "198.51.100.1"]


def test_action_label_shows_why_an_action_failed() -> None:
    ok = ActionResult(ActionKind.BLOCK_IP, "203.0.113.9", True, "ignored on success")
    failed = ActionResult(ActionKind.SUSPEND, "4242", False, "permission denied (run as root)")
    assert action_label(ok) == "\u2713 block_ip 203.0.113.9"
    assert action_label(failed) == "\u2717 suspend 4242: permission denied (run as root)"


def test_glyphs_are_short_distinct_text_not_symbol_names() -> None:
    glyphs = list(ICON_GLYPHS.values())
    assert len(set(glyphs)) == len(glyphs)
    # rumps shows the title verbatim, so a name like "shield.idle" would appear as that text.
    assert all(len(g) <= 2 and "." not in g for g in glyphs)


def test_model_survives_concurrent_writes_and_reads() -> None:
    # The runner writes from its asyncio thread while the main thread reads; unlocked, this
    # raised "dictionary changed size during iteration" within a few milliseconds.
    model = MenuModel(MenuBarConfig(max_alerts=1_000_000))
    stop = threading.Event()

    def writer() -> None:
        i = 0
        while not stop.is_set():
            model.observe(make_alert(alert_id=i, created_at=T0 + i))
            i += 1

    thread = threading.Thread(target=writer)
    thread.start()
    errors: list[Exception] = []
    deadline = time.monotonic() + 0.5
    try:
        while time.monotonic() < deadline:
            try:
                model.icon_state(now=T0)
                model.recent_alerts()
            except RuntimeError as exc:
                errors.append(exc)
    finally:
        stop.set()
        thread.join()
    assert errors == []


def test_a_system_binarys_sensor_access_does_not_light_the_icon() -> None:
    model = MenuModel()
    model.observe(make_event(timestamp=T0, system=True, bundle_id=None, process_name="coreaudiod"))
    assert model.icon_state(now=T0) is IconState.IDLE


def test_an_indicator_event_counts_even_for_a_system_app() -> None:
    model = MenuModel()
    model.observe(make_event(timestamp=T0, system=True, service="indicator:camera"))
    assert model.icon_state(now=T0) is IconState.SENSOR


def test_include_system_counts_system_accesses_too() -> None:
    model = MenuModel(MenuBarConfig(include_system=True))
    model.observe(make_event(timestamp=T0, system=True))
    assert model.icon_state(now=T0) is IconState.SENSOR


def test_snapshot_is_stable_until_what_the_menu_shows_changes() -> None:
    model = MenuModel()
    first = model.snapshot(now=T0)
    assert model.snapshot(now=T0) == first
    model.observe(make_alert(alert_id=1, created_at=T0))
    after_alert = model.snapshot(now=T0)
    assert after_alert != first
    assert after_alert.title == ICON_GLYPHS[IconState.ALERT]
    model.record_action(ActionResult(ActionKind.BLOCK_IP, "203.0.113.9", True))
    after_action = model.snapshot(now=T0)
    assert after_action != after_alert
    model.auto_block = True
    assert model.snapshot(now=T0) != after_action


def test_snapshot_status_carries_the_stop_reason() -> None:
    model = MenuModel()
    model.mark_stopped("monitoring stopped: log stream exited")
    snap = model.snapshot(now=T0)
    assert snap.status == "monitoring stopped: log stream exited"
    assert snap.title == ICON_GLYPHS[IconState.STOPPED]


def _status_item(height: float, occlusion: int) -> Any:
    """A stand-in for NSStatusItem exposing only what `status_item_on_screen` reads."""
    window = SimpleNamespace(
        frame=lambda: SimpleNamespace(size=SimpleNamespace(height=height)),
        occlusionState=lambda: occlusion,
    )
    return SimpleNamespace(button=lambda: SimpleNamespace(window=lambda: window))


def test_a_laid_out_unoccluded_status_item_is_on_screen() -> None:
    assert status_item_on_screen(_status_item(height=24, occlusion=8194)) is True


def test_a_status_item_macos_hid_is_not_on_screen() -> None:
    # What a hidden item reports on a full menu bar (seen on macOS 27.0.1): no height, occluded.
    assert status_item_on_screen(_status_item(height=0, occlusion=8192)) is False
    assert status_item_on_screen(_status_item(height=24, occlusion=0)) is False


def test_an_unexpected_status_item_shape_is_undecided() -> None:
    assert status_item_on_screen(SimpleNamespace()) is None


def test_tui_command_uses_an_absolute_path_that_survives_the_shell() -> None:
    # The source checkout lives under a path with a space and an apostrophe.
    exe = "/Users/carlo/oak's projects/safemaxxing/.venv/bin/safemaxxing"
    assert shlex.split(tui_command(exe, euid=501)) == [exe, "tui"]


def test_tui_command_keeps_root_through_sudo() -> None:
    assert shlex.split(tui_command("/usr/local/bin/safemaxxing", euid=0)) == [
        "sudo",
        "/usr/local/bin/safemaxxing",
        "tui",
    ]
