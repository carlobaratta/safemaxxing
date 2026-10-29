from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from conftest import T0, make_conn, make_event

from safemaxxing.menubar import (
    ICON_GLYPHS,
    IconState,
    MenuBarConfig,
    MenuModel,
    Update,
    menubar_available,
    pump_updates,
)
from safemaxxing.models import Alert, Finding, SensorType, Severity


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
