from __future__ import annotations

from simulator import logs, scenarios
from simulator.scenarios import T0, Scenario, replay

from safemaxxing.correlation import CorrelationConfig
from safemaxxing.models import SensorType, Severity


def test_brave_meet_raises_one_critical_alert_via_pktap() -> None:
    (alert,) = replay(scenarios.brave_meet())
    assert alert.severity is Severity.CRITICAL
    assert alert.sensors == {SensorType.CAMERA, SensorType.MICROPHONE}
    assert alert.finding.connection.remote == "74.125.250.240:3478"
    # The media socket is 188 ms behind the indicator.
    assert round(alert.finding.delta_s, 3) == 0.188


def test_zoom_native_raises_one_critical_alert_on_the_tcp_socket() -> None:
    (alert,) = replay(scenarios.zoom_native())
    assert alert.severity is Severity.CRITICAL
    assert alert.sensors == {SensorType.CAMERA, SensorType.MICROPHONE}
    assert alert.finding.connection.remote_port == 443


def test_screencapture_is_hidden_unless_system_is_included() -> None:
    scenario = scenarios.screencapture_cmd_shift_5()
    assert replay(scenario) == []
    (alert,) = replay(scenario, CorrelationConfig(include_system=True))
    assert alert.sensors == {SensorType.SCREEN_CAPTURE}


def test_camera_then_curl_upload_needs_both_chain_and_include_system() -> None:
    # curl (5001) owns the socket and is a different actor from the app (4242). Two things stand
    # between this and an alert: the process chain (to attribute curl's socket to the app) and
    # --include-system (because /usr/bin/curl is a system binary, so its socket is otherwise
    # dropped before correlation). Both are needed; neither alone suffices.
    scenario = scenarios.camera_then_curl_upload()
    chain = {5001: frozenset({5001, 4242})}
    assert replay(scenario) == []
    assert replay(scenario, actor_chain=chain) == []  # chain alone: curl's socket still filtered
    assert replay(scenario, CorrelationConfig(include_system=True)) == []  # system alone: no actor
    (alert,) = replay(scenario, CorrelationConfig(include_system=True), actor_chain=chain)
    assert alert.severity is Severity.HIGH
    assert alert.sensors == {SensorType.CAMERA}
    assert round(alert.finding.delta_s, 3) == 0.45


def test_photo_booth_system_app_is_hidden_unless_system_is_included() -> None:
    scenario = scenarios.photo_booth_system_app()
    assert replay(scenario) == []
    (alert,) = replay(scenario, CorrelationConfig(include_system=True))
    assert alert.sensors == {SensorType.CAMERA}


def test_background_noise_neither_creates_nor_suppresses_an_alert() -> None:
    # tccd manager checks, a coreaudiod preflight and a cmio backtrace around the real access
    # must leave exactly one critical alert.
    base = scenarios.zoom_native()
    noisy = Scenario(
        name="zoom_noisy",
        entries=[
            logs.tcc_manager_check(T0 - 0.01),
            *logs.coreaudio_preflight(T0 - 0.005, activity=77, client_pid=7001),
            logs.cmio_backtrace(T0 + 0.001, 7001, scenarios.ZOOM_BINARY),
            *base.entries,
        ],
        sockets=base.sockets,
    )
    (alert,) = replay(noisy)
    assert alert.severity is Severity.CRITICAL


def test_replay_is_deterministic() -> None:
    first = replay(scenarios.brave_meet())
    second = replay(scenarios.brave_meet())
    assert [a.summary for a in first] == [a.summary for a in second]
