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
    # Only screencapture's own TCC request, no indicator for it (Cmd+Shift+5 lights
    # `scr:com.apple.systemuiserver`): a permission request, so `tcc`.
    assert alert.sensors == {SensorType.TCC}


def test_camera_then_curl_upload_caught_by_the_process_chain() -> None:
    # curl (5001, /usr/bin/curl) owns the socket: a different actor from the app (4242) and a
    # system binary. Without the chain it is dropped. With the chain, the app that used the
    # camera is accountable for curl's socket, so it is caught -- the chain overrides the
    # system-path filter for an accountable delegate, no --include-system needed.
    scenario = scenarios.camera_then_curl_upload()
    assert replay(scenario) == []
    (alert,) = replay(scenario, actor_chain={5001: frozenset({5001, 4242})})
    assert alert.severity is Severity.HIGH
    assert alert.sensors == {SensorType.CAMERA}
    assert round(alert.finding.delta_s, 3) == 0.45


def test_photo_booth_system_app_is_hidden_unless_system_is_included() -> None:
    scenario = scenarios.photo_booth_system_app()
    assert replay(scenario) == []
    (alert,) = replay(scenario, CorrelationConfig(include_system=True))
    assert alert.sensors == {SensorType.CAMERA}
    assert alert.severity is Severity.HIGH


def test_a_permission_check_at_launch_is_only_a_medium_tcc_alert() -> None:
    # Before, the microphone and camera requests made this a critical camera+microphone alert,
    # and --auto-block (threshold high) blocked Spotify's server at every login.
    (alert,) = replay(scenarios.app_launch_permission_check())
    assert alert.sensors == {SensorType.TCC}
    assert alert.severity is Severity.MEDIUM


def test_a_request_followed_by_use_is_one_sensor_not_two() -> None:
    (alert,) = replay(scenarios.camera_request_then_use())
    assert alert.sensors == {SensorType.CAMERA}
    assert alert.severity is Severity.HIGH


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
