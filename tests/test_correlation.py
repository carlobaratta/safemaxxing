from __future__ import annotations

from conftest import T0, make_conn, make_event

from safemaxxing.correlation import CorrelationConfig, CorrelationEngine
from safemaxxing.models import Protocol, SensorType, Severity


def engine(**config: object) -> CorrelationEngine:
    return CorrelationEngine(CorrelationConfig(**config), clock=lambda: T0)  # type: ignore[arg-type]


def test_event_then_connection_within_window() -> None:
    eng = engine()
    assert eng.ingest_event(make_event()) == []
    (alert,) = eng.ingest_connection(make_conn(first_seen=T0 + 0.12))
    assert alert.severity is Severity.HIGH
    assert round(alert.finding.delta_s, 3) == 0.12
    assert "com.example.spy used camera" in alert.summary


def test_connection_before_late_log_line() -> None:
    eng = engine()
    assert eng.ingest_connection(make_conn(first_seen=T0 + 0.2)) == []
    assert len(eng.ingest_event(make_event())) == 1


def test_outside_window_or_before_event() -> None:
    eng = engine(window_s=0.5)
    eng.ingest_event(make_event())
    assert eng.ingest_connection(make_conn(first_seen=T0 + 0.8)) == []
    assert eng.ingest_connection(make_conn(local_port=2, first_seen=T0 - 0.3)) == []


def test_clock_skew_tolerated() -> None:
    eng = engine(clock_skew_s=0.05)
    eng.ingest_event(make_event())
    (alert,) = eng.ingest_connection(make_conn(first_seen=T0 - 0.02))
    assert alert.finding.delta_s == 0.0


def test_different_process_does_not_match() -> None:
    eng = engine()
    eng.ingest_event(make_event())
    assert eng.ingest_connection(make_conn(pid=1, process_name="other")) == []


def test_bundle_match_covers_helper_processes() -> None:
    eng = engine()
    eng.ingest_event(make_event(pid=None, bundle_id="com.google.Chrome"))
    conn = make_conn(pid=999, bundle_id="com.google.Chrome.helper")
    assert len(eng.ingest_connection(conn)) == 1


def test_duplicate_and_cooldown_suppression() -> None:
    eng = engine(alert_cooldown_s=30)
    eng.ingest_event(make_event())
    assert len(eng.ingest_connection(make_conn())) == 1
    assert eng.ingest_connection(make_conn(local_port=2)) == []
    assert len(eng.ingest_connection(make_conn(local_port=3, remote_address="198.51.100.1"))) == 1


def test_multiple_sensors_escalate() -> None:
    eng = engine()
    eng.ingest_event(make_event(sensor=SensorType.MICROPHONE, timestamp=T0 - 0.3))
    eng.ingest_event(make_event())
    alerts = eng.ingest_connection(make_conn())
    assert alerts and all(a.severity is Severity.CRITICAL for a in alerts)


def test_tcc_generic_is_medium() -> None:
    eng = engine()
    eng.ingest_event(make_event(sensor=SensorType.TCC))
    (alert,) = eng.ingest_connection(make_conn())
    assert alert.severity is Severity.MEDIUM


def test_ignore_list() -> None:
    eng = engine(ignore=frozenset({"com.example.spy"}))
    eng.ingest_event(make_event())
    assert eng.ingest_connection(make_conn(bundle_id="com.example.spy")) == []


def test_old_items_evicted() -> None:
    eng = engine(window_s=0.5, late_arrival_s=1.0)
    eng.ingest_event(make_event())
    eng.ingest_event(make_event(pid=1, timestamp=T0 + 10))
    assert len(eng.events) == 1
    assert eng.ingest_connection(make_conn(first_seen=T0 + 0.1)) == []


def test_alert_ids_increment() -> None:
    eng = engine()
    eng.ingest_event(make_event())
    eng.ingest_event(make_event(pid=7, bundle_id=None, process_name="b"))
    a = eng.ingest_connection(make_conn())
    b = eng.ingest_connection(make_conn(pid=7, process_name="b"))
    assert [x.id for x in a + b] == [1, 2]


def test_one_access_from_three_sources_yields_one_alert() -> None:
    eng = engine()
    eng.ingest_event(make_event(pid=None, process_name="", bundle_id="com.example.spy"))
    eng.ingest_event(make_event(bundle_id=None, process_name=""))
    eng.ingest_event(make_event(bundle_id=None, process_name="spy"))
    alerts = eng.ingest_connection(make_conn(bundle_id="com.example.spy"))
    assert len(alerts) == 1


def test_system_binaries_ignored_by_default() -> None:
    from safemaxxing.models import is_system_path

    assert is_system_path(
        "/System/Library/PrivateFrameworks/CloudKitDaemon.framework/Support/cloudd"
    )
    assert is_system_path("/usr/libexec/apsd")
    assert not is_system_path("/usr/local/bin/spy")
    assert not is_system_path("/Applications/Spy.app/Contents/MacOS/Spy")
    assert not is_system_path(None)

    eng = engine()
    eng.ingest_event(make_event())
    assert eng.ingest_connection(make_conn(exe_path="/usr/libexec/apsd")) == []
    assert (
        len(
            eng.ingest_connection(
                make_conn(local_port=2, exe_path="/Applications/Spy.app/Contents/MacOS/Spy")
            )
        )
        == 1
    )


def test_include_system_opt_in() -> None:
    eng = engine(include_system=True)
    eng.ingest_event(make_event())
    assert len(eng.ingest_connection(make_conn(exe_path="/usr/libexec/apsd"))) == 1


def test_dns_lookups_do_not_alert_by_default() -> None:
    eng = engine()
    eng.ingest_event(make_event())
    assert eng.ingest_connection(make_conn(remote_address="10.128.132.57", remote_port=53)) == []
    assert len(eng.ingest_connection(make_conn(local_port=2, remote_port=443))) == 1
    eng = engine(include_dns=True)
    eng.ingest_event(make_event())
    assert len(eng.ingest_connection(make_conn(remote_port=53))) == 1


def test_system_events_not_correlated_by_default() -> None:
    eng = engine()
    eng.ingest_event(make_event(system=True))
    assert eng.ingest_connection(make_conn()) == []
    eng = engine(include_system=True)
    eng.ingest_event(make_event(system=True))
    assert len(eng.ingest_connection(make_conn())) == 1


def test_brave_meet_timeline_merges_into_one_critical_alert() -> None:
    # macOS 27.0.1: mic permission check, media socket 1119 ms later, camera line ~0 ms after it.
    eng = CorrelationEngine(clock=lambda: T0)  # default window
    brave = {"pid": None, "process_name": "", "bundle_id": "com.brave.Browser"}
    conn = make_conn(
        pid=3293,
        bundle_id="com.brave.Browser",
        remote_address="74.125.250.135",
        remote_port=19305,
        protocol=Protocol.UDP,
        first_seen=T0 + 1.119,
    )
    assert eng.ingest_event(make_event(sensor=SensorType.MICROPHONE, **brave)) == []
    (first,) = eng.ingest_connection(conn)
    assert first.sensors == {SensorType.MICROPHONE} and first.severity is Severity.HIGH
    assert not first.updated
    (merged,) = eng.ingest_event(
        make_event(sensor=SensorType.CAMERA, timestamp=T0 + 1.139, **brave)
    )
    assert merged.id == first.id and merged.updated
    assert merged.sensors == {SensorType.MICROPHONE, SensorType.CAMERA}
    assert merged.severity is Severity.CRITICAL
    assert "used camera+microphone" in merged.summary
    assert eng.ingest_event(make_event(sensor=SensorType.CAMERA, timestamp=T0 + 1.2, **brave)) == []


def test_sensor_logged_just_after_socket_counts_for_severity() -> None:
    eng = engine()
    eng.ingest_event(make_event(sensor=SensorType.MICROPHONE))
    eng.ingest_event(make_event(timestamp=T0 + 0.12))  # camera, 20 ms after the socket
    (alert,) = eng.ingest_connection(make_conn(first_seen=T0 + 0.1))
    assert alert.severity is Severity.CRITICAL


def test_merged_alert_sensors_all_enter_cooldown() -> None:
    eng = engine()
    eng.ingest_event(make_event(sensor=SensorType.MICROPHONE))
    eng.ingest_event(make_event())
    assert len(eng.ingest_connection(make_conn())) == 1
    assert eng.ingest_connection(make_conn(local_port=9)) == []


def test_indicator_events_correlate_even_when_marked_system() -> None:
    # An indicator event's system flag comes from a bundle id, which any app can claim, so it
    # only hides the event from display. The genuine Apple app's sockets are system and
    # dropped anyway; a non-system socket with that bundle id is exactly the spoof to catch.
    indicator = make_event(
        pid=None,
        process_name="",
        bundle_id="com.apple.PhotoBooth",
        subsystem="com.apple.controlcenter",
        service="indicator:cam",
        system=True,
    )
    eng = engine()
    eng.ingest_event(indicator)
    genuine = make_conn(
        bundle_id="com.apple.PhotoBooth",
        exe_path="/System/Applications/Photo Booth.app/Contents/MacOS/Photo Booth",
    )
    assert eng.ingest_connection(genuine) == []
    spoof = make_conn(
        local_port=2,
        bundle_id="com.apple.PhotoBooth",
        exe_path="/Users/u/Applications/Photo Booth.app/Contents/MacOS/Photo Booth",
    )
    assert len(eng.ingest_connection(spoof)) == 1
    # A path-based system event (log metadata) is still ignored.
    eng = engine()
    eng.ingest_event(make_event(system=True))
    assert eng.ingest_connection(make_conn()) == []
