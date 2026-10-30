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


def test_child_socket_attributes_to_parent_via_chain() -> None:
    # The app (pid 300) used the camera; the socket is owned by a helper it spawned (pid 501,
    # "curl"), a different pid, name and bundle. Only the actor chain links the two.
    chains = {501: frozenset({501, 412, 300})}
    eng = CorrelationEngine(
        CorrelationConfig(),
        clock=lambda: T0,
        actor_chain=lambda pid: chains.get(pid, frozenset({pid})),
    )
    eng.ingest_event(make_event(pid=300, bundle_id=None, process_name="app"))
    conn = make_conn(pid=501, process_name="curl", bundle_id=None, first_seen=T0 + 0.1)
    (alert,) = eng.ingest_connection(conn)
    assert alert.severity is Severity.HIGH


def test_chain_does_not_match_unrelated_process() -> None:
    eng = CorrelationEngine(
        CorrelationConfig(),
        clock=lambda: T0,
        actor_chain=lambda pid: frozenset({pid}),
    )
    eng.ingest_event(make_event(pid=300, bundle_id=None, process_name="app"))
    conn = make_conn(pid=501, process_name="curl", bundle_id=None, first_seen=T0 + 0.1)
    assert eng.ingest_connection(conn) == []


def test_decay_window_late_connection_still_alerts_at_lower_severity() -> None:
    # Camera (high) at T0; the upload opens 2.0 s later, past the 0.5 s hard window but inside
    # the 5.0 s decay window. It still correlates, one step down (medium), flagged late.
    eng = engine(window_s=0.5, decay_window_s=5.0)
    eng.ingest_event(make_event(sensor=SensorType.CAMERA))
    (alert,) = eng.ingest_connection(make_conn(first_seen=T0 + 2.0))
    assert alert.severity is Severity.MEDIUM
    assert alert.finding.late
    assert 0.0 < alert.finding.weight < 1.0


def test_decay_weight_fades_with_delay() -> None:
    eng = engine(window_s=0.5, decay_window_s=5.0)
    eng.ingest_event(make_event())
    (near,) = eng.ingest_connection(
        make_conn(local_port=10, remote_address="198.51.100.1", first_seen=T0 + 1.0)
    )
    (far,) = eng.ingest_connection(
        make_conn(local_port=11, remote_address="198.51.100.2", first_seen=T0 + 4.0)
    )
    assert near.finding.weight > far.finding.weight


def test_beyond_decay_window_no_match() -> None:
    eng = engine(window_s=0.5, decay_window_s=5.0)
    eng.ingest_event(make_event())
    assert eng.ingest_connection(make_conn(first_seen=T0 + 6.0)) == []


def test_in_hard_window_is_full_severity_with_decay_enabled() -> None:
    eng = engine(window_s=0.5, decay_window_s=5.0)
    eng.ingest_event(make_event(sensor=SensorType.CAMERA))
    (alert,) = eng.ingest_connection(make_conn(first_seen=T0 + 0.3))
    assert alert.severity is Severity.HIGH
    assert not alert.finding.late


def test_in_window_sensor_keeps_full_severity_despite_a_late_one() -> None:
    # A late microphone match and an in-window camera match on the same connection: the
    # in-window one keeps it at full strength, and two sensors bump it to critical.
    eng = engine(window_s=0.5, decay_window_s=5.0)
    eng.ingest_event(make_event(sensor=SensorType.MICROPHONE, timestamp=T0 - 1.6))
    eng.ingest_event(make_event(sensor=SensorType.CAMERA, timestamp=T0))
    (alert,) = eng.ingest_connection(make_conn(first_seen=T0 + 0.3))
    assert alert.severity is Severity.CRITICAL


def test_pktap_syn_and_socket_poll_of_one_flow_alert_once() -> None:
    # The same TCP flow reaches the engine twice: pktap's SYN (early, accurate) and the socket
    # poll (up to a poll late). One alert, keeping the earlier SYN timing -- no duplicate.
    eng = engine()
    eng.ingest_event(make_event())
    syn = make_conn(status="PKTAP", first_seen=T0 + 0.02)
    polled = make_conn(status="ESTABLISHED", first_seen=T0 + 0.15)
    alerts = eng.ingest_connection(syn) + eng.ingest_connection(polled)
    assert len(alerts) == 1
    assert round(alerts[0].finding.delta_s, 3) == 0.02


def _chain_engine(chains: dict[int, frozenset[int]]) -> CorrelationEngine:
    return CorrelationEngine(
        CorrelationConfig(),
        clock=lambda: T0,
        actor_chain=lambda pid: chains.get(pid, frozenset({pid})),
    )


def test_system_delegate_socket_caught_via_chain_without_include_system() -> None:
    # The app (4242, non-system) used the camera; the upload is owned by /usr/bin/curl (5001),
    # a system binary. The chain attributes it, so it alerts even with include_system off.
    eng = _chain_engine({5001: frozenset({5001, 4242})})
    eng.ingest_event(make_event(pid=4242, bundle_id=None, process_name="app"))
    conn = make_conn(pid=5001, process_name="curl", exe_path="/usr/bin/curl", first_seen=T0 + 0.1)
    (alert,) = eng.ingest_connection(conn)
    assert alert.severity is Severity.HIGH


def test_system_socket_without_an_accountable_sensor_user_is_dropped() -> None:
    # nsurlsessiond's socket with no accountable sensor user stays Apple's own traffic: dropped.
    eng = _chain_engine({5001: frozenset({5001})})
    eng.ingest_event(make_event(pid=4242, bundle_id=None, process_name="app"))
    conn = make_conn(
        pid=5001,
        process_name="nsurlsessiond",
        exe_path="/usr/libexec/nsurlsessiond",
        first_seen=T0 + 0.1,
    )
    assert eng.ingest_connection(conn) == []


def test_system_socket_dropped_when_attribution_disabled() -> None:
    # Backward compatible: with no actor chain, a system-path socket is dropped as before.
    eng = engine()
    eng.ingest_event(make_event(pid=4242, bundle_id=None, process_name="app"))
    conn = make_conn(pid=5001, exe_path="/usr/bin/curl", first_seen=T0 + 0.1)
    assert eng.ingest_connection(conn) == []


def test_a_tcc_alert_becomes_the_sensor_its_indicator_shows() -> None:
    # A camera request first (tcc, medium), then the indicator a few ms after the socket.
    eng = CorrelationEngine(clock=lambda: T0)
    assert eng.ingest_event(make_event(sensor=SensorType.TCC, service="Camera")) == []
    (first,) = eng.ingest_connection(make_conn())
    assert first.sensors == {SensorType.TCC} and first.severity is Severity.MEDIUM
    indicator = make_event(sensor=SensorType.CAMERA, pid=None, timestamp=T0 + 0.12)
    (merged,) = eng.ingest_event(indicator)
    assert merged.id == first.id and merged.updated
    assert merged.sensors == {SensorType.CAMERA}
    assert merged.severity is Severity.HIGH
    # Another request for the same connection adds nothing once use is known.
    assert eng.ingest_event(make_event(sensor=SensorType.TCC, timestamp=T0 + 0.13)) == []
