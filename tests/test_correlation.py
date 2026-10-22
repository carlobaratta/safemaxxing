from __future__ import annotations

from conftest import T0, make_conn, make_event

from safemaxxing.correlation import CorrelationConfig, CorrelationEngine
from safemaxxing.models import SensorType, Severity


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
