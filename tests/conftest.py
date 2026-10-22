from __future__ import annotations

from typing import Any

from safemaxxing.models import Event, NetworkConnection, Protocol, SensorType

T0 = 1_700_000_000.0


def make_event(**overrides: Any) -> Event:
    fields: dict[str, Any] = {
        "timestamp": T0,
        "sensor": SensorType.CAMERA,
        "pid": 4242,
        "process_name": "spy",
        "bundle_id": "com.example.spy",
        "subsystem": "com.apple.TCC",
        "message": "test",
    }
    fields.update(overrides)
    return Event(**fields)


def make_conn(**overrides: Any) -> NetworkConnection:
    fields: dict[str, Any] = {
        "pid": 4242,
        "process_name": "spy",
        "protocol": Protocol.TCP,
        "local_address": "10.0.0.5",
        "local_port": 51544,
        "remote_address": "203.0.113.9",
        "remote_port": 443,
        "status": "ESTABLISHED",
        "first_seen": T0 + 0.1,
    }
    fields.update(overrides)
    return NetworkConnection(**fields)
