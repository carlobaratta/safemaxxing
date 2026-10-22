"""Immutable domain model shared by sensors, network monitor, correlation and UI."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import IntEnum, StrEnum


class SensorType(StrEnum):
    CAMERA = "camera"
    MICROPHONE = "microphone"
    LOCATION = "location"
    SCREEN_CAPTURE = "screen_capture"
    TCC = "tcc"


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


class ActionKind(StrEnum):
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    SUSPEND = "suspend"
    RESUME = "resume"
    KILL = "kill"


@dataclass(frozen=True, slots=True)
class Event:
    """A sensitive-resource access observed in the unified log."""

    timestamp: float
    sensor: SensorType
    pid: int | None
    process_name: str
    bundle_id: str | None
    subsystem: str
    message: str
    service: str | None = None

    @property
    def identity(self) -> str:
        return self.bundle_id or self.process_name or f"pid:{self.pid}"


@dataclass(frozen=True, slots=True)
class NetworkConnection:
    """An outbound socket owned by a process."""

    pid: int
    process_name: str
    protocol: Protocol
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    status: str
    first_seen: float
    exe_path: str | None = None
    bundle_id: str | None = None
    hostname: str | None = None

    @property
    def key(self) -> tuple[int, Protocol, str, int, str, int]:
        return (
            self.pid,
            self.protocol,
            self.local_address,
            self.local_port,
            self.remote_address,
            self.remote_port,
        )

    @property
    def remote(self) -> str:
        host = f"[{self.remote_address}]" if ":" in self.remote_address else self.remote_address
        return f"{host}:{self.remote_port}"

    @property
    def is_loopback(self) -> bool:
        try:
            return ipaddress.ip_address(self.remote_address).is_loopback
        except ValueError:
            return False


@dataclass(frozen=True, slots=True)
class Finding:
    """A sensor event causally linked to an outbound connection."""

    event: Event
    connection: NetworkConnection
    delta_s: float

    @property
    def key(self) -> tuple[float, SensorType, int, Protocol, str, int, str, int]:
        return (self.event.timestamp, self.event.sensor, *self.connection.key)


@dataclass(frozen=True, slots=True)
class Alert:
    id: int
    finding: Finding
    severity: Severity
    created_at: float

    @property
    def summary(self) -> str:
        ev, conn = self.finding.event, self.finding.connection
        destination = conn.hostname or conn.remote
        return (
            f"{ev.identity} used {ev.sensor.value} then connected to {destination} "
            f"after {self.finding.delta_s * 1000:.0f} ms"
        )


@dataclass(frozen=True, slots=True)
class ActionResult:
    kind: ActionKind
    target: str
    ok: bool
    detail: str = ""
