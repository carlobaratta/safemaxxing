"""Immutable domain model shared by sensors, network monitor, correlation and UI."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum

# SIP-protected locations: binaries here can only come from Apple.
SYSTEM_PREFIXES = ("/System/", "/usr/", "/bin/", "/sbin/")


def is_system_path(path: str | None) -> bool:
    """Whether `path` is an Apple-only binary location; `/usr/local/` is user-installed."""
    if not path or path.startswith("/usr/local/"):
        return False
    return path.startswith(SYSTEM_PREFIXES)


class SensorType(StrEnum):
    """Kind of sensitive resource being accessed; `TCC` covers other TCC-gated services."""

    CAMERA = "camera"
    MICROPHONE = "microphone"
    LOCATION = "location"
    SCREEN_CAPTURE = "screen_capture"
    TCC = "tcc"


class Protocol(StrEnum):
    """Transport protocol of a socket."""

    TCP = "tcp"
    UDP = "udp"


class Direction(StrEnum):
    """Direction of a packet relative to this host, as pktap's metadata reports it."""

    OUTBOUND = "out"
    INBOUND = "in"


class Severity(IntEnum):
    """Alert level; ordered so levels compare and can be bumped with integer arithmetic."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """Lower-case level name, e.g. `high`."""
        return self.name.lower()


class ActionKind(StrEnum):
    """Response action that can be taken on an alert: network block or process control."""

    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    SUSPEND = "suspend"
    RESUME = "resume"
    KILL = "kill"
    LOCKDOWN_ON = "lockdown_on"
    LOCKDOWN_OFF = "lockdown_off"


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
    # Set only from paths (log metadata, tccd's binary_path, the running binaries behind an
    # indicator's bundle id), never from a bundle id alone, which an app can choose freely.
    system: bool = False

    @property
    def identity(self) -> str:
        """Best display name: bundle id, else process name, else `pid:<n>`."""
        return self.bundle_id or self.process_name or f"pid:{self.pid}"

    @property
    def from_indicator(self) -> bool:
        """Whether Control Center's sensor indicator reported it: its identity is a bundle id."""
        return self.service is not None and self.service.startswith("indicator:")


@dataclass(frozen=True, slots=True)
class IndicatorState:
    """Control Center's full set of sensor attributions after a change, as (sensor, bundle id).

    Unlike `Event`, which fires once when a use starts, this also reports a use ending: the
    lockdown leases need the off edge to start their grace period. It is not merged across
    flicker; the lease grace (longer than `INDICATOR_MERGE_S`) absorbs that.
    """

    timestamp: float
    active: frozenset[tuple[SensorType, str]]

    def bundles(self, sensors: frozenset[SensorType]) -> frozenset[str]:
        """Bundle ids holding any of `sensors`."""
        return frozenset(bundle for sensor, bundle in self.active if sensor in sensors)


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
        """Socket identity (pid, protocol and both endpoints), independent of first_seen."""
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
        """Remote endpoint as `host:port`, bracketing IPv6 addresses."""
        host = f"[{self.remote_address}]" if ":" in self.remote_address else self.remote_address
        return f"{host}:{self.remote_port}"

    @property
    def is_loopback(self) -> bool:
        """Whether the remote address is a loopback IP; hostnames and bad addresses are not."""
        try:
            return ipaddress.ip_address(self.remote_address).is_loopback
        except ValueError:
            return False


@dataclass(frozen=True, slots=True)
class PktapEvent:
    """One packet seen on a pktap interface, with the kernel's per-packet process metadata.

    `pid` is the socket owner; `process_name` is the kernel's name, cut to 16 characters
    ("Brave Browser He"). `effective_pid` is set when the socket acts on another process's
    behalf (pktap's `eproc`).
    """

    timestamp: float
    interface: str
    pid: int
    process_name: str
    protocol: Protocol
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    direction: Direction
    length: int = 0
    effective_pid: int | None = None
    effective_process_name: str | None = None

    @property
    def flow_key(self) -> tuple[int, Protocol, str, int, str, int]:
        """(pid, protocol, local and remote endpoints) of the flow, the same shape as
        `NetworkConnection.key`; an inbound packet is keyed from this host's side."""
        if self.direction is Direction.OUTBOUND:
            return (
                self.pid,
                self.protocol,
                self.src_ip,
                self.src_port,
                self.dest_ip,
                self.dest_port,
            )
        return (self.pid, self.protocol, self.dest_ip, self.dest_port, self.src_ip, self.src_port)

    def to_connection(
        self,
        process_name: str | None = None,
        exe_path: str | None = None,
        bundle_id: str | None = None,
    ) -> NetworkConnection:
        """The flow as a `NetworkConnection` first seen at this packet, so the correlation
        engine treats it like a socket from the table; `process_name` replaces the cut name."""
        _, protocol, local_ip, local_port, remote_ip, remote_port = self.flow_key
        return NetworkConnection(
            pid=self.pid,
            process_name=process_name or self.process_name,
            protocol=protocol,
            local_address=local_ip,
            local_port=local_port,
            remote_address=remote_ip,
            remote_port=remote_port,
            status=PKTAP_STATUS,
            first_seen=self.timestamp,
            exe_path=exe_path,
            bundle_id=bundle_id,
        )


# `NetworkConnection.status` of flows seen by pktap rather than in the socket table.
PKTAP_STATUS = "PKTAP"


@dataclass(frozen=True, slots=True)
class Finding:
    """A sensor event causally linked to an outbound connection.

    `weight` is the confidence the link is real, from the delay between the two: 1.0 inside
    the hard correlation window, decaying toward 0.0 across the adaptive decay window (a late
    upload after a local recording). It is 1.0 whenever decay is disabled.
    """

    event: Event
    connection: NetworkConnection
    delta_s: float
    weight: float = 1.0

    @property
    def late(self) -> bool:
        """Whether the connection fell in the decay window rather than the hard window."""
        return self.weight < 1.0

    @property
    def key(self) -> tuple[float, SensorType, int, Protocol, str, int, str, int]:
        """Identity of this (event, connection) pair, used to ignore repeated matches."""
        return (self.event.timestamp, self.event.sensor, *self.connection.key)


@dataclass(frozen=True, slots=True)
class Alert:
    """One alert per outbound connection; re-emitted with the same id when more sensors match."""

    id: int
    finding: Finding
    severity: Severity
    created_at: float
    sensors: frozenset[SensorType] = field(default_factory=frozenset)
    updated: bool = False

    @property
    def sensor_label(self) -> str:
        """Sorted sensor names joined with `+`, e.g. `camera+microphone`."""
        names = sorted(s.value for s in self.sensors) or [self.finding.event.sensor.value]
        return "+".join(names)

    @property
    def summary(self) -> str:
        """One-line description: who used which sensors, where it connected and the delay."""
        ev, conn = self.finding.event, self.finding.connection
        destination = conn.hostname or conn.remote
        return (
            f"{ev.identity} used {self.sensor_label} then connected to {destination} "
            f"after {self.finding.delta_s * 1000:.0f} ms"
        )


@dataclass(frozen=True, slots=True)
class ActionResult:
    """Outcome of a response action on `target` (an IP, firewall table or pid)."""

    kind: ActionKind
    target: str
    ok: bool
    detail: str = ""
