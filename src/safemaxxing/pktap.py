"""pktap egress source: per-packet process metadata from `tcpdump -k` on a pktap interface.

UDP sockets that are never `connect()`ed (Meet's media in Brave, on macOS 27.0.1) have no remote
address in the socket table, so `NetworkMonitor` cannot see where they send. pktap tags every
packet with the owning process, its pid and the direction; the first outbound packet of a flow
is turned into a `NetworkConnection` that the correlation engine handles like any other.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import ipaddress
import os
import re
import socket
import time
from collections.abc import AsyncGenerator, Callable, Sequence

import psutil

from safemaxxing.correlation import DNS_PORTS
from safemaxxing.models import (
    Direction,
    NetworkConnection,
    PktapEvent,
    Protocol,
    is_system_path,
)
from safemaxxing.network import HostnameResolver, bundle_id_for_exe
from safemaxxing.sensors import ProcessInfo, _drain_tail, process_info
from safemaxxing.throughput import THROUGHPUT_STATUS, ThroughputDeltaMonitor, ThroughputSpike

TCPDUMP_BINARY = "/usr/sbin/tcpdump"


def udp_filter(include_dns: bool = False) -> str:
    """BPF for outbound UDP, without `DNS_PORTS` unless `include_dns` (the correlation engine
    drops them anyway; Avast's DNS proxy sends from a new port per query, one flow each)."""
    if include_dns:
        return "udp"
    return " and ".join(["udp", *(f"not port {p}" for p in sorted(DNS_PORTS))])


# A SYN with no ACK is a connection this host is opening (an outbound SYN-ACK would be us
# accepting someone else's). `-Q dir=out` already keeps only our packets, so this isolates
# the initiations: the one on-wire sign of a TCP socket that opens and closes inside a single
# 200 ms poll and so never appears in the socket table.
TCP_SYN_FILTER = "(tcp[tcpflags] & (tcp-syn|tcp-ack)) == tcp-syn"


def capture_filter(
    include_udp: bool = True,
    include_dns: bool = False,
    tcp_syn: bool = False,
    tcp_data: bool = False,
) -> str:
    """Compose a BPF expression from the sources wanted.

    `include_udp` adds outbound UDP (what the socket table misses). `tcp_data` adds every TCP
    packet, which the throughput monitor needs to weigh a pre-established socket but is heavy;
    it already includes SYNs, so it supersedes `tcp_syn`, which on its own adds only connection
    initiations (short-lived sockets) at almost no cost. With nothing selected the filter falls
    back to UDP, the historical default.
    """
    clauses: list[str] = []
    if include_udp:
        clauses.append(udp_filter(include_dns))
    if tcp_data:
        clauses.append("tcp")
    elif tcp_syn:
        clauses.append(TCP_SYN_FILTER)
    if not clauses:
        return udp_filter(include_dns)
    if len(clauses) == 1:
        return clauses[0]
    return " or ".join(f"({clause})" for clause in clauses)


# TCP connections are already in the socket table with their peer; UDP is what it misses.
DEFAULT_BPF_FILTER = udp_filter()
# `-Q` runs in tcpdump, not the kernel ("drops by metadata filter"): it saves parsing only.
DEFAULT_METADATA_FILTER = "dir=out"
KERNEL_PID = 0

FlowKey = tuple[int, Protocol, str, int, str, int]

# `(<if>, proc <name>:<pid>, [eproc <name>:<pid>, ]svc <class>, <in|out>[, <flags>]) IP[6] ...`
# Process names are chosen by the process itself, so they are matched lazily and capped at the
# kernel's 16 characters (MAXCOMLEN): a name cannot fit both fake fields and a closing `) IP`.
_LINE_RE = re.compile(
    r"^(?P<ts>\d+\.\d+) "
    r"\((?P<interface>[^,()]+), proc (?P<proc>.{1,16}?):(?P<pid>\d+), "
    r"(?:eproc (?P<eproc>.{1,16}?):(?P<epid>\d+), )?"
    r"svc \w+, (?P<dir>in|out)(?:, [^()]*)?\) "
    r"IP6? (?P<src>\S+)\.(?P<sport>\d+) > (?P<dst>\S+)\.(?P<dport>\d+): (?P<rest>.*)$"
)
_UDP_RE = re.compile(r"^UDP, length (\d+)")
_TCP_QUICK_RE = re.compile(r"^tcp (\d+)")
_TCP_FULL_RE = re.compile(r"^Flags \[[^\]]*\].*?(?:length (\d+))?$")


def pktap_command(
    bpf_filter: str | None = DEFAULT_BPF_FILTER,
    metadata_filter: str | None = DEFAULT_METADATA_FILTER,
    interface: str = "pktap,all",
) -> list[str]:
    """`tcpdump` printing pktap metadata (`-k`), numeric (`-n`), short (`-q`), epoch timestamps
    (`-tt`) and one line per packet as it arrives (`-l`). Needs root.

    `--immediate-mode` is the default only on a terminal; on a pipe, without it, packets come
    in batches up to about 1 s late (macOS 27.0.1, TESTLOG 2026-10-27 08:35).
    """
    command = [TCPDUMP_BINARY, "-k", "-n", "-q", "-tt", "-l", "--immediate-mode", "-i", interface]
    if metadata_filter:
        command += ["-Q", metadata_filter]
    if bpf_filter:
        command.append(bpf_filter)
    return command


def _protocol(rest: str) -> tuple[Protocol, int] | None:
    if match := _UDP_RE.match(rest):
        return Protocol.UDP, int(match[1])
    if match := _TCP_QUICK_RE.match(rest):
        return Protocol.TCP, int(match[1])
    if match := _TCP_FULL_RE.match(rest):
        return Protocol.TCP, int(match[1] or 0)
    return None


def _port(text: str) -> int | None:
    port = int(text)
    return port if port <= 0xFFFF else None


def parse_pktap_line(line: str) -> PktapEvent | None:
    """Parse one line of `pktap_command` output; None for anything else (headers, ICMP...)."""
    match = _LINE_RE.match(line.rstrip("\r\n"))
    if not match:
        return None
    proto = _protocol(match["rest"])
    src_port, dest_port = _port(match["sport"]), _port(match["dport"])
    if proto is None or src_port is None or dest_port is None:
        return None
    try:
        src_ip = str(ipaddress.ip_address(match["src"]))
        dest_ip = str(ipaddress.ip_address(match["dst"]))
    except ValueError:
        return None
    protocol, length = proto
    return PktapEvent(
        timestamp=float(match["ts"]),
        interface=match["interface"],
        pid=int(match["pid"]),
        process_name=match["proc"],
        protocol=protocol,
        src_ip=src_ip,
        src_port=src_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        direction=Direction(match["dir"]),
        length=length,
        effective_pid=int(match["epid"]) if match["epid"] else None,
        effective_process_name=match["eproc"],
    )


def is_relevant_destination(ip: str, include_loopback: bool = False) -> bool:
    """Whether a packet to `ip` can leave this host: not multicast, link-local (AWDL, mDNS),
    unspecified or broadcast, and not loopback unless asked."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback:
        return include_loopback
    return not (
        addr.is_multicast or addr.is_link_local or addr.is_unspecified or ip == "255.255.255.255"
    )


def interface_broadcasts() -> frozenset[str]:
    """The IPv4 broadcast address of every interface now (`10.243.255.255` for a /16 on en0);
    read per new flow, since the network can change under a running capture."""
    return frozenset(
        addr.broadcast
        for addrs in psutil.net_if_addrs().values()
        for addr in addrs
        if addr.family == socket.AF_INET and addr.broadcast
    )


class PktapFlowTracker:
    """Turns packets into connections: the first outbound packet of a flow is its connection.

    A flow with no packet in either direction for `idle_s` is forgotten, so it counts as new
    when it resumes. Flows first seen before `mute_until` are tracked but not returned, and
    flows to an interface's broadcast address are never returned. Flows of the kernel and of
    SIP-protected binaries are dropped unless `include_system`; the process is looked up once
    per new flow, never cached, so a reused pid is never mistaken for the process that held
    it before.
    """

    def __init__(
        self,
        include_system: bool = False,
        include_loopback: bool = False,
        idle_s: float = 60.0,
        max_flows: int = 8192,
        process_lookup: ProcessInfo = process_info,
        bundle_lookup: Callable[[str], str | None] = bundle_id_for_exe,
        broadcasts: Callable[[], frozenset[str]] = interface_broadcasts,
    ) -> None:
        self._include_system = include_system
        self._include_loopback = include_loopback
        self._idle_s = idle_s
        self._max_flows = max_flows
        self._process_lookup = process_lookup
        self._bundle_lookup = bundle_lookup
        self._broadcasts = broadcasts
        self._last_packet: dict[FlowKey, float] = {}
        self._conns: dict[FlowKey, NetworkConnection] = {}
        self._muted_until = 0.0

    def mute_until(self, timestamp: float) -> None:
        """Track flows first seen before `timestamp` without returning them: when a capture
        starts, a flow that was already open looks new on its first packet."""
        self._muted_until = timestamp

    def active(self, now: float | None = None) -> tuple[NetworkConnection, ...]:
        """Connections of the flows with a packet in the last `idle_s`, muted ones included."""
        horizon = (time.time() if now is None else now) - self._idle_s
        return tuple(c for k, c in self._conns.items() if self._last_packet.get(k, 0.0) >= horizon)

    def connection_for(self, key: FlowKey) -> NetworkConnection | None:
        """The connection built for `key` (with process name, exe and bundle id resolved) when
        its first packet was seen, or None if the flow is unknown. Lets a throughput spike
        re-use that identity instead of only the kernel's 16-character process name."""
        return self._conns.get(key)

    def _prune(self, now: float) -> None:
        horizon = now - self._idle_s
        self._last_packet = {k: t for k, t in self._last_packet.items() if t >= horizon}
        if len(self._last_packet) >= self._max_flows:
            self._last_packet.clear()
        self._conns = {k: c for k, c in self._conns.items() if k in self._last_packet}

    def feed(self, packet: PktapEvent) -> NetworkConnection | None:
        """The connection `packet` opens, or None if its flow is known, inbound or filtered."""
        key = packet.flow_key
        if packet.direction is Direction.INBOUND:
            if key in self._last_packet:
                self._last_packet[key] = packet.timestamp
            return None
        if not is_relevant_destination(packet.dest_ip, self._include_loopback):
            return None
        last = self._last_packet.get(key)
        if len(self._last_packet) >= self._max_flows:
            self._prune(packet.timestamp)
        self._last_packet[key] = packet.timestamp
        if last is not None and packet.timestamp - last < self._idle_s:
            return None
        if packet.dest_ip in self._broadcasts():
            return None
        # A process gone already keeps the kernel's name and counts as non-system.
        name, exe = self._process_lookup(packet.pid) or (None, None)
        # kernel_task has no executable path to check; on macOS 27.0.1 it sends the NetBIOS
        # broadcasts (UDP 137 to the subnet's broadcast address).
        system = packet.pid == KERNEL_PID or is_system_path(exe)
        if not self._include_system and system:
            return None
        bundle = self._bundle_lookup(exe) if exe else None
        conn = packet.to_connection(process_name=name, exe_path=exe, bundle_id=bundle)
        self._conns[key] = conn
        return None if packet.timestamp < self._muted_until else conn


class PktapError(RuntimeError):
    pass


async def _stop(proc: asyncio.subprocess.Process, timeout_s: float) -> None:
    """SIGTERM, then SIGKILL after `timeout_s`; always reaps the child so no zombie is left."""
    if proc.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout_s)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await proc.wait()


class PktapCapture:
    """Async wrapper around a pktap `tcpdump`, yielding packets or new outbound connections.

    The child is stopped and reaped when iteration ends for any reason: the consumer breaks
    out, the task is cancelled (the TUI quits) or an error is raised.
    """

    def __init__(
        self,
        command: Sequence[str] | None = None,
        tracker: PktapFlowTracker | None = None,
        stop_timeout_s: float = 1.0,
        warmup_s: float = 2.0,
        max_restarts: int = 5,
        restart_backoff_s: float = 1.0,
        max_backoff_s: float = 30.0,
        resolver: HostnameResolver | None = None,
        throughput: ThroughputDeltaMonitor | None = None,
    ) -> None:
        self._command = list(command) if command is not None else pktap_command()
        self.tracker = tracker or PktapFlowTracker()
        self._stop_timeout_s = stop_timeout_s
        self._warmup_s = warmup_s
        self._max_restarts = max_restarts
        self._restart_backoff_s = restart_backoff_s
        self._max_backoff_s = max_backoff_s
        self._resolver = resolver
        # Optional: re-surfaces a pre-established flow when its outbound rate spikes. None keeps
        # the capture to new-flow detection only.
        self._throughput = throughput
        self.packets = 0
        self.unparsed = 0
        self.restarts = 0
        self.spikes = 0

    def _named(self, conn: NetworkConnection) -> NetworkConnection:
        host = self._resolver.cached(conn.remote_address) if self._resolver else None
        return dataclasses.replace(conn, hostname=host) if host else conn

    def _spike_connection(self, spike: ThroughputSpike) -> NetworkConnection:
        """A spike as a connection, re-using the flow's resolved identity when the tracker has
        it (it does once the flow's first packet went by), else the kernel's process name."""
        known = self.tracker.connection_for(spike.flow_key)
        if known is None:
            return spike.to_connection()
        return dataclasses.replace(known, status=THROUGHPUT_STATUS, first_seen=spike.timestamp)

    def active(self, now: float | None = None) -> tuple[NetworkConnection, ...]:
        """The tracker's active flows, with hostnames filled in from the resolver cache."""
        return tuple(self._named(c) for c in self.tracker.active(now))

    async def lines(self) -> AsyncGenerator[str]:
        """Raw output lines; raises `PktapError` if tcpdump exits with an error (e.g. not root)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *self._command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise PktapError(f"cannot run {self._command[0]}: {exc}") from exc
        assert proc.stdout is not None and proc.stderr is not None
        stderr_task = asyncio.create_task(_drain_tail(proc.stderr))
        try:
            while True:
                try:
                    raw = await proc.stdout.readline()
                except ValueError:  # a line over the reader's limit: skipped, not fatal
                    self.unparsed += 1
                    continue
                if not raw:
                    break
                yield raw.decode(errors="replace").rstrip("\r\n")
            returncode = await proc.wait()
            if returncode != 0:
                stderr = (await stderr_task).decode(errors="replace").strip()
                raise PktapError(f"{self._command[0]} exited with {returncode}: {stderr}")
        finally:
            # Shielded: a second cancellation while stopping must not leave tcpdump running.
            await asyncio.shield(_stop(proc, self._stop_timeout_s))
            stderr_task.cancel()

    async def events(self) -> AsyncGenerator[PktapEvent]:
        """Parsed packets, counted in `packets`; blank and unrecognised lines are counted in
        `unparsed`."""
        # aclosing: leaving this generator early must close `lines()` too, which stops tcpdump.
        async with contextlib.aclosing(self.lines()) as lines:
            async for line in lines:
                if not line:
                    continue
                packet = parse_pktap_line(line)
                if packet is None:
                    self.unparsed += 1
                    continue
                self.packets += 1
                yield packet

    async def connections(self) -> AsyncGenerator[NetworkConnection]:
        """New outbound flows as connections, in the form `Supervisor` takes from the monitor.

        Flows first seen within `warmup_s` of a run's first packet were already open: they are
        tracked, not yielded. When tcpdump stops (an error, or the end of its output) it is
        started again, up to `max_restarts` times in a row, after `restart_backoff_s` doubled
        each time up to `max_backoff_s`; a run longer than `max_backoff_s` resets the count.
        Past that, the last error is raised, or iteration ends if tcpdump exited cleanly.
        Hostnames come only from the resolver cache; a new destination is prefetched, never
        awaited, as in `NetworkMonitor.connections`.
        """
        loop = asyncio.get_running_loop()
        failures = 0
        while True:
            started = loop.time()
            error: PktapError | None = None
            try:
                async with contextlib.aclosing(self.events()) as packets:
                    first = True
                    async for packet in packets:
                        if first:
                            self.tracker.mute_until(packet.timestamp + self._warmup_s)
                            first = False
                        if (conn := self.tracker.feed(packet)) is not None:
                            if self._resolver is not None:
                                self._resolver.prefetch(conn.remote_address)
                            yield self._named(conn)
                        if self._throughput is not None:
                            spike = self._throughput.observe(packet)
                            if spike is not None:
                                self.spikes += 1
                                spike_conn = self._spike_connection(spike)
                                if self._resolver is not None:
                                    self._resolver.prefetch(spike_conn.remote_address)
                                yield self._named(spike_conn)
            except PktapError as exc:
                error = exc
            if loop.time() - started > self._max_backoff_s:
                failures = 0
            if failures >= self._max_restarts:
                if error is not None:
                    raise error
                return
            failures += 1
            self.restarts += 1
            delay = self._restart_backoff_s * 2 ** (failures - 1)
            await asyncio.sleep(min(delay, self._max_backoff_s))


def pktap_unavailable(binary: str = TCPDUMP_BINARY, euid: int | None = None) -> str | None:
    """Why a pktap capture cannot start here, as one sentence; None if it may.

    Cheap checks only (tcpdump executable, root); a refused pktap device still shows up later
    as `PktapError`.
    """
    if not os.access(binary, os.X_OK):
        return f"{binary} is missing or not executable"
    if (os.geteuid() if euid is None else euid) != 0:
        return "capturing on pktap needs root: re-run with sudo"
    return None
