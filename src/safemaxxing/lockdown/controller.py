"""LockdownController: turns Paranoia Mode on and off and runs it while it is on.

Entering is ordered so that no step can leave the user offline without a way back:

1. preflight: root, the watchdog job loaded, the single-owner lock, resolvers found, the
   ruleset accepted by `pfctl -n`;
2. the sinkhole listening, the exception tables filled, grants seeded for the leases already
   held (a call in progress keeps going);
3. the watchdog armed: from here, silence restores v0.2;
4. the default-deny ruleset loaded, atomically.

While on, the learn loop reads what the default-deny rule dropped (`pflog0`), finds the socket
owner, and grants the destination when the owner belongs to an ACTIVE lease's app, passes code
verification and the DNS checks. pktap flows are audited for processes outside a lease reaching
a granted destination (a piggyback, stopped with SIGSTOP), and leased processes are
re-verified on a timer.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import ipaddress
import json
import os
import re
import socket
import tempfile
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import IO

import psutil

from safemaxxing.boot import LaunchdJob
from safemaxxing.codesign import CodeVerifier, Verdict, assess, kernel_code_status, start_time
from safemaxxing.firewall import (
    STATE_DIR,
    FirewallError,
    ProcessController,
    Runner,
    is_root,
    run_command,
)
from safemaxxing.lockdown.dns import DnsMap, DomainBlocklist, Sinkhole, system_resolvers
from safemaxxing.lockdown.leases import GRACE_S, MAX_GRANTS, Lease, LeaseBook, LeaseSource
from safemaxxing.lockdown.pf import LockdownFirewall
from safemaxxing.lockdown.pflog import BlockedPacket, blocked_packets, ensure_interface
from safemaxxing.lockdown.rules import (
    APPLE_NETWORKS,
    APPLE_TABLE,
    DNS_TABLE,
    NTP_TABLE,
    USER_TABLE,
    Grant,
    LockdownConfig,
    lockdown_rules,
)
from safemaxxing.lockdown.sni import ClientHelloSeen, SniOutcome
from safemaxxing.lockdown.watchdog import RUN_DIR, Heartbeat, WatchdogJob
from safemaxxing.models import (
    ActionKind,
    ActionResult,
    IndicatorState,
    NetworkConnection,
    Protocol,
    SensorType,
    Severity,
    is_system_path,
)
from safemaxxing.network import bundle_id_for_exe, enclosing_apps

PINS = STATE_DIR / "pins.json"
LOCK = RUN_DIR / "owner.lock"
SCUTIL = "/usr/sbin/scutil"
LSAPPINFO = "/usr/bin/lsappinfo"
# Sensors whose use means "the user is communicating": location is not one of them.
COMMS_SENSORS = frozenset({SensorType.CAMERA, SensorType.MICROPHONE, SensorType.SCREEN_CAPTURE})
# Public DNS-over-HTTPS/TLS resolvers: an app reaching one on 443/853 would resolve around
# the sinkhole, so they are never granted; browsers then fall back to the system resolver.
DOH_RESOLVERS = frozenset(
    {
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "149.112.112.112",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        "2620:fe::fe",
        "2620:fe::9",
    }
)
_RETRY_TTL_S = 5.0
_SOCKETS_TTL_S = 0.25
_VERIFIED_TTL_S = 10.0
_BUNDLE_RE = re.compile(r'(?:bundleID|"CFBundleIdentifier")\s*=\s*"([^"]+)"')


class LockdownState(StrEnum):
    """OFF, ARMING while entering, ON, or TRIPPED once the watchdog took pf back."""

    OFF = "off"
    ARMING = "arming"
    ON = "on"
    TRIPPED = "tripped"


@dataclass(frozen=True, slots=True)
class LockdownNotice:
    """Something the user should see: a refused grant, a piggyback, a trip."""

    severity: Severity
    message: str
    pid: int | None = None
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True, slots=True)
class ParanoiaConfig:
    """Everything about Paranoia Mode a user may set."""

    rules: LockdownConfig = LockdownConfig()
    foreground_leases: bool = True
    # What a blocked SNI on a granted flow does: "alert" only, or "revoke" the grant too.
    sni_action: str = "alert"
    # TCP 443 to an address no DNS answer named: unusual for an app, normal for WebRTC media
    # (UDP, ICE candidates). Refused when True.
    require_dns_for_https: bool = False
    ntp_hosts: tuple[str, ...] = ("time.apple.com",)
    user_allow: tuple[str, ...] = ()


DEFAULT_PARANOIA = ParanoiaConfig()


@dataclass(frozen=True, slots=True)
class SocketOwner:
    """A local socket and the pid that owns it."""

    protocol: Protocol
    address: str
    port: int
    pid: int
    remote: tuple[str, int] | None


def psutil_sockets() -> list[SocketOwner]:
    """Every inet socket with an owner (needs root to see other users' processes)."""
    owners: list[SocketOwner] = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.pid is None or not conn.laddr:
            continue
        protocol = Protocol.TCP if conn.type == socket.SOCK_STREAM else Protocol.UDP
        remote = (conn.raddr.ip, conn.raddr.port) if conn.raddr else None
        owners.append(SocketOwner(protocol, conn.laddr.ip, conn.laddr.port, conn.pid, remote))
    return owners


def exe_of(pid: int) -> str | None:
    """Executable path of `pid`, or None."""
    try:
        return psutil.Process(pid).exe() or None
    except psutil.Error:
        return None


class PinStore:
    """Team ID pinned per bundle id at its first verified grant (trust on first use).

    A later process claiming the bundle id with another Team ID is refused: that is either a
    spoofed bundle id or a vendor change, and the user decides (`unpin`). Platform binaries
    pin as '' (Apple, no Team ID).
    """

    def __init__(self, path: Path = PINS) -> None:
        self.path = path
        try:
            data = json.loads(path.read_text())
        except (FileNotFoundError, ValueError):
            data = {}
        self._pins: dict[str, str] = {
            k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)
        }

    def get(self, bundle_id: str) -> str | None:
        """The pinned Team ID, '' for Apple, None if never pinned."""
        return self._pins.get(bundle_id)

    def pin(self, bundle_id: str, team_id: str) -> None:
        """Record `team_id` for `bundle_id` and save."""
        self._pins[bundle_id] = team_id
        self._save()

    def unpin(self, bundle_id: str) -> None:
        """Forget a pin, so the next grant pins again."""
        if self._pins.pop(bundle_id, None) is not None:
            self._save()

    def _save(self) -> None:
        """Replace the file atomically (root-owned, 0644)."""
        self.path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".pins-")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(self._pins, fh, indent=1, sort_keys=True)
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.path)
        except BaseException:
            os.unlink(tmp)
            raise


async def frontmost_bundle(runner: Runner = run_command) -> str | None:
    """Bundle id of the frontmost app, from `lsappinfo`; None if it cannot tell."""
    front = await runner([LSAPPINFO, "front"])
    asn = front.stdout.strip()
    if front.returncode != 0 or not asn:
        return None
    info = await runner([LSAPPINFO, "info", "-only", "bundleid", asn])
    match = _BUNDLE_RE.search(info.stdout)
    return match.group(1) if match else None


async def resolve_hosts(hosts: Iterable[str]) -> list[str]:
    """Addresses of `hosts`, resolved now (before lockdown, while DNS still works)."""
    found: set[str] = set()
    for host in hosts:
        with contextlib.suppress(OSError):
            for *_, sockaddr in await asyncio.get_running_loop().getaddrinfo(host, 123):
                found.add(str(sockaddr[0]).split("%", 1)[0])
    return sorted(found)


class LockdownController:
    """Owns Paranoia Mode. Every seam is injected; the defaults are the real Mac ones."""

    def __init__(
        self,
        config: ParanoiaConfig = DEFAULT_PARANOIA,
        firewall: LockdownFirewall | None = None,
        verifier: CodeVerifier | None = None,
        pins: PinStore | None = None,
        heartbeat: Heartbeat | None = None,
        watchdog: LaunchdJob | None = None,
        processes: ProcessController | None = None,
        blocklist: DomainBlocklist | None = None,
        runner: Runner = run_command,
        sockets: Callable[[], list[SocketOwner]] = psutil_sockets,
        exe: Callable[[int], str | None] = exe_of,
        blocked: Callable[[], AsyncIterator[BlockedPacket]] = blocked_packets,
        hellos: Callable[[], AsyncIterator[ClientHelloSeen]] | None = None,
        foreground: Callable[[], Awaitable[str | None]] | None = None,
        sinkhole: Callable[[list[str]], Sinkhole] | None = None,
        notify: Callable[[LockdownNotice], None] = lambda notice: None,
        root: Callable[[], bool] = is_root,
        lock_path: Path = LOCK,
        grace_s: Mapping[LeaseSource, float] = GRACE_S,
        started: Callable[[int], float | None] = start_time,
    ) -> None:
        self.config = config
        self.firewall = firewall or LockdownFirewall(runner)
        self.verifier = verifier or CodeVerifier()
        self.pins = pins or PinStore()
        self.watchdog = watchdog or WatchdogJob(runner)
        self.processes = processes or ProcessController()
        self.blocklist = blocklist or DomainBlocklist()
        self.dns_map = DnsMap()
        self._run = runner
        self._sockets_fn = sockets
        self._exe = exe
        self._blocked = blocked
        self._hellos = hellos
        self._foreground = foreground or (lambda: frontmost_bundle(runner))
        self._make_sinkhole = sinkhole or self._default_sinkhole
        self.notify = notify
        self._root = root
        self._lock_path = lock_path
        self.heartbeat = heartbeat or Heartbeat()
        # Beats mean "lockdown is working", whoever built the heartbeat.
        self.heartbeat.healthy = self._healthy
        self.leases = LeaseBook(self._on_revoke, grace_s)
        self._started = started
        self.state = LockdownState.OFF
        self.sinkhole: Sinkhole | None = None
        self.denied = 0
        self._lock: IO[str] | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self._sni_task: asyncio.Task[None] | None = None
        self._dirty = asyncio.Event()
        self._retries: dict[tuple[Protocol, str, int, str, int], float] = {}
        self._socket_cache: tuple[float, list[SocketOwner]] = (0.0, [])
        # (pid, start time) -> (bundle id, when verified); the re-verify loop walks it.
        self._verified: dict[tuple[int, float], tuple[str, float]] = {}
        self._background: set[asyncio.Task[object]] = set()

    # Signals that hold leases (run whatever the state, so entering mid-call knows the call)

    def observe_indicator(self, state: IndicatorState) -> None:
        """Sensor callback from the listener: comms sensors in use hold SENSOR leases."""
        self.leases.set_holders(LeaseSource.SENSOR, state.bundles(COMMS_SENSORS))

    def grant_manual(self, bundle_id: str) -> None:
        """The user granted `bundle_id` from the TUI."""
        self.leases.hold(bundle_id, LeaseSource.MANUAL)

    def release_manual(self, bundle_id: str) -> None:
        """The user withdrew a manual grant: revoked at once, unless another source holds it."""
        self.leases.release(bundle_id, LeaseSource.MANUAL)

    # Entering and leaving

    def _default_sinkhole(self, upstreams: list[str]) -> Sinkhole:
        def blocked(name: str) -> None:
            self.notify(LockdownNotice(Severity.LOW, f"DNS sinkholed {name}"))

        return Sinkhole(self.blocklist, self.dns_map, upstreams, on_block=blocked)

    async def enter(self) -> ActionResult:
        """Turn Paranoia Mode on (see the module docstring for the order)."""
        if self.state is not LockdownState.OFF:
            return ActionResult(ActionKind.LOCKDOWN_ON, "pf", False, f"already {self.state}")
        self.state = LockdownState.ARMING
        try:
            await self._arm()
        except (FirewallError, OSError, ValueError) as exc:
            await self._teardown()
            self.state = LockdownState.OFF
            return ActionResult(ActionKind.LOCKDOWN_ON, "pf", False, str(exc))
        self.state = LockdownState.ON
        for job in (self._learn_loop, self._flush_loop, self._reverify_loop, self._beat):
            self._tasks.append(asyncio.create_task(job()))
        if self.config.foreground_leases:
            self._tasks.append(asyncio.create_task(self._foreground_loop()))
        if self._hellos is not None:
            self._sni_task = asyncio.create_task(self._sni_loop(self._hellos))
            self._tasks.append(self._sni_task)
        held = sum(1 for _ in self.leases)
        return ActionResult(ActionKind.LOCKDOWN_ON, "pf", True, f"{held} leases held")

    async def _arm(self) -> None:
        if not self._root():
            raise FirewallError("Paranoia Mode needs root")
        if await self.watchdog.print() is None:
            raise FirewallError(
                "the watchdog is not loaded: run `sudo safemaxxing paranoia install` first"
            )
        self._take_lock()
        await ensure_interface(self._run)
        rules = lockdown_rules(self.config.rules)
        await self.firewall.check(rules)
        resolvers = system_resolvers((await self._run([SCUTIL, "--dns"])).stdout)
        if self.config.rules.sinkhole:
            self.sinkhole = self._make_sinkhole(resolvers)
            await self.sinkhole.start()
        tables = {
            DNS_TABLE: resolvers,
            NTP_TABLE: await resolve_hosts(self.config.ntp_hosts),
            APPLE_TABLE: list(APPLE_NETWORKS),
            USER_TABLE: [
                str(ipaddress.ip_network(a, strict=False)) for a in self.config.user_allow
            ],
        }
        for table, addresses in tables.items():
            await self.firewall.replace_table(table, addresses)
        await self._seed()
        await self.firewall.set_grants(self._all_grants())
        self.heartbeat.arm()
        await self.firewall.load(rules)

    async def leave(self) -> ActionResult:
        """Turn Paranoia Mode off: v0.2 rules back, grants flushed, watchdog disarmed."""
        if self.state is LockdownState.OFF:
            return ActionResult(ActionKind.LOCKDOWN_OFF, "pf", True, "already off")
        try:
            await self._teardown()
        except (FirewallError, OSError) as exc:
            # Still armed: the watchdog restores pf within MISSED_BEATS seconds anyway.
            return ActionResult(ActionKind.LOCKDOWN_OFF, "pf", False, str(exc))
        self.state = LockdownState.OFF
        return ActionResult(ActionKind.LOCKDOWN_OFF, "pf", True, "")

    async def _teardown(self) -> None:
        current = asyncio.current_task()
        for task in self._tasks:
            if task is not current:
                task.cancel()
        await asyncio.gather(*(t for t in self._tasks if t is not current), return_exceptions=True)
        self._tasks.clear()
        self._sni_task = None
        if self.sinkhole is not None:
            await self.sinkhole.close()
            self.sinkhole = None
        try:
            # pf first, then disarm: a crash in between leaves the watchdog to finish the job.
            await self.firewall.restore_normal()
            self.heartbeat.disarm()
        finally:
            for lease in self.leases:
                lease.grants.clear()
            self._verified.clear()
            self._release_lock()

    def _take_lock(self) -> None:
        self._lock_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        handle = open(self._lock_path, "w")  # noqa: SIM115 - held until _release_lock
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            raise FirewallError("another safemaxxing (TUI or daemon) owns Paranoia Mode") from None
        self._lock = handle

    def _release_lock(self) -> None:
        if self._lock is not None:
            self._lock.close()
            self._lock = None

    def _on_tripped(self) -> None:
        if self.state is not LockdownState.ON:
            return
        self.state = LockdownState.TRIPPED
        self.notify(
            LockdownNotice(
                Severity.CRITICAL,
                "watchdog restored the v0.2 rules: Paranoia Mode is OFF (no heartbeat)",
            )
        )
        self._spawn(self._after_trip())

    async def _after_trip(self) -> None:
        with contextlib.suppress(FirewallError, OSError):
            await self._teardown()
        self.state = LockdownState.OFF

    def _healthy(self) -> bool:
        # The SNI audit only reports after a grant: losing it must not drop the lockdown.
        skip = (asyncio.current_task(), self._sni_task)
        return all(not t.done() for t in self._tasks if t not in skip)

    async def _beat(self) -> None:
        await self.heartbeat.run(self._on_tripped)

    # Grants

    def _all_grants(self) -> set[Grant]:
        return {g for lease in self.leases for g in lease.grants}

    def _owners_of(self, grant: Grant) -> set[str]:
        return {lease.bundle_id for lease in self.leases if grant in lease.grants}

    async def _on_revoke(self, lease: Lease) -> None:
        if lease.grants and self.state is LockdownState.ON:
            self.notify(
                LockdownNotice(
                    Severity.LOW, f"lease of {lease.bundle_id} ended: {len(lease.grants)} cut"
                )
            )
            self._dirty.set()

    async def _flush_loop(self) -> None:
        """Reload the grants sub-anchor when they change, batching bursts (50 ms)."""
        while True:
            await self._dirty.wait()
            await asyncio.sleep(0.05)
            self._dirty.clear()
            try:
                await self.firewall.set_grants(self._all_grants())
            except FirewallError as exc:
                # The load is atomic, so pf still holds the previous grants: fewer, not more.
                # Ending this loop would stop the heartbeat and drop the whole lockdown.
                self.notify(LockdownNotice(Severity.HIGH, f"grants not updated: {exc}"))

    def _socket_table(self) -> list[SocketOwner]:
        now = time.monotonic()
        stamp, table = self._socket_cache
        if now - stamp > _SOCKETS_TTL_S:
            table = self._sockets_fn()
            self._socket_cache = (now, table)
        return table

    def _owner(self, packet: BlockedPacket) -> int | None:
        if packet.pid is not None:
            return packet.pid
        wildcard = "::" if ":" in packet.src else "0.0.0.0"
        for owner in self._socket_table():
            if (
                owner.protocol is packet.protocol
                and owner.port == packet.src_port
                and owner.address in (packet.src, wildcard, "::")
            ):
                return owner.pid
        return None

    async def _verify(self, pid: int, bundle_id: str, exe: str) -> Verdict:
        started = self._started(pid)
        if started is None:
            return Verdict(False, ("process gone",))
        key = (pid, started)
        cached = self._verified.get(key)
        if cached is not None and time.monotonic() - cached[1] < _VERIFIED_TTL_S:
            return Verdict(True)
        apps = enclosing_apps(exe)
        pinned = self.pins.get(bundle_id)
        verdict = await self.verifier.verify(pid, pinned, apps[0] if apps else None)
        if verdict.ok and pinned is None and verdict.status is not None:
            self.pins.pin(bundle_id, verdict.status.team_id or "")
        if verdict.ok:
            self._verified[key] = (bundle_id, time.monotonic())
        return verdict

    def _refusal(self, grant: Grant) -> str | None:
        """Why `grant` must not be given whoever asks, from DNS knowledge alone."""
        if grant.address in DOH_RESOLVERS and grant.port in (443, 853):
            return "public DNS-over-HTTPS/TLS resolver (would bypass the sinkhole)"
        names = self.dns_map.names(grant.address)
        if tracker := next((n for n in sorted(names) if self.blocklist.blocks(n)), None):
            return f"resolved from blocklisted {tracker}"
        if (
            self.config.require_dns_for_https
            and not names
            and grant.protocol is Protocol.TCP
            and grant.port == 443
        ):
            return "HTTPS to an address no DNS answer named"
        return None

    async def consider(self, pid: int, grant: Grant) -> bool:
        """Grant `grant` to `pid`'s lease if every check passes; True if granted."""
        exe = self._exe(pid)
        bundle_id = bundle_id_for_exe(exe) if exe else None
        lease = self.leases.active(bundle_id) if bundle_id else None
        if lease is None or exe is None or bundle_id is None:
            self.denied += 1
            return False
        if grant in lease.grants:
            return True
        if (why := self._refusal(grant)) is not None:
            self.notify(LockdownNotice(Severity.MEDIUM, f"{bundle_id} -> {grant.address}: {why}"))
            return False
        verdict = await self._verify(pid, bundle_id, exe)
        if not verdict.ok:
            reasons = "; ".join(verdict.reasons)
            self.notify(LockdownNotice(Severity.CRITICAL, f"{bundle_id} refused: {reasons}", pid))
            return False
        if len(lease.grants) >= MAX_GRANTS:
            self.notify(LockdownNotice(Severity.HIGH, f"{bundle_id} hit {MAX_GRANTS} grants", pid))
            return False
        lease.grants.add(grant)
        self._dirty.set()
        return True

    async def _seed(self) -> None:
        """Grant held leases the destinations their apps already talk to."""
        for owner in self._socket_table():
            if owner.remote is None:
                continue
            with contextlib.suppress(ValueError):
                grant = Grant(owner.protocol, owner.remote[0], owner.remote[1])
                await self.consider(owner.pid, grant)

    async def _learn_loop(self) -> None:
        async for packet in self._blocked():
            now = time.monotonic()
            if self._retries.get(packet.flow, 0.0) > now:
                continue  # a retransmission of a connect already judged
            self._retries[packet.flow] = now + _RETRY_TTL_S
            if len(self._retries) > 4096:
                self._retries = {k: t for k, t in self._retries.items() if t > now}
            pid = self._owner(packet)
            if pid is None:
                self.denied += 1
                continue
            with contextlib.suppress(ValueError):
                await self.consider(pid, Grant(packet.protocol, packet.dst, packet.dst_port))
        raise FirewallError("pflog capture ended")

    async def _reverify_loop(self, interval_s: float = 10.0) -> None:
        """Re-read every granted process's kernel status; revoke on any failure."""
        while True:
            await asyncio.sleep(interval_s)
            for (pid, _), (bundle_id, _) in list(self._verified.items()):
                status = kernel_code_status(pid)
                if status is None:
                    continue
                verdict = assess(status, self.pins.get(bundle_id), self.verifier.strictness)
                if not verdict.ok:
                    self.leases.revoke_now(bundle_id)
                    self._suspend(pid, f"{bundle_id} failed re-verification: {verdict.reasons}")

    async def _foreground_loop(self, interval_s: float = 1.0) -> None:
        while True:
            bundle_id = await self._foreground()
            self.leases.set_holders(LeaseSource.FOREGROUND, [bundle_id] if bundle_id else [])
            await asyncio.sleep(interval_s)

    async def _sni_loop(self, hellos: Callable[[], AsyncIterator[ClientHelloSeen]]) -> None:
        try:
            await self._sni_audit(hellos)
        except (OSError, ValueError) as exc:
            self.notify(LockdownNotice(Severity.MEDIUM, f"SNI audit stopped: {exc}"))
        else:
            self.notify(LockdownNotice(Severity.MEDIUM, "SNI audit stopped: capture ended"))

    async def _sni_audit(self, hellos: Callable[[], AsyncIterator[ClientHelloSeen]]) -> None:
        async for seen in hellos():
            name = seen.hello.server_name
            if seen.hello.outcome is not SniOutcome.FOUND or name is None:
                continue
            self.dns_map.record(name, [])
            if not self.blocklist.blocks(name):
                continue
            pkt = seen.packet
            message = f"{pkt.process_name} ({pkt.pid}) sent SNI {name}, a blocklisted name"
            self.notify(LockdownNotice(Severity.HIGH, message, pkt.pid))
            if self.config.sni_action == "revoke":
                for lease in self.leases:
                    lease.grants = {g for g in lease.grants if g.address != pkt.dest_ip}
                self._dirty.set()

    # Piggyback audit (called for every connection the supervisor streams)

    def audit_flow(self, conn: NetworkConnection) -> None:
        """Stop a process outside a lease that reaches a granted destination."""
        if self.state is not LockdownState.ON or conn.pid <= 1:
            return
        try:
            grant = Grant(conn.protocol, conn.remote_address, conn.remote_port)
        except ValueError:
            return
        owners = self._owners_of(grant)
        if not owners:
            return
        exe = conn.exe_path or self._exe(conn.pid)
        bundle_id = conn.bundle_id or (bundle_id_for_exe(exe) if exe else None)
        if bundle_id in owners:
            return
        who = bundle_id or conn.process_name
        message = f"piggyback: {who} ({conn.pid}) reached {conn.remote}, granted to {owners}"
        if exe is not None and is_system_path(exe):
            # Never SIGSTOP a system daemon (nsurlsessiond stalls every download): flag only.
            self.notify(LockdownNotice(Severity.HIGH, message, conn.pid))
            return
        self._suspend(conn.pid, message)

    def _suspend(self, pid: int, message: str) -> None:
        result = self.processes.suspend(pid)
        verdict = "SIGSTOP" if result.ok else f"SIGSTOP failed: {result.detail}"
        self.notify(LockdownNotice(Severity.CRITICAL, f"{message} [{verdict}]", pid))

    def _spawn(self, coro: Awaitable[object]) -> None:
        task: asyncio.Task[object] = asyncio.ensure_future(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    def summary(self) -> str:
        """One line for the TUI: state, leases with their countdowns, grants, denied."""
        if self.state is not LockdownState.ON:
            return f"lockdown {self.state}"
        now = time.monotonic()
        parts = []
        for lease in self.leases:
            tail = f" {max(0.0, lease.deadline - now):.0f}s" if lease.deadline else ""
            parts.append(f"{lease.bundle_id.rsplit('.', 1)[-1]}({len(lease.grants)}){tail}")
        leases = ", ".join(parts) or "no lease"
        return f"LOCKDOWN · {leases} · {len(self._all_grants())} grants · {self.denied} denied"
