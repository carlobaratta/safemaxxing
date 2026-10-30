"""LockdownController end to end on fakes, and the TUI's panic button on top of it."""

from __future__ import annotations

import asyncio
import plistlib
import signal
from collections.abc import AsyncIterator, Callable, Sequence
from pathlib import Path

from test_supervisor_tui import supervisor
from test_tui import wait_for

from safemaxxing.codesign import (
    CS_HARD,
    CS_RUNTIME,
    CS_SIGNED,
    CS_VALID,
    CodeStatus,
    CodeVerifier,
    Verdict,
)
from safemaxxing.firewall import CommandResult, ProcessController
from safemaxxing.lockdown.controller import (
    LockdownController,
    LockdownNotice,
    LockdownState,
    ParanoiaConfig,
    PinStore,
    SocketOwner,
)
from safemaxxing.lockdown.dns import DomainBlocklist, Record
from safemaxxing.lockdown.leases import LeaseSource
from safemaxxing.lockdown.pflog import BlockedPacket
from safemaxxing.lockdown.rules import LockdownConfig
from safemaxxing.lockdown.sni import ClientHello, ClientHelloSeen, SniOutcome
from safemaxxing.lockdown.watchdog import Heartbeat
from safemaxxing.models import (
    Direction,
    IndicatorState,
    NetworkConnection,
    PktapEvent,
    Protocol,
    SensorType,
    Severity,
)
from safemaxxing.tui.app import SafemaxxingApp

ZOOM, SPY = 4242, 6666
FAST = {LeaseSource.SENSOR: 0.1, LeaseSource.FOREGROUND: 0.05, LeaseSource.MANUAL: 0.0}


def app_bundle(root: Path, name: str, bundle_id: str) -> str:
    contents = root / f"{name}.app" / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    (contents / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": bundle_id}))
    return str(contents / "MacOS" / name)


class FakeMac:
    """pfctl, launchctl and scutil, recording argv and stdin; the watchdog is loaded."""

    def __init__(self, heartbeat: Heartbeat, watchdog_loaded: bool = True) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.heartbeat = heartbeat
        self.watchdog_loaded = watchdog_loaded
        self.armed_at_load: bool | None = None

    async def __call__(self, argv: Sequence[str], stdin: str | None = None) -> CommandResult:
        args = list(argv)
        self.calls.append((args, stdin))
        if args[0] == "/bin/launchctl":
            return CommandResult(0 if self.watchdog_loaded else 113, "state = running", "")
        if args[0] == "/usr/sbin/scutil":
            return CommandResult(0, "  nameserver[0] : 192.168.1.1\n", "")
        if args == ["/sbin/ifconfig", "pflog0"]:
            # As on macOS 27.0.1: no pflog0 until it is created.
            created = any(a[-1] == "create" for a, _ in self.calls)
            return CommandResult(0 if created else 1, "", "")
        if args[-2:] == ["-f", "-"] and "-n" not in args and stdin and "log quick all" in stdin:
            self.armed_at_load = self.heartbeat.armed
        return CommandResult(0, "", "")

    def grants_loads(self) -> list[str]:
        return [
            stdin or ""
            for argv, stdin in self.calls
            if argv[1:3] == ["-a", "com.apple/safemaxxing/grants"] and argv[3] == "-f"
        ]


class Verifier(CodeVerifier):
    async def verify(self, pid: int, pinned: str | None, app: str | None) -> Verdict:
        status = CodeStatus(
            pid, CS_VALID | CS_SIGNED | CS_RUNTIME | CS_HARD, None, "ZOOMTEAM01", frozenset()
        )
        return Verdict(True, status=status)


def build(
    tmp_path: Path,
    watchdog_loaded: bool = True,
    hellos: Callable[[], AsyncIterator[ClientHelloSeen]] | None = None,
) -> tuple[
    LockdownController,
    FakeMac,
    asyncio.Queue[BlockedPacket],
    list[LockdownNotice],
    list[tuple[int, int]],
]:
    zoom_exe = app_bundle(tmp_path, "zoom.us", "us.zoom.xos")
    spy_exe = app_bundle(tmp_path, "Spy", "com.example.spy")
    exes = {ZOOM: zoom_exe, SPY: spy_exe, 99: "/usr/libexec/nsurlsessiond"}
    heartbeat = Heartbeat(run_dir=tmp_path / "run", interval_s=0.02)
    mac = FakeMac(heartbeat, watchdog_loaded)
    queue: asyncio.Queue[BlockedPacket] = asyncio.Queue()
    notices: list[LockdownNotice] = []
    signals: list[tuple[int, int]] = []

    async def blocked() -> AsyncIterator[BlockedPacket]:
        while True:
            yield await queue.get()

    sockets = [
        SocketOwner(Protocol.TCP, "10.0.0.5", 50001, ZOOM, ("203.0.113.9", 443)),
        SocketOwner(Protocol.UDP, "0.0.0.0", 53266, ZOOM, None),
        SocketOwner(Protocol.TCP, "10.0.0.5", 50002, SPY, None),
    ]
    controller = LockdownController(
        config=ParanoiaConfig(
            rules=LockdownConfig(sinkhole=False), foreground_leases=False, ntp_hosts=()
        ),
        verifier=Verifier(),
        pins=PinStore(tmp_path / "pins.json"),
        heartbeat=heartbeat,
        processes=ProcessController(kill=lambda pid, sig: signals.append((pid, sig))),
        blocklist=DomainBlocklist({"telemetry.zoom.us"}),
        runner=mac,
        sockets=lambda: sockets,
        exe=exes.get,
        blocked=blocked,
        hellos=hellos,
        notify=notices.append,
        root=lambda: True,
        lock_path=tmp_path / "run" / "owner.lock",
        grace_s=FAST,
        started=lambda pid: 1000.0 if pid in exes else None,
    )
    return controller, mac, queue, notices, signals


def camera(*bundles: str) -> IndicatorState:
    return IndicatorState(0.0, frozenset((SensorType.CAMERA, b) for b in bundles))


async def until(condition: Callable[[], bool]) -> None:
    for _ in range(200):
        if condition():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not met")


async def test_enter_seeds_the_call_and_arms_before_default_deny(tmp_path: Path) -> None:
    controller, mac, _, _, _ = build(tmp_path)
    controller.observe_indicator(camera("us.zoom.xos"))
    result = await controller.enter()
    try:
        assert result.ok, result.detail
        assert controller.state is LockdownState.ON
        assert mac.armed_at_load is True  # the watchdog was armed before default-deny loaded
        assert "203.0.113.9 port 443" in mac.grants_loads()[0]  # the call in progress
        assert PinStore(tmp_path / "pins.json").get("us.zoom.xos") == "ZOOMTEAM01"
        assert ["/sbin/ifconfig", "pflog0", "create"] in [argv for argv, _ in mac.calls]
    finally:
        await controller.leave()
    assert not controller.heartbeat.armed
    assert mac.calls[-1][0][-2:] == ["-F", "rules"]


async def test_enter_refuses_without_the_watchdog(tmp_path: Path) -> None:
    controller, mac, _, _, _ = build(tmp_path, watchdog_loaded=False)
    result = await controller.enter()
    assert not result.ok and "watchdog" in result.detail
    assert controller.state is LockdownState.OFF and mac.armed_at_load is None


async def test_learns_only_for_leased_apps_and_applies_dns_checks(tmp_path: Path) -> None:
    controller, mac, queue, notices, _ = build(tmp_path)
    controller.observe_indicator(camera("us.zoom.xos"))
    controller.dns_map.record(
        "telemetry.zoom.us", [Record("telemetry.zoom.us", 1, 300, "192.0.2.50")]
    )
    assert (await controller.enter()).ok
    try:
        media = BlockedPacket(1.0, Protocol.UDP, "10.0.0.5", 53266, "198.51.100.7", 8801)
        spy = BlockedPacket(1.0, Protocol.TCP, "10.0.0.5", 50002, "198.51.100.66", 443)
        doh = BlockedPacket(1.0, Protocol.TCP, "10.0.0.5", 50001, "1.1.1.1", 443)
        tracker = BlockedPacket(1.0, Protocol.TCP, "10.0.0.5", 50001, "192.0.2.50", 443)
        for packet in (media, spy, doh, tracker):
            queue.put_nowait(packet)
        await until(lambda: "198.51.100.7 port 8801" in mac.grants_loads()[-1])
        await until(lambda: len(notices) >= 2)
        loaded = mac.grants_loads()[-1]
        assert "198.51.100.66" not in loaded and "1.1.1.1" not in loaded
        assert "192.0.2.50" not in loaded
        assert controller.denied == 1
        reasons = " | ".join(n.message for n in notices)
        assert "DNS-over-HTTPS" in reasons and "blocklisted telemetry.zoom.us" in reasons
    finally:
        await controller.leave()


async def test_a_rejected_grants_load_is_reported_and_lockdown_stays(tmp_path: Path) -> None:
    controller, mac, queue, notices, _ = build(tmp_path)
    controller.observe_indicator(camera("us.zoom.xos"))
    assert (await controller.enter()).ok
    try:
        real = mac.__call__

        async def rejecting(argv: Sequence[str], stdin: str | None = None) -> CommandResult:
            if list(argv[1:3]) == ["-a", "com.apple/safemaxxing/grants"]:
                return CommandResult(1, "", "stdin:1: syntax error\n")
            return await real(argv, stdin)

        controller.firewall._run = rejecting
        queue.put_nowait(BlockedPacket(1.0, Protocol.UDP, "10.0.0.5", 53266, "198.51.100.7", 8801))
        await until(lambda: any("grants not updated" in n.message for n in notices))
        await asyncio.sleep(0.1)  # several heartbeat intervals
        assert controller.state is LockdownState.ON and controller._healthy()
    finally:
        controller.firewall._run = mac
        await controller.leave()


async def test_revocation_cuts_the_grants_after_the_grace(tmp_path: Path) -> None:
    controller, mac, _, _, _ = build(tmp_path)
    controller.observe_indicator(camera("us.zoom.xos"))
    assert (await controller.enter()).ok
    try:
        controller.observe_indicator(camera())  # camera off: the lease starts draining
        await asyncio.sleep(0.05)
        assert "203.0.113.9" in mac.grants_loads()[-1]  # still inside the grace
        await until(lambda: mac.grants_loads()[-1] == "")
    finally:
        await controller.leave()


async def test_piggyback_is_stopped_but_system_daemons_are_only_flagged(tmp_path: Path) -> None:
    controller, _, _, notices, signals = build(tmp_path)
    controller.observe_indicator(camera("us.zoom.xos"))
    assert (await controller.enter()).ok
    try:

        def conn(pid: int) -> NetworkConnection:
            return NetworkConnection(
                pid, "x", Protocol.TCP, "10.0.0.5", 50002, "203.0.113.9", 443, "ESTABLISHED", 1.0
            )

        controller.audit_flow(conn(ZOOM))
        controller.audit_flow(conn(SPY))
        controller.audit_flow(conn(99))
        assert signals == [(SPY, signal.SIGSTOP)]
        assert [n.severity for n in notices] == [Severity.CRITICAL, Severity.HIGH]
    finally:
        await controller.leave()


async def test_sni_audit_flags_trackers_and_its_end_does_not_drop_lockdown(tmp_path: Path) -> None:
    async def hellos() -> AsyncIterator[ClientHelloSeen]:
        packet = PktapEvent(
            1.0, "en0", ZOOM, "zoom.us", Protocol.TCP, "10.0.0.5", 50001, "203.0.113.9", 443,
            Direction.OUTBOUND,
        )  # fmt: skip
        yield ClientHelloSeen(packet, ClientHello(SniOutcome.FOUND, "telemetry.zoom.us"))

    controller, _, _, notices, _ = build(tmp_path, hellos=hellos)
    assert (await controller.enter()).ok
    try:
        await until(lambda: any("capture ended" in n.message for n in notices))
        assert any("SNI telemetry.zoom.us" in n.message for n in notices)
        await asyncio.sleep(0.1)  # several heartbeat intervals
        assert controller.state is LockdownState.ON and controller.heartbeat.armed
        beats = controller.heartbeat.count
        await asyncio.sleep(0.05)
        assert controller.heartbeat.count > beats  # still beating: the watchdog stays quiet
    finally:
        await controller.leave()


async def test_a_watchdog_trip_turns_the_mode_off_and_says_so(tmp_path: Path) -> None:
    controller, _, _, notices, _ = build(tmp_path)
    assert (await controller.enter()).ok
    controller.heartbeat.armed_flag.unlink()  # what the watchdog does when it restores pf
    await until(lambda: controller.state is LockdownState.OFF)
    assert notices[-1].severity is Severity.CRITICAL and "watchdog" in notices[-1].message


async def test_panic_button_turns_the_tui_red_and_leaving_asks_first(tmp_path: Path) -> None:
    controller, _, _, _, _ = build(tmp_path)
    app = SafemaxxingApp(supervisor(hold=True), lockdown=controller, root=lambda: True)
    async with app.run_test() as pilot:
        await pilot.press("P")
        await wait_for(pilot, lambda: controller.state is LockdownState.ON)
        screen = app.screen_stack[0]
        assert screen.has_class("-lockdown")
        assert "LOCKDOWN ON" in str(app.query_one("#panic").render())
        await pilot.pause(app.BLINK_S + 0.1)
        assert app._blink_timer is not None
        await pilot.press("P")  # leaving reopens egress: it asks
        await pilot.pause()
        assert controller.state is LockdownState.ON
        await pilot.press("y")
        await wait_for(pilot, lambda: controller.state is LockdownState.OFF)
        await wait_for(pilot, lambda: not screen.has_class("-lockdown"))
