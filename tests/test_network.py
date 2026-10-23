from __future__ import annotations

import asyncio
import os
import plistlib
import threading
import time
from pathlib import Path

from conftest import T0, make_conn

from safemaxxing.models import NetworkConnection, Protocol
from safemaxxing.network import (
    HostnameResolver,
    NetworkMonitor,
    bundle_id_for_exe,
    outbound_only,
    parse_lsof,
)

LSOF_OUTPUT = """p4242
cSpy
f12
PTCP
n10.0.0.5:51544->203.0.113.9:443
TST=ESTABLISHED
TQR=0
f13
PTCP
n*:8080
TST=LISTEN
f14
PUDP
n[fe80::1]:5353->[2001:db8::1]:53
p99
cnode
f20
PTCP
n127.0.0.1:60000->127.0.0.1:5432
TST=ESTABLISHED
"""


def test_parse_lsof() -> None:
    conns = parse_lsof(LSOF_OUTPUT, T0)
    assert len(conns) == 3
    tcp, udp, local = conns
    assert (tcp.pid, tcp.process_name, tcp.protocol) == (4242, "Spy", Protocol.TCP)
    assert (tcp.remote_address, tcp.remote_port, tcp.status) == ("203.0.113.9", 443, "ESTABLISHED")
    assert udp.protocol is Protocol.UDP
    assert udp.remote_address == "2001:db8::1"
    assert udp.remote == "[2001:db8::1]:53"
    assert local.pid == 99 and local.is_loopback


def test_outbound_filters_listen_inbound_and_loopback() -> None:
    listener = make_conn(local_port=8080, remote_address="", remote_port=0, status="LISTEN")
    inbound = make_conn(local_port=8080, remote_address="198.51.100.7", remote_port=50000)
    outbound = make_conn()
    closing = make_conn(local_port=1, status="TIME_WAIT")
    loop = make_conn(local_port=2, remote_address="127.0.0.1")
    kept = outbound_only([listener, inbound, outbound, closing, loop])
    assert kept == [outbound]
    assert loop in outbound_only([loop], include_loopback=True)


def test_bundle_id_uses_outermost_app(tmp_path: Path) -> None:
    app = tmp_path / "Google Chrome.app"
    (app / "Contents").mkdir(parents=True)
    with open(app / "Contents" / "Info.plist", "wb") as fh:
        plistlib.dump({"CFBundleIdentifier": "com.google.Chrome"}, fh)
    helper = app / "Contents/Frameworks/Helper.app/Contents/MacOS/Helper"
    assert bundle_id_for_exe(str(helper)) == "com.google.Chrome"
    assert bundle_id_for_exe("/usr/bin/curl") is None


def test_monitor_reports_only_new_connections() -> None:
    snapshots: list[list[NetworkConnection]] = [
        [make_conn(first_seen=T0)],
        [make_conn(first_seen=T0 + 1), make_conn(local_port=1, first_seen=T0 + 1)],
        [make_conn(local_port=1, first_seen=T0 + 2)],
    ]
    monitor = NetworkMonitor(snapshot=lambda now: snapshots.pop(0))
    assert len(monitor.poll_once(T0)) == 1
    fresh = monitor.poll_once(T0 + 1)
    assert [c.local_port for c in fresh] == [1]
    assert monitor.poll_once(T0 + 2) == []
    (active,) = monitor.active
    assert active.local_port == 1 and active.first_seen == T0 + 1


async def test_resolver_times_out_fast_and_caches_late_answer() -> None:
    release = threading.Event()

    def slow_lookup(ip: str) -> str | None:
        release.wait(5)
        return "late.example"

    resolver = HostnameResolver(timeout_s=0.05, lookup=slow_lookup)
    start = time.perf_counter()
    assert await resolver.resolve("8.8.8.8") is None
    assert time.perf_counter() - start < 0.5
    release.set()
    for _ in range(100):
        if resolver.cached("8.8.8.8"):
            break
        await asyncio.sleep(0.01)
    assert resolver.cached("8.8.8.8") == "late.example"
    resolver.close()


async def test_resolver_skips_private_and_bounds_pending() -> None:
    calls: list[str] = []
    block = threading.Event()

    def lookup(ip: str) -> str | None:
        calls.append(ip)
        block.wait(5)
        return None

    resolver = HostnameResolver(timeout_s=0.01, lookup=lookup, max_pending=2, max_workers=1)
    assert await resolver.resolve("10.0.0.1") is None
    for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1"):
        resolver.prefetch(ip)
    await asyncio.sleep(0.05)
    assert "10.0.0.1" not in calls
    assert len(calls) <= 2
    block.set()
    resolver.close()


async def test_poller_not_blocked_by_hung_dns() -> None:
    hang = threading.Event()

    def hung(ip: str) -> str | None:
        hang.wait(5)
        return None

    resolver = HostnameResolver(lookup=hung)
    polls: list[float] = []
    batches = iter(
        [
            [],
            [make_conn(remote_address="8.8.8.8")],
            [make_conn(local_port=2, remote_address="8.8.4.4")],
        ]
    )

    def snapshot(now: float) -> list[NetworkConnection]:
        polls.append(now)
        return next(batches, [])

    monitor = NetworkMonitor(snapshot=snapshot, interval_s=0.02, resolver=resolver)
    start = time.perf_counter()
    stream = monitor.connections()
    got = [await anext(stream), await anext(stream)]
    assert [c.local_port for c in got] == [51544, 2]
    assert time.perf_counter() - start < 1.0
    await stream.aclose()
    hang.set()
    resolver.close()


async def test_active_picks_up_hostname_once_resolved() -> None:
    resolver = HostnameResolver(lookup=lambda ip: "dst.example")
    monitor = NetworkMonitor(
        snapshot=lambda now: [make_conn(remote_address="8.8.8.8")], resolver=resolver
    )
    (fresh,) = monitor.poll_once(T0)
    assert fresh.hostname is None
    assert await resolver.resolve("8.8.8.8") == "dst.example"
    assert monitor.active[0].hostname == "dst.example"
    resolver.close()


def test_bundle_id_survives_hostile_info_plists(tmp_path: Path) -> None:
    # Any running app's Info.plist is read: a broken, oversized or non-regular one must not
    # raise or block the caller.
    broken = tmp_path / "Broken.app" / "Contents"
    broken.mkdir(parents=True)
    (broken / "Info.plist").write_text('<?xml version="1.0"?><plist><dict><key>CFBundle')
    huge = tmp_path / "Huge.app" / "Contents"
    huge.mkdir(parents=True)
    with open(huge / "Info.plist", "wb") as fh:
        plistlib.dump({"CFBundleIdentifier": "com.example.huge", "pad": "x" * (2 << 20)}, fh)
    fifo = tmp_path / "Fifo.app" / "Contents"
    fifo.mkdir(parents=True)
    os.mkfifo(fifo / "Info.plist")
    results: dict[str, str | None] = {}

    def lookup() -> None:
        for app in ("Broken", "Huge", "Fifo"):
            results[app] = bundle_id_for_exe(str(tmp_path / f"{app}.app/Contents/MacOS/{app}"))

    worker = threading.Thread(target=lookup, daemon=True)
    worker.start()
    worker.join(timeout=2.0)
    assert not worker.is_alive(), "blocked on a FIFO Info.plist"
    assert results == {"Broken": None, "Huge": None, "Fifo": None}
