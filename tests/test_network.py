from __future__ import annotations

import plistlib
from pathlib import Path

from conftest import T0, make_conn

from safemaxxing.models import NetworkConnection, Protocol
from safemaxxing.network import NetworkMonitor, bundle_id_for_exe, outbound_only, parse_lsof

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
