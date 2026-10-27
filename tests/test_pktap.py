from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import psutil
import pytest
from conftest import make_event

from safemaxxing.correlation import CorrelationEngine
from safemaxxing.models import PKTAP_STATUS, Direction, PktapEvent, Protocol, SensorType
from safemaxxing.pktap import (
    TCPDUMP_BINARY,
    PktapCapture,
    PktapError,
    PktapFlowTracker,
    is_relevant_destination,
    parse_pktap_line,
    pktap_command,
    udp_filter,
)

FIXTURES = Path(__file__).parent / "fixtures" / "pktap"

# Verbatim from `sudo tcpdump -k -n -tt ... -Q ...` on macOS 27.0.1 (testlogs/pktap-*.txt).
MEET_OUT = "1793026849.635980 (en0, proc Brave Browser He:16112, svc BE, out, so) IP 10.243.5.87.64316 > 74.125.250.240.3478: UDP, length 679"
AWDL_OUT = "1793085237.548483 (awdl0, proc replicatord:737, svc BE, out, so) IP6 fe80::6465:c2ff:fe33:a8a8.55477 > fe80::3811:10ff:fedb:ad8a.51304: UDP, length 1200"
# Verbatim apart from the timestamp, printed without -tt in TESTLOG 2026-10-26 14:04.
MEET_IN = "1793026691.457222 (en0, proc Brave Browser He:16112, svc BE, in, so) IP 74.125.250.240.3478 > 10.243.5.87.51784: UDP, length 68"

BRAVE_HELPER_EXE = (
    "/Applications/Brave Browser.app/Contents/Frameworks/Brave Browser Framework.framework/"
    "Versions/1/Helpers/Brave Browser Helper.app/Contents/MacOS/Brave Browser Helper"
)
PROCESSES: dict[int, tuple[str, str | None]] = {
    16112: ("Brave Browser Helper", BRAVE_HELPER_EXE),
    19122: ("WhatsApp", "/Applications/WhatsApp.app/Contents/MacOS/WhatsApp"),
    808: (
        "amsaccountsd",
        "/System/Library/PrivateFrameworks/AppleMediaServices.framework/Resources/amsaccountsd",
    ),
    737: ("replicatord", "/usr/libexec/replicatord"),
}
BUNDLES = {BRAVE_HELPER_EXE: "com.brave.Browser.helper"}


def make_tracker(**overrides: object) -> PktapFlowTracker:
    kwargs: dict[str, object] = {
        "process_lookup": PROCESSES.get,
        "bundle_lookup": BUNDLES.get,
    }
    kwargs.update(overrides)
    return PktapFlowTracker(**kwargs)  # type: ignore[arg-type]


def fixture_packets(name: str) -> list[PktapEvent]:
    lines = (FIXTURES / name).read_text().splitlines()
    return [p for line in lines if (p := parse_pktap_line(line)) is not None]


def make_packet(**overrides: object) -> PktapEvent:
    packet = parse_pktap_line(MEET_OUT)
    assert packet is not None
    fields = {f: getattr(packet, f) for f in PktapEvent.__slots__}
    fields.update(overrides)
    return PktapEvent(**fields)


# --- parser ---------------------------------------------------------------------------------


def test_parses_meet_media_packet() -> None:
    packet = parse_pktap_line(MEET_OUT)
    assert packet == PktapEvent(
        timestamp=1793026849.635980,
        interface="en0",
        pid=16112,
        process_name="Brave Browser He",
        protocol=Protocol.UDP,
        src_ip="10.243.5.87",
        src_port=64316,
        dest_ip="74.125.250.240",
        dest_port=3478,
        direction=Direction.OUTBOUND,
        length=679,
    )


def test_parses_inbound_packet_and_keys_it_from_this_host() -> None:
    packet = parse_pktap_line(MEET_IN)
    assert packet is not None
    assert packet.direction is Direction.INBOUND
    assert packet.flow_key == (16112, Protocol.UDP, "10.243.5.87", 51784, "74.125.250.240", 3478)


def test_parses_ipv6_packet() -> None:
    packet = parse_pktap_line(AWDL_OUT)
    assert packet is not None
    assert (packet.interface, packet.pid, packet.process_name) == ("awdl0", 737, "replicatord")
    assert (packet.src_ip, packet.src_port) == ("fe80::6465:c2ff:fe33:a8a8", 55477)
    assert (packet.dest_ip, packet.dest_port) == ("fe80::3811:10ff:fedb:ad8a", 51304)


@pytest.mark.parametrize(
    "name, packets",
    [
        ("idle.txt", 2),
        ("meet.txt", 40),
        ("meet-pid.txt", 40),
        ("youtube.txt", 68),
        ("youtube-buf.txt", 40),
    ],
)
def test_every_captured_line_parses(name: str, packets: int) -> None:
    lines = [line for line in (FIXTURES / name).read_text().splitlines() if line]
    assert len(lines) == packets
    assert all(parse_pktap_line(line) is not None for line in lines)


@pytest.mark.parametrize(
    "rest, length",
    [
        # Synthetic: tcpdump's -q TCP form, and the full form without -q.
        ("tcp 0", 0),
        ("Flags [S], seq 1, win 65535, options [mss 1460], length 0", 0),
        ("Flags [P.], seq 1:518, ack 1, win 2058, length 517", 517),
    ],
)
def test_parses_tcp_forms(rest: str, length: int) -> None:
    line = f"1793026849.635980 (en0, proc curl:999, svc BE, out, so) IP 10.0.0.5.50000 > 1.1.1.1.443: {rest}"
    packet = parse_pktap_line(line)
    assert packet is not None
    assert (packet.protocol, packet.length) == (Protocol.TCP, length)


def test_parses_effective_process() -> None:
    # Synthetic: the `eproc` field pktap adds for a socket used on another process's behalf.
    line = "1793026849.635980 (en0, proc nsurlsessiond:400, eproc Spy:4242, svc BE, out, so) IP 10.0.0.5.50000 > 203.0.113.9.443: UDP, length 10"
    packet = parse_pktap_line(line)
    assert packet is not None
    assert (packet.pid, packet.process_name) == (400, "nsurlsessiond")
    assert (packet.effective_pid, packet.effective_process_name) == (4242, "Spy")


def test_process_name_cannot_forge_metadata_fields() -> None:
    # A 15-character name crafted to look like `pid 1, inbound`; the real fields follow it.
    line = "1793026849.635980 (en0, proc a:1, svc BE, in:666, svc BE, out, so) IP 10.0.0.5.50000 > 203.0.113.9.443: UDP, length 10"
    packet = parse_pktap_line(line)
    assert packet is not None
    assert (packet.pid, packet.process_name) == (666, "a:1, svc BE, in")
    assert packet.direction is Direction.OUTBOUND


@pytest.mark.parametrize(
    "line",
    [
        "",
        "listening on pktap,all, link-type PKTAP (Apple DLT_PKTAP), snapshot length 524288 bytes",
        "1793026849.635980 (en0, proc ping:5, svc BE, out, so) IP 10.0.0.5 > 1.1.1.1: ICMP echo request, id 1, seq 0, length 64",
        "1793026849.635980 (en0, proc x:5, svc BE, out, so) IP 10.0.0.5.70000 > 1.1.1.1.53: UDP, length 1",
        "1793026849.635980 (en0, proc x:5, svc BE, out, so) IP 10.0.0.999.5000 > 1.1.1.1.53: UDP, length 1",
        "1793026849.635980 (en0, proc this-name-is-too-long:5, svc BE, out, so) IP 10.0.0.5.5000 > 1.1.1.1.53: UDP, length 1",
        # Verbatim (testlogs/pktap-meet-buf.txt, 3150 of 9076 lines): llw0 carries no process.
        "1793086443.141005 (llw0, svc BE, out, ch) IP6 fdcb:5bd0:633f::13.58272 > fd0c:cc11:ad0c::1c.50020: UDP, length 50",
    ],
)
def test_rejects_other_lines(line: str) -> None:
    assert parse_pktap_line(line) is None


# --- filtering and flows --------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip, relevant",
    [
        ("74.125.250.240", True),
        ("10.0.0.1", True),  # the LAN is still somewhere data can go
        ("2001:4860:4860::8888", True),
        ("fe80::3811:10ff:fedb:ad8a", False),  # AWDL, link-local
        ("169.254.1.1", False),
        ("224.0.0.251", False),  # mDNS
        ("ff02::fb", False),
        ("255.255.255.255", False),
        ("0.0.0.0", False),
        ("127.0.0.1", False),
        ("not-an-ip", False),
    ],
)
def test_relevant_destinations(ip: str, relevant: bool) -> None:
    assert is_relevant_destination(ip) is relevant


def test_loopback_kept_on_request() -> None:
    assert is_relevant_destination("::1", include_loopback=True)


def test_meet_call_is_one_connection_named_from_the_process() -> None:
    tracker = make_tracker()
    packets = fixture_packets("meet.txt")
    conns = [c for p in packets if (c := tracker.feed(p)) is not None]
    assert len(conns) == 1
    conn = conns[0]
    assert (conn.pid, conn.process_name, conn.bundle_id) == (
        16112,
        "Brave Browser Helper",
        "com.brave.Browser.helper",
    )
    assert (conn.protocol, conn.remote, conn.local_port) == (
        Protocol.UDP,
        "74.125.250.240:3478",
        64316,
    )
    assert (conn.status, conn.first_seen, conn.exe_path) == (
        PKTAP_STATUS,
        packets[0].timestamp,
        BRAVE_HELPER_EXE,
    )


def test_idle_capture_gives_whatsapp_connection() -> None:
    tracker = make_tracker()
    conns = [c for p in fixture_packets("idle.txt") if (c := tracker.feed(p)) is not None]
    assert [(c.process_name, c.remote) for c in conns] == [("WhatsApp", "57.144.249.32:443")]


@pytest.mark.parametrize("name", ["youtube.txt", "youtube-buf.txt"])
def test_system_and_link_local_traffic_dropped(name: str) -> None:
    tracker = make_tracker()
    assert [c for p in fixture_packets(name) if (c := tracker.feed(p)) is not None] == []


def test_kernel_netbios_broadcast_dropped_as_system() -> None:
    # Synthetic line for the root run of 2026-10-27: `kernel_task 0 10.244.255.255:137`.
    line = "1793085900.000000 (en0, proc kernel_task:0, svc BE, out, so) IP 10.244.165.228.137 > 10.244.255.255.137: UDP, length 50"
    packet = parse_pktap_line(line)
    assert packet is not None
    # psutil names pid 0 but reports no executable path for it.
    kernel = {0: ("kernel_task", None)}
    assert make_tracker(process_lookup=kernel.get).feed(packet) is None
    kept = make_tracker(process_lookup=kernel.get, include_system=True).feed(packet)
    assert kept is not None and kept.remote == "10.244.255.255:137"


def test_include_system_keeps_sip_binaries_but_not_link_local() -> None:
    tracker = make_tracker(include_system=True)
    conns = [c for p in fixture_packets("youtube.txt") if (c := tracker.feed(p)) is not None]
    assert [(c.process_name, c.remote) for c in conns] == [("amsaccountsd", "17.253.122.199:443")]


def test_flow_idle_too_long_counts_again() -> None:
    tracker = make_tracker(idle_s=10.0)
    t = 1793026849.0
    assert tracker.feed(make_packet(timestamp=t)) is not None
    assert tracker.feed(make_packet(timestamp=t + 9.0)) is None
    assert tracker.feed(make_packet(timestamp=t + 18.5)) is None
    assert tracker.feed(make_packet(timestamp=t + 30.0)) is not None


def test_inbound_packets_keep_a_flow_alive_but_never_open_one() -> None:
    tracker = make_tracker(idle_s=10.0)
    t = 1793026849.0
    inbound = {
        "direction": Direction.INBOUND,
        "src_ip": "74.125.250.240",
        "src_port": 3478,
        "dest_ip": "10.243.5.87",
        "dest_port": 64316,
    }
    assert tracker.feed(make_packet(timestamp=t - 1, **inbound)) is None
    assert tracker.feed(make_packet(timestamp=t)) is not None
    assert tracker.feed(make_packet(timestamp=t + 8, **inbound)) is None
    assert tracker.feed(make_packet(timestamp=t + 16)) is None


def test_process_is_looked_up_per_new_flow_never_cached() -> None:
    calls: list[int] = []

    def lookup(pid: int) -> tuple[str, str | None] | None:
        calls.append(pid)
        return None if len(calls) == 1 else ("cloudd", "/System/Library/cloudd")

    tracker = make_tracker(process_lookup=lookup)
    gone = tracker.feed(make_packet())
    assert gone is not None
    assert (gone.process_name, gone.exe_path, gone.bundle_id) == ("Brave Browser He", None, None)
    # The pid now belongs to a SIP binary: a new flow is looked up again and dropped.
    assert tracker.feed(make_packet(src_port=60000)) is None
    assert calls == [16112, 16112]


def test_flow_table_is_bounded() -> None:
    tracker = make_tracker(max_flows=4)
    t = 1793026849.0
    for port in range(10):
        assert tracker.feed(make_packet(timestamp=t + port, src_port=50000 + port)) is not None
    assert len(tracker._last_packet) <= 4


def test_meet_flow_correlates_with_brave_microphone() -> None:
    tracker = make_tracker()
    first = fixture_packets("meet.txt")[0]
    engine = CorrelationEngine(clock=lambda: first.timestamp)
    # The mic check came from Brave's main process; the media socket is its NetworkService.
    mic = make_event(
        timestamp=first.timestamp - 1.1,
        sensor=SensorType.MICROPHONE,
        pid=6254,
        process_name="Brave Browser",
        bundle_id="com.brave.Browser",
    )
    assert engine.ingest_event(mic) == []
    conn = tracker.feed(first)
    assert conn is not None
    [alert] = engine.ingest_connection(conn)
    assert alert.summary == (
        "com.brave.Browser used microphone then connected to 74.125.250.240:3478 after 1100 ms"
    )


def test_command_line() -> None:
    assert pktap_command() == [
        TCPDUMP_BINARY,
        "-k",
        "-n",
        "-q",
        "-tt",
        "-l",
        "--immediate-mode",
        "-i",
        "pktap,all",
        "-Q",
        "dir=out",
        "udp and not port 53 and not port 853 and not port 5353",
    ]
    assert pktap_command(bpf_filter=None, metadata_filter="pid = 16112")[-2:] == [
        "-Q",
        "pid = 16112",
    ]
    assert pktap_command(bpf_filter=udp_filter(include_dns=True))[-1] == "udp"


# --- subprocess -----------------------------------------------------------------------------


def fake_tcpdump(tmp_path: Path, body: str) -> list[str]:
    script = tmp_path / "fake_tcpdump.py"
    script.write_text(body)
    return [sys.executable, str(script)]


def reaped(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


async def test_capture_yields_connections_from_a_recorded_stream(tmp_path: Path) -> None:
    command = fake_tcpdump(
        tmp_path,
        "import sys\n"
        "sys.stdout.write(open(sys.argv[1]).read())\n"
        "sys.stdout.write('not a packet line\\n')\n",
    )
    capture = PktapCapture([*command, str(FIXTURES / "meet.txt")], tracker=make_tracker())
    conns = [c async for c in capture.connections()]
    assert [(c.pid, c.remote) for c in conns] == [(16112, "74.125.250.240:3478")]
    assert capture.unparsed == 1


async def test_capture_error_carries_stderr(tmp_path: Path) -> None:
    command = fake_tcpdump(
        tmp_path,
        "import sys\n"
        "sys.stderr.write('tcpdump: pktap,all: You don\\'t have permission to capture\\n')\n"
        "sys.exit(1)\n",
    )
    with pytest.raises(PktapError, match="exited with 1: tcpdump: pktap,all: You don't have"):
        [p async for p in PktapCapture(command).events()]


@pytest.mark.parametrize("ignore_sigterm", [False, True])
async def test_leaving_early_stops_and_reaps_tcpdump(tmp_path: Path, ignore_sigterm: bool) -> None:
    trap = "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n" if ignore_sigterm else ""
    command = fake_tcpdump(
        tmp_path,
        f"import signal, time\n{trap}print({MEET_OUT!r}, flush=True)\ntime.sleep(60)\n",
    )
    capture = PktapCapture(command, tracker=make_tracker(), stop_timeout_s=0.2)
    events = capture.events()
    packet = await anext(events)
    assert packet.pid == 16112
    pids = await asyncio.to_thread(_child_pids)
    await events.aclose()
    assert pids and all(reaped(p) for p in pids)


async def test_cancelled_consumer_stops_and_reaps_tcpdump(tmp_path: Path) -> None:
    command = fake_tcpdump(
        tmp_path, f"import time\nprint({MEET_OUT!r}, flush=True)\ntime.sleep(60)\n"
    )
    capture = PktapCapture(command, tracker=make_tracker())
    started = asyncio.Event()

    async def consume() -> None:
        async for _ in capture.connections():
            started.set()

    task = asyncio.create_task(consume())
    await asyncio.wait_for(started.wait(), 5)
    pids = await asyncio.to_thread(_child_pids)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert pids and all(reaped(p) for p in pids)


def _child_pids() -> list[int]:
    return [c.pid for c in psutil.Process().children(recursive=True)]
