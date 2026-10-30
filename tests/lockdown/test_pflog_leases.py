from __future__ import annotations

import asyncio
import ipaddress
import struct

import pytest

from safemaxxing.lockdown.leases import Lease, LeaseBook, LeaseSource, LeaseState
from safemaxxing.lockdown.pflog import PFLOG_HDRLEN, PcapReader, parse_pflog
from safemaxxing.lockdown.rules import Grant
from safemaxxing.models import Protocol

# --- pflog ---------------------------------------------------------------------------------


def pfloghdr(af: int = 2, action: int = 1, direction: int = 2, pid: int = 100000) -> bytes:
    """A Darwin `struct pfloghdr` (layout in pflog.py); NO_PID by default."""
    header = struct.pack(
        "=BBBB16s16s4s4siiiiB3x",
        61,
        af,
        action,
        0,
        b"en0",
        b"com.apple/safemaxxing",
        struct.pack("!I", 16),
        struct.pack("!I", 0),
        501,
        pid,
        -1,
        -1,
        direction,
    )
    assert len(header) == PFLOG_HDRLEN
    return header


def ipv4_tcp(src: str, sport: int, dst: str, dport: int) -> bytes:
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        0,
        0,
        64,
        6,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    return ip + struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x02, 65535, 0, 0)


def ipv6_udp(src: str, sport: int, dst: str, dport: int) -> bytes:
    ip = struct.pack(
        "!IHBB16s16s",
        0x60000000,
        8,
        17,
        64,
        ipaddress.IPv6Address(src).packed,
        ipaddress.IPv6Address(dst).packed,
    )
    return ip + struct.pack("!HHHH", sport, dport, 8, 0)


def pcap(records: list[bytes]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 117)
    for i, data in enumerate(records):
        out += struct.pack("<IIII", 1793026849 + i, 500000, len(data), len(data)) + data
    return out


def test_parses_dropped_outbound_packets() -> None:
    v4 = parse_pflog(pfloghdr() + ipv4_tcp("10.0.0.5", 51544, "203.0.113.9", 443), 1.0)
    assert v4 is not None
    assert (v4.protocol, v4.src_port, v4.dst, v4.dst_port, v4.pid) == (
        Protocol.TCP,
        51544,
        "203.0.113.9",
        443,
        None,
    )
    v6 = parse_pflog(
        pfloghdr(af=30, pid=4242) + ipv6_udp("2001:db8::5", 53266, "2001:db8::1", 8801), 1.0
    )
    assert v6 is not None and v6.protocol is Protocol.UDP and v6.pid == 4242


@pytest.mark.parametrize("header", [pfloghdr(action=0), pfloghdr(direction=1), pfloghdr(af=7)])
def test_ignores_passes_inbound_and_other_families(header: bytes) -> None:
    assert parse_pflog(header + ipv4_tcp("10.0.0.5", 1, "203.0.113.9", 443), 1.0) is None


def test_pcap_reader_handles_any_chunking() -> None:
    stream = pcap(
        [pfloghdr() + ipv4_tcp("10.0.0.5", 50000 + i, "203.0.113.9", 443) for i in range(3)]
    )
    reader = PcapReader()
    records = [r for i in range(0, len(stream), 7) for r in reader.feed(stream[i : i + 7])]
    assert [round(ts, 1) for ts, _ in records] == [1793026849.5, 1793026850.5, 1793026851.5]
    with pytest.raises(ValueError, match="link type"):
        list(PcapReader(linktype=1).feed(stream))


# --- leases --------------------------------------------------------------------------------

GRANT = Grant(Protocol.UDP, "203.0.113.9", 8801)
FAST = {LeaseSource.SENSOR: 0.05, LeaseSource.FOREGROUND: 0.02, LeaseSource.MANUAL: 0.0}


def book() -> tuple[LeaseBook, list[Lease]]:
    revoked: list[Lease] = []

    async def on_revoke(lease: Lease) -> None:
        revoked.append(lease)

    return LeaseBook(on_revoke, grace_s=FAST), revoked


async def test_lease_drains_then_is_revoked_after_its_grace() -> None:
    leases, revoked = book()
    leases.hold("us.zoom.xos", LeaseSource.SENSOR).grants.add(GRANT)
    leases.release("us.zoom.xos", LeaseSource.SENSOR)
    lease = leases.get("us.zoom.xos")
    assert lease is not None and lease.state is LeaseState.DRAINING
    assert leases.active("us.zoom.xos") is None  # draining learns nothing new
    await asyncio.sleep(0.1)
    assert leases.get("us.zoom.xos") is None
    assert [r.grants for r in revoked] == [{GRANT}]


async def test_a_source_coming_back_while_draining_keeps_the_grants() -> None:
    leases, revoked = book()
    leases.hold("us.zoom.xos", LeaseSource.SENSOR).grants.add(GRANT)
    leases.release("us.zoom.xos", LeaseSource.SENSOR)
    await asyncio.sleep(0.02)
    leases.hold("us.zoom.xos", LeaseSource.SENSOR)
    await asyncio.sleep(0.1)
    lease = leases.active("us.zoom.xos")
    assert lease is not None and lease.grants == {GRANT} and revoked == []


async def test_grace_is_the_longest_of_the_sources_it_had() -> None:
    leases, revoked = book()
    leases.hold("us.zoom.xos", LeaseSource.SENSOR)
    leases.hold("us.zoom.xos", LeaseSource.FOREGROUND)
    leases.release("us.zoom.xos", LeaseSource.FOREGROUND)
    assert leases.active("us.zoom.xos") is not None  # the sensor still holds it
    leases.release("us.zoom.xos", LeaseSource.SENSOR)
    await asyncio.sleep(0.03)
    assert leases.get("us.zoom.xos") is not None  # sensor grace (0.05), not foreground's
    await asyncio.sleep(0.06)
    assert len(revoked) == 1


async def test_manual_release_and_revoke_now_are_immediate() -> None:
    leases, revoked = book()
    leases.hold("org.example.chat", LeaseSource.MANUAL)
    leases.release("org.example.chat", LeaseSource.MANUAL)
    leases.hold("us.zoom.xos", LeaseSource.SENSOR)
    leases.revoke_now("us.zoom.xos")
    await asyncio.sleep(0)
    assert [r.bundle_id for r in revoked] == ["org.example.chat", "us.zoom.xos"]


async def test_set_holders_holds_new_and_releases_missing() -> None:
    leases, _ = book()
    leases.set_holders(LeaseSource.SENSOR, ["us.zoom.xos", "com.brave.Browser"])
    leases.set_holders(LeaseSource.SENSOR, ["com.brave.Browser"])
    zoom = leases.get("us.zoom.xos")
    assert zoom is not None and zoom.state is LeaseState.DRAINING
    assert leases.active("com.brave.Browser") is not None
