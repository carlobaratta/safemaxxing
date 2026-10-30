"""TLS ClientHello SNI from pktap, to audit where a *granted* app's TLS actually goes.

It runs after a grant, not before: the default-deny rule drops a SYN before any ClientHello
exists, so SNI cannot decide a grant, only check one. The capture keeps just the packet that
starts a ClientHello (BPF on the TLS record and handshake type bytes), with pktap's process
metadata and a hex dump (`-x`) of the packet.

Limits, by design rather than by bug: a ClientHello split across two TCP segments (common
with post-quantum key shares, ~1.8 KB) yields its SNI only when the extension sits in the
first segment; Encrypted Client Hello shows only its public outer name; QUIC (UDP 443) is
not parsed. In those cases the DNS map is the only name the flow has.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
import struct
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from enum import StrEnum

from safemaxxing.models import PktapEvent
from safemaxxing.pktap import TCPDUMP_BINARY, parse_pktap_line

EXT_SERVER_NAME = 0x0000
EXT_ECH = 0xFE0D
_IPV4_CLIENT_HELLO = (
    "(tcp dst port 443"
    " and tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16"
    " and tcp[((tcp[12:1] & 0xf0) >> 2) + 5:1] = 0x01)"
)
_IPV6_CLIENT_HELLO = (
    "(ip6 and ip6[6] = 6 and tcp dst port 443"
    " and ip6[40 + ((ip6[52] & 0xf0) >> 2)] = 0x16"
    " and ip6[45 + ((ip6[52] & 0xf0) >> 2)] = 0x01)"
)
CLIENT_HELLO_FILTER = f"{_IPV4_CLIENT_HELLO} or {_IPV6_CLIENT_HELLO}"
_HEX_RE = re.compile(r"^\s+0x[0-9a-f]+:\s+((?:[0-9a-f]{2,4}\s?)+)")


class SniOutcome(StrEnum):
    """What a ClientHello said about its destination name."""

    FOUND = "found"
    NO_SNI = "no_sni"
    TRUNCATED = "truncated"
    NOT_CLIENT_HELLO = "not_client_hello"


@dataclass(frozen=True, slots=True)
class ClientHello:
    """The SNI of one ClientHello, and whether it offered ECH (then SNI is the outer name)."""

    outcome: SniOutcome
    server_name: str | None = None
    ech: bool = False


class _Truncated(Exception):
    pass


class _Cursor:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, size: int) -> bytes:
        if self.pos + size > len(self.data):
            raise _Truncated
        chunk = self.data[self.pos : self.pos + size]
        self.pos += size
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int(struct.unpack("!H", self.take(2))[0])

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")


def parse_client_hello(payload: bytes) -> ClientHello:
    """SNI from the start of a TCP payload holding a TLS record with a ClientHello.

    Reads as far as the bytes go: an SNI found before the end is FOUND even if the rest of
    the hello is in the next segment.
    """
    cur = _Cursor(payload)
    server_name: str | None = None
    ech = False
    try:
        if cur.u8() != 0x16:
            return ClientHello(SniOutcome.NOT_CLIENT_HELLO)
        cur.take(4)  # record version, record length
        if cur.u8() != 0x01:
            return ClientHello(SniOutcome.NOT_CLIENT_HELLO)
        cur.u24()
        cur.take(2 + 32)  # client_version, random
        cur.take(cur.u8())  # session id
        cur.take(cur.u16())  # cipher suites
        cur.take(cur.u8())  # compression methods
        end = cur.pos + cur.u16()
        while cur.pos < end:
            ext_type, ext_len = cur.u16(), cur.u16()
            if ext_type == EXT_ECH:
                ech = True
                cur.take(ext_len)
            elif ext_type == EXT_SERVER_NAME:
                body = _Cursor(cur.take(ext_len))
                body.u16()  # server_name_list length
                if body.u8() == 0:  # host_name
                    name = body.take(body.u16()).decode("ascii", "replace").lower()
                    server_name = name.rstrip(".") or None
            else:
                cur.take(ext_len)
    except _Truncated:
        if server_name is None:
            return ClientHello(SniOutcome.TRUNCATED, None, ech)
    if server_name is None:
        return ClientHello(SniOutcome.NO_SNI, None, ech)
    return ClientHello(SniOutcome.FOUND, server_name, ech)


def tcp_payload(packet: bytes) -> tuple[str, int, str, int, bytes] | None:
    """(source, sport, destination, dport, payload) of an IPv4/IPv6 TCP packet."""
    if not packet:
        return None
    src: ipaddress.IPv4Address | ipaddress.IPv6Address
    dst: ipaddress.IPv4Address | ipaddress.IPv6Address
    if packet[0] >> 4 == 4 and len(packet) >= 20 and packet[9] == 6:
        ihl = (packet[0] & 0x0F) * 4
        total = struct.unpack_from("!H", packet, 2)[0]
        src, dst = ipaddress.IPv4Address(packet[12:16]), ipaddress.IPv4Address(packet[16:20])
        segment = packet[ihl:total]
    elif packet[0] >> 4 == 6 and len(packet) >= 40 and packet[6] == 6:
        plen = struct.unpack_from("!H", packet, 4)[0]
        src, dst = ipaddress.IPv6Address(packet[8:24]), ipaddress.IPv6Address(packet[24:40])
        segment = packet[40 : 40 + plen]
    else:
        return None
    if len(segment) < 20:
        return None
    sport, dport = struct.unpack_from("!HH", segment)
    offset = (segment[12] >> 4) * 4
    return str(src), sport, str(dst), dport, segment[offset:]


def client_hello_command(interface: str = "pktap,all") -> list[str]:
    """`tcpdump` with pktap metadata (`-k`) and a hex dump (`-x`) of each ClientHello start."""
    return [
        TCPDUMP_BINARY,
        "-k",
        "-n",
        "-tt",
        "-l",
        "--immediate-mode",
        "-x",
        "-s",
        "1600",
        "-i",
        interface,
        "-Q",
        "dir=out",
        CLIENT_HELLO_FILTER,
    ]


@dataclass(frozen=True, slots=True)
class ClientHelloSeen:
    """A ClientHello a process sent, with the pid pktap attributed it to."""

    packet: PktapEvent
    hello: ClientHello


def parse_dump(lines: Sequence[str]) -> ClientHelloSeen | None:
    """One packet's header line plus its `-x` hex lines -> who sent which SNI."""
    if not lines:
        return None
    header = parse_pktap_line(lines[0])
    if header is None:
        return None
    hexdigits = "".join(
        m.group(1).replace(" ", "") for line in lines[1:] if (m := _HEX_RE.match(line))
    )
    try:
        parsed = tcp_payload(bytes.fromhex(hexdigits))
    except ValueError:
        return None
    if parsed is None:
        return None
    return ClientHelloSeen(header, parse_client_hello(parsed[4]))


async def client_hellos(command: Sequence[str] | None = None) -> AsyncIterator[ClientHelloSeen]:
    """ClientHellos as they leave; tcpdump is always stopped and reaped."""
    proc = await asyncio.create_subprocess_exec(
        *(command or client_hello_command()),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    assert proc.stdout is not None
    pending: list[str] = []
    try:
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").rstrip("\n")
            if _HEX_RE.match(line):
                pending.append(line)
                continue
            if seen := parse_dump(pending):
                yield seen
            pending = [line]
        if seen := parse_dump(pending):
            yield seen
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), 2.0)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.wait()
