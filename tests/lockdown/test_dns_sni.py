from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import struct

import pytest

from safemaxxing.lockdown.dns import (
    DnsError,
    DnsMap,
    DomainBlocklist,
    Record,
    Sinkhole,
    parse_blocklist,
    parse_message,
    system_resolvers,
)
from safemaxxing.lockdown.sni import SniOutcome, parse_client_hello, parse_dump, tcp_payload

# --- DNS wire ------------------------------------------------------------------------------


def query(name: str, ident: int = 0x1234) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def answer(q: bytes, records: list[tuple[int, bytes]]) -> bytes:
    """A reply to `q` whose records all name the question through a pointer (0xc00c)."""
    end = parse_message(q).question_end
    out = bytearray(q[:end])
    out[2:4] = struct.pack("!H", 0x8180)
    out[6:8] = struct.pack("!H", len(records))
    for rtype, rdata in records:
        out += struct.pack("!HHHIH", 0xC00C, rtype, 1, 300, len(rdata)) + rdata
    return bytes(out)


CNAME_TARGET = b"\x05track\x07example\x03net\x00"


def test_parses_compressed_answers() -> None:
    reply = answer(query("cloaked.example.org"), [(5, CNAME_TARGET), (1, bytes([198, 51, 100, 7]))])
    message = parse_message(reply)
    assert message.qname == "cloaked.example.org"
    assert [(r.rtype, r.data) for r in message.answers] == [
        (5, "track.example.net"),
        (1, "198.51.100.7"),
    ]


def test_rejects_a_compression_loop_and_truncation() -> None:
    looped = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c" + b"\0\x01\0\x01"
    with pytest.raises(DnsError):
        parse_message(looped)
    with pytest.raises(DnsError):
        parse_message(query("zoom.us")[:-3])


def test_blocklist_formats_and_suffix_matching() -> None:
    text = "\n".join(
        [
            "# hosts",
            "0.0.0.0 telemetry.zoom.us",
            "127.0.0.1 localhost",
            "10.0.0.1 not-a-sink.example",
            "! abp",
            "||doubleclick.net^",
            "||ads.example.com^$third-party",
            "@@||ok.doubleclick.net^",
            "plain.example.org",
        ]
    )
    blocked, allowed = parse_blocklist(text)
    assert blocked == {"telemetry.zoom.us", "doubleclick.net", "plain.example.org"}
    assert allowed == {"ok.doubleclick.net"}
    lists = DomainBlocklist(blocked, allowed)
    assert lists.blocks("a.b.telemetry.zoom.us") and not lists.blocks("zoom.us")
    assert lists.blocks("x.doubleclick.net") and not lists.blocks("ok.doubleclick.net")


def test_dns_map_keeps_names_for_the_ttl_and_maps_cnames() -> None:
    now = [0.0]
    dns = DnsMap(clock=lambda: now[0])
    dns.record(
        "cdn.example.org",
        [
            Record("cdn.example.org", 5, 30, "edge.example.net"),
            Record("edge.example.net", 1, 30, "198.51.100.7"),
        ],
    )
    assert dns.names("198.51.100.7") == {"cdn.example.org", "edge.example.net"}
    now[0] = 61.0  # the 30 s TTL was clamped up to the 60 s minimum
    assert dns.names("198.51.100.7") == frozenset()


def test_system_resolvers_skip_loopback_and_scope() -> None:
    scutil = """
resolver #1
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
resolver #2
  nameserver[0] : 127.0.0.1
  nameserver[1] : 192.168.1.1
"""
    assert system_resolvers(scutil) == ["192.168.1.1", "fe80::1"]


async def test_sinkhole_end_to_end_over_udp_and_tcp() -> None:
    loop = asyncio.get_running_loop()

    class Upstream(asyncio.DatagramProtocol):
        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            assert isinstance(transport, asyncio.DatagramTransport)
            self.transport = transport

        def datagram_received(self, data: bytes, addr: tuple[str | object, ...]) -> None:
            if parse_message(data).qname == "cloaked.example.org":
                reply = answer(data, [(5, CNAME_TARGET), (1, bytes([198, 51, 100, 7]))])
            else:
                reply = answer(data, [(1, bytes([203, 0, 113, 9]))])
            self.transport.sendto(reply, addr)

    upstream, _ = await loop.create_datagram_endpoint(Upstream, local_addr=("127.0.0.1", 0))
    up_port = upstream.get_extra_info("sockname")[1]
    refused: list[str] = []
    sinkhole = Sinkhole(
        DomainBlocklist({"telemetry.zoom.us", "example.net"}),
        DnsMap(),
        ["127.0.0.1"],
        on_block=refused.append,
        listen=["127.0.0.1"],
        port=25353,
        upstream_port=up_port,
        upstream_ports=(26000, 26999),
    )
    await sinkhole.start()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(2)
    try:

        async def ask(name: str) -> tuple[int, list[str]]:
            client.sendto(query(name), ("127.0.0.1", 25353))
            message = parse_message(await loop.run_in_executor(None, client.recv, 4096))
            return message.flags & 0xF, [r.data for r in message.answers]

        assert await ask("zoom.us") == (0, ["203.0.113.9"])
        assert await ask("telemetry.zoom.us") == (3, [])
        assert await ask("cloaked.example.org") == (3, [])  # CNAME cloaking
        reader, writer = await asyncio.open_connection("127.0.0.1", 25353)
        q = query("zoom.us")
        writer.write(struct.pack("!H", len(q)) + q)
        size = struct.unpack("!H", await reader.readexactly(2))[0]
        assert parse_message(await reader.readexactly(size)).answers[0].data == "203.0.113.9"
        writer.close()
        assert refused == ["telemetry.zoom.us", "track.example.net"]
        assert sinkhole.dns_map.names("203.0.113.9") == {"zoom.us"}
    finally:
        client.close()
        await sinkhole.close()
        upstream.close()


def test_sinkhole_refuses_to_start_without_upstreams() -> None:
    with pytest.raises(ValueError, match="no upstream"):
        Sinkhole(DomainBlocklist(), DnsMap(), [])


# --- SNI -----------------------------------------------------------------------------------


def openssl_client_hello(server_name: str) -> bytes:
    """A real ClientHello from this Python's OpenSSL (1524 bytes on macOS 27.0.1: post-quantum
    key share, so it spans two TCP segments on the wire)."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname=server_name)
    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


def test_sni_from_a_real_client_hello() -> None:
    hello = openssl_client_hello("telemetry.zoom.us")
    assert parse_client_hello(hello).server_name == "telemetry.zoom.us"
    assert parse_client_hello(hello[:200]).outcome is SniOutcome.FOUND
    assert parse_client_hello(hello[:60]).outcome is SniOutcome.TRUNCATED
    assert parse_client_hello(b"\x17\x03\x03\x00\x02ok").outcome is SniOutcome.NOT_CLIENT_HELLO


def tcp_packet(payload: bytes) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", 51544, 443, 1, 1, 0x50, 0x18, 2058, 0, 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        0,
        0,
        64,
        6,
        0,
        ipaddress.IPv4Address("10.0.0.5").packed,
        ipaddress.IPv4Address("203.0.113.9").packed,
    )
    return ip + tcp


def hexdump(packet: bytes) -> list[str]:
    """tcpdump -x layout: 16 bytes a line, in groups of two."""
    lines = []
    for offset in range(0, len(packet), 16):
        chunk = packet[offset : offset + 16].hex()
        groups = " ".join(chunk[i : i + 4] for i in range(0, len(chunk), 4))
        lines.append(f"\t0x{offset:04x}:  {groups}")
    return lines


def test_parse_dump_ties_the_sni_to_the_pktap_process() -> None:
    hello = openssl_client_hello("telemetry.zoom.us")[:1400]
    packet = tcp_packet(hello)
    header = (
        "1793026849.635980 (en0, proc zoom.us:4242, svc BE, out, so) "
        f"IP 10.0.0.5.51544 > 203.0.113.9.443: Flags [P.], seq 1:1401, ack 1, win 2058, length {len(hello)}"
    )
    seen = parse_dump([header, *hexdump(packet)])
    assert seen is not None
    assert (seen.packet.pid, seen.packet.dest_ip) == (4242, "203.0.113.9")
    assert seen.hello.server_name == "telemetry.zoom.us"
    parsed = tcp_payload(packet)
    assert parsed is not None and parsed[1:4] == (51544, "203.0.113.9", 443)
