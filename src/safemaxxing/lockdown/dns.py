"""DNS sinkhole for Paranoia Mode: block tracker and C2 names, and learn which name an IP
was resolved from.

On macOS every lookup goes through mDNSResponder, so a query on the wire never carries the
app's pid; what it does carry is the name, and the answer ties that name to the IPs the app
connects to next. In lockdown pf redirects every outbound :53 query to this forwarder
(`route-to lo0` + `rdr`, see rules.py). It answers NXDOMAIN for a blocked name, or for an
answer whose CNAME chain reaches one (CNAME cloaking), and forwards the rest to the resolvers
the system had, from a privileged source port so that pf can let only it through.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import ipaddress
import os
import random
import re
import socket
import struct
import tempfile
import time
import urllib.request
from collections import OrderedDict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from safemaxxing.firewall import STATE_DIR
from safemaxxing.lockdown.rules import SINKHOLE_PORT, SINKHOLE_UPSTREAM_PORTS

TYPE_A = 1
TYPE_CNAME = 5
TYPE_AAAA = 28
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
_FLAG_TC = 0x0200
BLOCKLIST_CACHE = STATE_DIR / "dns-blocklist.txt"
# Default source: Steven Black's unified hosts (adware + malware), MIT licensed.
DEFAULT_BLOCKLIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
MAX_BLOCKLIST_BYTES = 32 * 1024 * 1024


class DnsError(ValueError):
    """A malformed DNS message."""


@dataclass(frozen=True, slots=True)
class Record:
    """One answer record: an address for A/AAAA, the target for CNAME, '' otherwise."""

    name: str
    rtype: int
    ttl: int
    data: str


@dataclass(frozen=True, slots=True)
class Message:
    """The parts of a DNS message the sinkhole needs."""

    id: int
    flags: int
    qname: str | None
    qtype: int | None
    question_end: int
    answers: tuple[Record, ...]

    @property
    def truncated(self) -> bool:
        """Whether the TC bit is set (retry over TCP)."""
        return bool(self.flags & _FLAG_TC)


def _read_name(buf: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) name at `offset`; return it and the offset after it."""
    labels: list[str] = []
    end: int | None = None
    jumps = 0
    while True:
        if offset >= len(buf):
            raise DnsError("name runs past the message")
        length = buf[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise DnsError("truncated compression pointer")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | buf[offset + 1]
            jumps += 1
            if jumps > 64:
                raise DnsError("compression loop")
            continue
        if length & 0xC0:
            raise DnsError("unsupported label type")
        offset += 1
        if length == 0:
            break
        if offset + length > len(buf):
            raise DnsError("label runs past the message")
        labels.append(buf[offset : offset + length].decode("ascii", "replace").lower())
        offset += length
    return ".".join(labels), end if end is not None else offset


def parse_message(buf: bytes) -> Message:
    """Header, first question and answer records of `buf`; raises DnsError when malformed."""
    if len(buf) < 12:
        raise DnsError("shorter than a header")
    ident, flags, qdcount, ancount, _ns, _ar = struct.unpack_from("!HHHHHH", buf)
    offset = 12
    qname = qtype = None
    for i in range(qdcount):
        name, offset = _read_name(buf, offset)
        if offset + 4 > len(buf):
            raise DnsError("truncated question")
        if i == 0:
            qname, qtype = name, struct.unpack_from("!H", buf, offset)[0]
        offset += 4
    question_end = offset
    answers: list[Record] = []
    for _ in range(ancount):
        name, offset = _read_name(buf, offset)
        if offset + 10 > len(buf):
            raise DnsError("truncated record")
        rtype, _class, ttl, rdlength = struct.unpack_from("!HHIH", buf, offset)
        offset += 10
        rdata = buf[offset : offset + rdlength]
        if len(rdata) != rdlength:
            raise DnsError("truncated rdata")
        data = ""
        if rtype == TYPE_A and rdlength == 4:
            data = str(ipaddress.IPv4Address(rdata))
        elif rtype == TYPE_AAAA and rdlength == 16:
            data = str(ipaddress.IPv6Address(rdata))
        elif rtype == TYPE_CNAME:
            data = _read_name(buf, offset)[0]
        answers.append(Record(name, rtype, ttl, data))
        offset += rdlength
    return Message(ident, flags, qname, qtype, question_end, tuple(answers))


def error_response(query: bytes, rcode: int) -> bytes:
    """An answer to `query` with `rcode` and no records: QR and RA set, RD and opcode kept."""
    message = parse_message(query)
    flags = 0x8000 | (message.flags & 0x7900) | 0x0080 | rcode
    qdcount = 1 if message.qname is not None else 0
    header = struct.pack("!HHHHHH", message.id, flags, qdcount, 0, 0, 0)
    return header + query[12 : message.question_end]


_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_SINK_ADDRESSES = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})
_NOT_DOMAINS = frozenset(
    {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost"}
)


def normalise_domain(raw: str) -> str | None:
    """`raw` lower-cased without a trailing dot if it is a plausible domain, else None."""
    name = raw.strip().lower().rstrip(".")
    if not name or "." not in name or len(name) > 253 or name in _NOT_DOMAINS:
        return None
    return name if all(_LABEL_RE.match(label) for label in name.split(".")) else None


def parse_blocklist(text: str) -> tuple[set[str], set[str]]:
    """(blocked, allowed) domains from hosts, Adblock Plus or one-domain-per-line text.

    ABP: `||domain^` blocks, `@@||domain^` allows; rules with `$` options or paths are
    skipped (they are browser rules, not DNS ones). Hosts: lines whose address is a sink.
    """
    blocked: set[str] = set()
    allowed: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("!", "[")):
            continue
        if line.startswith(("||", "@@||")):
            target = allowed if line.startswith("@@") else blocked
            body = line.removeprefix("@@").removeprefix("||")
            if "$" in body or "/" in body or not body.endswith("^"):
                continue
            if name := normalise_domain(body.removesuffix("^")):
                target.add(name)
            continue
        fields = line.split()
        if len(fields) == 1:
            if name := normalise_domain(fields[0]):
                blocked.add(name)
        elif fields[0] in _SINK_ADDRESSES:
            blocked.update(n for f in fields[1:] if (n := normalise_domain(f)))
    return blocked, allowed


class DomainBlocklist:
    """Blocked domains, each covering its subdomains; an allowed domain wins over a block."""

    def __init__(self, blocked: Iterable[str] = (), allowed: Iterable[str] = ()) -> None:
        self._blocked = frozenset(blocked)
        self._allowed = frozenset(allowed)

    @classmethod
    def from_text(cls, text: str) -> DomainBlocklist:
        """Parse hosts / ABP / plain text (see `parse_blocklist`)."""
        return cls(*parse_blocklist(text))

    def __len__(self) -> int:
        return len(self._blocked)

    def blocks(self, name: str) -> bool:
        """Whether `name` or any parent domain of it is blocked and none is allowed."""
        labels = name.lower().rstrip(".").split(".")
        suffixes = [".".join(labels[i:]) for i in range(len(labels))]
        if any(s in self._allowed for s in suffixes):
            return False
        return any(s in self._blocked for s in suffixes)


def _download(url: str, limit: int, timeout_s: float) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing a non-HTTPS blocklist URL: {url}")
    with urllib.request.urlopen(url, timeout=timeout_s) as response:
        data: bytes = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"blocklist larger than {limit} bytes")
    return data


async def fetch_blocklist(
    url: str = DEFAULT_BLOCKLIST_URL,
    cache: Path = BLOCKLIST_CACHE,
    limit: int = MAX_BLOCKLIST_BYTES,
    timeout_s: float = 30.0,
) -> DomainBlocklist:
    """Download `url` (HTTPS only, size-capped) off the event loop, save it atomically to
    the root-owned `cache`, and parse it. Run it outside lockdown: inside, nothing reaches the
    list's host."""
    data = await asyncio.to_thread(_download, url, limit, timeout_s)
    text = data.decode("utf-8", "replace")
    blocklist = DomainBlocklist.from_text(text)
    cache.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=cache.parent, prefix=f".{cache.name}-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, cache)
    except BaseException:
        os.unlink(tmp)
        raise
    return blocklist


def load_blocklist(cache: Path = BLOCKLIST_CACHE) -> DomainBlocklist:
    """The cached list, or an empty one when none was fetched yet."""
    try:
        return DomainBlocklist.from_text(cache.read_text(errors="replace"))
    except FileNotFoundError:
        return DomainBlocklist()


class DnsMap:
    """IP -> names it was resolved from, kept for the answer's TTL clamped to [min, max]."""

    def __init__(
        self,
        min_ttl_s: float = 60.0,
        max_ttl_s: float = 3600.0,
        max_ips: int = 65536,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._min, self._max, self._cap, self._clock = min_ttl_s, max_ttl_s, max_ips, clock
        self._names: OrderedDict[str, dict[str, float]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._names)

    def record(self, qname: str, answers: Iterable[Record]) -> None:
        """Map every address in `answers` to `qname` and every CNAME on the way to it."""
        now = self._clock()
        records = list(answers)
        cnames = (r.data for r in records if r.rtype == TYPE_CNAME)
        chain = {qname, *(r.name for r in records), *cnames}
        for rec in records:
            if rec.rtype not in (TYPE_A, TYPE_AAAA):
                continue
            expiry = now + min(max(rec.ttl, self._min), self._max)
            names = self._names.setdefault(rec.data, {})
            self._names.move_to_end(rec.data)
            for name in chain:
                names[name] = max(names.get(name, 0.0), expiry)
        while len(self._names) > self._cap:
            self._names.popitem(last=False)

    def names(self, address: str) -> frozenset[str]:
        """Unexpired names `address` was resolved from (empty: never seen in DNS)."""
        now = self._clock()
        entry = self._names.get(address, {})
        return frozenset(name for name, expiry in entry.items() if expiry > now)


def system_resolvers(scutil_dns: str) -> list[str]:
    """Resolver addresses from `scutil --dns`, in order, without loopback ones (forwarding
    to those would loop back into the sinkhole)."""
    found: list[str] = []
    for line in scutil_dns.splitlines():
        key, _, value = line.strip().partition(" : ")
        if not key.startswith("nameserver["):
            continue
        address = value.strip().split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not ip.is_loopback and str(ip) not in found:
            found.append(str(ip))
    return found


def _privileged_socket(family: int, kind: int, ports: tuple[int, int]) -> socket.socket:
    """A socket bound to a random port in `ports`; below 1024 only root may bind one."""
    low, high = ports
    candidates = random.sample(range(low, high + 1), k=high - low + 1)
    for port in candidates:
        sock = socket.socket(family, kind)
        sock.setblocking(False)
        try:
            sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", port))
        except OSError as exc:
            sock.close()
            if exc.errno == errno.EADDRINUSE:
                continue
            raise
        return sock
    raise OSError(errno.EADDRINUSE, f"no free source port in {low}-{high}")


class _UdpServer(asyncio.DatagramProtocol):
    def __init__(self, sinkhole: Sinkhole) -> None:
        self._sinkhole = sinkhole
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | object, ...]) -> None:
        self._sinkhole.spawn(self._answer(data, addr))

    async def _answer(self, data: bytes, addr: tuple[str | object, ...]) -> None:
        reply = await self._sinkhole.resolve(data)
        if reply is not None and self._transport is not None:
            self._transport.sendto(reply, addr)


class Sinkhole:
    """Local DNS forwarder that refuses blocked names; one per lockdown.

    `on_block(name)` is called for every refused query. `listen`, `port` and
    `upstream_ports` are parameters only so the tests can run it unprivileged.
    """

    def __init__(
        self,
        blocklist: DomainBlocklist,
        dns_map: DnsMap,
        upstreams: Sequence[str],
        on_block: Callable[[str], None] = lambda name: None,
        listen: Sequence[str] = ("127.0.0.1", "::1"),
        port: int = SINKHOLE_PORT,
        upstream_port: int = 53,
        upstream_ports: tuple[int, int] = SINKHOLE_UPSTREAM_PORTS,
        timeout_s: float = 2.0,
    ) -> None:
        if not upstreams:
            raise ValueError("no upstream resolver: refusing a sinkhole that cannot resolve")
        self.blocklist = blocklist
        self.dns_map = dns_map
        self.upstreams = list(upstreams)
        self._on_block = on_block
        self._listen = list(listen)
        self.port = port
        self._upstream_port = upstream_port
        self._upstream_ports = upstream_ports
        self._timeout_s = timeout_s
        self._closers: list[Callable[[], object]] = []
        self._tasks: set[asyncio.Task[None]] = set()
        self.blocked = 0
        self.forwarded = 0

    def spawn(self, coro: object) -> None:
        """Run a reply in the background, keeping a reference until it finishes."""
        assert asyncio.iscoroutine(coro)
        task: asyncio.Task[None] = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def start(self) -> None:
        """Listen on UDP and TCP on every `listen` address."""
        loop = asyncio.get_running_loop()
        try:
            for host in self._listen:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _UdpServer(self), local_addr=(host, self.port)
                )
                self._closers.append(transport.close)
                server = await asyncio.start_server(self._tcp_client, host, self.port)
                self._closers.append(server.close)
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        """Stop listening and drop in-flight replies."""
        for close in self._closers:
            close()
        self._closers.clear()
        for task in list(self._tasks):
            task.cancel()

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                (length,) = struct.unpack("!H", await reader.readexactly(2))
                reply = await self.resolve(await reader.readexactly(length))
                if reply is None:
                    break
                writer.write(struct.pack("!H", len(reply)) + reply)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    def _refuses(self, names: Iterable[str]) -> str | None:
        return next((n for n in names if n and self.blocklist.blocks(n)), None)

    async def resolve(self, query: bytes) -> bytes | None:
        """The reply to `query`: NXDOMAIN for a blocked name, else the upstream answer
        (recorded in the DNS map). None drops a message too malformed to answer."""
        try:
            message = parse_message(query)
        except DnsError:
            return None
        if message.qname is None:
            return error_response(query, RCODE_SERVFAIL)
        if (name := self._refuses([message.qname])) is not None:
            return self._refuse(query, name)
        try:
            answer = await self._forward(query, message.id)
            parsed = parse_message(answer)
        except (OSError, TimeoutError, DnsError):
            return error_response(query, RCODE_SERVFAIL)
        cnames = [r.data for r in parsed.answers if r.rtype == TYPE_CNAME]
        if (name := self._refuses(cnames)) is not None:
            return self._refuse(query, name)
        self.dns_map.record(message.qname, parsed.answers)
        self.forwarded += 1
        return answer

    def _refuse(self, query: bytes, name: str) -> bytes:
        self.blocked += 1
        self._on_block(name)
        return error_response(query, RCODE_NXDOMAIN)

    async def _forward(self, query: bytes, ident: int) -> bytes:
        last: Exception = OSError("no upstream answered")
        for upstream in self.upstreams:
            try:
                answer = await asyncio.wait_for(self._udp(upstream, query, ident), self._timeout_s)
                if parse_message(answer).truncated:
                    answer = await asyncio.wait_for(self._tcp(upstream, query), self._timeout_s)
                return answer
            except (OSError, TimeoutError, DnsError) as exc:
                last = exc
        raise last

    def _family(self, upstream: str) -> int:
        return socket.AF_INET6 if ":" in upstream else socket.AF_INET

    async def _udp(self, upstream: str, query: bytes, ident: int) -> bytes:
        loop = asyncio.get_running_loop()
        sock = _privileged_socket(self._family(upstream), socket.SOCK_DGRAM, self._upstream_ports)
        with contextlib.closing(sock):
            await loop.sock_sendto(sock, query, (upstream, self._upstream_port))
            while True:
                data, addr = await loop.sock_recvfrom(sock, 65535)
                # Only the upstream we asked, answering this query, counts.
                if addr[0] == upstream and data[:2] == struct.pack("!H", ident):
                    return data

    async def _tcp(self, upstream: str, query: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        sock = _privileged_socket(self._family(upstream), socket.SOCK_STREAM, self._upstream_ports)
        with contextlib.closing(sock):
            await loop.sock_connect(sock, (upstream, self._upstream_port))
            await loop.sock_sendall(sock, struct.pack("!H", len(query)) + query)
            head = await self._recv_exactly(loop, sock, 2)
            return await self._recv_exactly(loop, sock, struct.unpack("!H", head)[0])

    @staticmethod
    async def _recv_exactly(
        loop: asyncio.AbstractEventLoop, sock: socket.socket, size: int
    ) -> bytes:
        data = b""
        while len(data) < size:
            chunk = await loop.sock_recv(sock, size - len(data))
            if not chunk:
                raise ConnectionError("upstream closed the connection")
            data += chunk
        return data
