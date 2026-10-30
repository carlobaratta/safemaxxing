"""What the default-deny rule dropped, read from `pflog0` as a pcap stream.

`tcpdump -w -` writes pcap; each record is a `struct pfloghdr` followed by the dropped IP
packet. The header layout comes from xnu's `bsd/net/if_pflog.h`, which is not in the public
SDK: its pid field is filled only when pf looked the socket up, so it is a hint, and the
socket owner is otherwise found from the packet's local port (see `controller.py`).
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import struct
from collections.abc import AsyncIterator, Iterator, Sequence
from dataclasses import dataclass

from safemaxxing.firewall import FirewallError, Runner, run_command
from safemaxxing.models import Protocol
from safemaxxing.pktap import TCPDUMP_BINARY

IFCONFIG = "/sbin/ifconfig"
PFLOG_INTERFACE = "pflog0"
DLT_PFLOG = 117
# struct pfloghdr: length, af, action, reason (1 byte each), ifname[16], ruleset[16],
# rulenr, subrulenr (network order), uid, pid, rule_uid, rule_pid (host order), dir, pad[3].
_HDR = struct.Struct("=BBBB16s16s4s4siiiiB3x")
PFLOG_HDRLEN = _HDR.size  # 64, the BPF_WORDALIGN(61) the kernel uses before the packet
PF_DROP = 1
PF_OUT = 2
_AF_INET = 2
_AF_INET6 = 30  # Darwin's value; Linux's 10 never reaches a Mac's pflog0
# Darwin's PID_MAX; pf writes NO_PID (PID_MAX + 1) when it did no socket lookup.
_PID_MAX = 99999
_PROTOCOLS = {6: Protocol.TCP, 17: Protocol.UDP}
# Header (64) + IPv6 (40) + the 4 port bytes, rounded up.
SNAPLEN = 128


@dataclass(frozen=True, slots=True)
class BlockedPacket:
    """An outbound packet the default-deny rule dropped."""

    timestamp: float
    protocol: Protocol
    src: str
    src_port: int
    dst: str
    dst_port: int
    pid: int | None = None

    @property
    def flow(self) -> tuple[Protocol, str, int, str, int]:
        """(protocol, local and remote endpoints): retries of one connect share it."""
        return (self.protocol, self.src, self.src_port, self.dst, self.dst_port)


async def ensure_interface(runner: Runner = run_command, interface: str = PFLOG_INTERFACE) -> None:
    """Create `pflog0` if missing: macOS 27.0.1 has none until asked, and without it the
    default-deny rule's `log` goes nowhere and nothing is ever learned. Needs root."""
    if (await runner([IFCONFIG, interface])).returncode == 0:
        return
    res = await runner([IFCONFIG, interface, "create"])
    if res.returncode != 0:
        raise FirewallError(f"cannot create {interface}: {res.stderr.strip() or res.returncode}")


def pflog_command(interface: str = PFLOG_INTERFACE) -> list[str]:
    """`tcpdump` writing raw pcap to stdout, flushed per packet (`-U`). Needs root."""
    return [TCPDUMP_BINARY, "-n", "-U", "-s", str(SNAPLEN), "-i", interface, "-w", "-"]


def _l4(packet: bytes) -> tuple[int, str, str, bytes] | None:
    """(protocol number, source, destination, transport header) of an IPv4/IPv6 packet."""
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4 and len(packet) >= 20:
        ihl = (packet[0] & 0x0F) * 4
        src = str(ipaddress.IPv4Address(packet[12:16]))
        dst = str(ipaddress.IPv4Address(packet[16:20]))
        return packet[9], src, dst, packet[ihl:]
    if version == 6 and len(packet) >= 40:
        # Extension headers are not walked: TCP and UDP follow the fixed header directly in
        # the traffic the default-deny rule sees from an app.
        src = str(ipaddress.IPv6Address(packet[8:24]))
        dst = str(ipaddress.IPv6Address(packet[24:40]))
        return packet[6], src, dst, packet[40:]
    return None


def parse_pflog(record: bytes, timestamp: float) -> BlockedPacket | None:
    """The dropped outbound TCP/UDP packet in one pflog record, or None for anything else."""
    if len(record) < PFLOG_HDRLEN:
        return None
    _length, af, action, _reason, _ifn, _rs, _nr, _sub, _uid, pid, _ru, _rp, direction = (
        _HDR.unpack_from(record)
    )
    if action != PF_DROP or direction != PF_OUT or af not in (_AF_INET, _AF_INET6):
        return None
    parsed = _l4(record[PFLOG_HDRLEN:])
    if parsed is None:
        return None
    number, src, dst, l4 = parsed
    protocol = _PROTOCOLS.get(number)
    if protocol is None or len(l4) < 4:
        return None
    sport, dport = struct.unpack_from("!HH", l4)
    return BlockedPacket(
        timestamp,
        protocol,
        src,
        sport,
        dst,
        dport,
        pid if 1 < pid <= _PID_MAX else None,
    )


class PcapReader:
    """Incremental pcap decoder: feed it bytes as they arrive, get (timestamp, data) back."""

    def __init__(self, linktype: int = DLT_PFLOG) -> None:
        self._buf = bytearray()
        self._linktype = linktype
        self._order: str | None = None
        self._ts_scale = 1e-6

    def feed(self, chunk: bytes) -> Iterator[tuple[float, bytes]]:
        """Records completed by `chunk`; raises ValueError on a file that is not ours."""
        self._buf += chunk
        if self._order is None:
            if len(self._buf) < 24:
                return
            magic = bytes(self._buf[:4])
            if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                self._order = "<"
            elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                self._order = ">"
            else:
                raise ValueError(f"not a pcap stream: magic {magic.hex()}")
            self._ts_scale = 1e-9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e-6
            (linktype,) = struct.unpack_from(f"{self._order}I", self._buf, 20)
            if linktype != self._linktype:
                raise ValueError(f"link type {linktype}, expected {self._linktype}")
            del self._buf[:24]
        record = struct.Struct(f"{self._order}IIII")
        while len(self._buf) >= record.size:
            sec, frac, incl, _orig = record.unpack_from(self._buf)
            end = record.size + incl
            if len(self._buf) < end:
                return
            data = bytes(self._buf[record.size : end])
            del self._buf[:end]
            yield sec + frac * self._ts_scale, data


async def blocked_packets(
    command: Sequence[str] | None = None,
) -> AsyncIterator[BlockedPacket]:
    """Dropped outbound packets as pf logs them; tcpdump is always stopped and reaped."""
    proc = await asyncio.create_subprocess_exec(
        *(command or pflog_command()),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    assert proc.stdout is not None
    reader = PcapReader()
    try:
        while chunk := await proc.stdout.read(65536):
            for timestamp, record in reader.feed(chunk):
                if packet := parse_pflog(record, timestamp):
                    yield packet
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), 2.0)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.wait()
