"""Outbound socket discovery (psutil / lsof) and hostname resolution."""

from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import os
import plistlib
import re
import socket
import stat
import subprocess
import time
from collections.abc import AsyncGenerator, Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import PurePosixPath

import psutil

from safemaxxing.models import NetworkConnection, Protocol

OUTBOUND_TCP_STATES = frozenset({"ESTABLISHED", "SYN_SENT"})
LISTEN_STATE = "LISTEN"

Snapshot = Callable[[float], list[NetworkConnection]]

_LSOF_NAME_RE = re.compile(r"^(?P<laddr>.+):(?P<lport>\d+|\*)->(?P<raddr>.+):(?P<rport>\d+)$")


_MAX_PLIST_BYTES = 1 << 20


def _read_plist(path: str) -> object | None:
    """Parse `path` only if it is a small regular file; never raise or block on it.

    Any running app's Info.plist is untrusted input: it may be malformed, huge or a FIFO.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        data = os.read(fd, _MAX_PLIST_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(data) > _MAX_PLIST_BYTES:
        return None
    try:
        parsed: object = plistlib.loads(data)
    except Exception:  # expat errors, bad binary plists: the file is attacker-controlled
        return None
    return parsed


def enclosing_apps(exe_path: str) -> list[str]:
    """Every .app directory containing `exe_path`, outermost first."""
    parts = PurePosixPath(exe_path).parts
    return [str(PurePosixPath(*parts[: i + 1])) for i, p in enumerate(parts) if p.endswith(".app")]


@lru_cache(maxsize=1024)
def bundle_id_for_app(app_path: str) -> str | None:
    """CFBundleIdentifier of the bundle (.app, .systemextension) at `app_path`, or None if
    its Info.plist is unusable."""
    data = _read_plist(f"{app_path}/Contents/Info.plist")
    ident = data.get("CFBundleIdentifier") if isinstance(data, dict) else None
    return ident if isinstance(ident, str) else None


def bundle_id_for_exe(exe_path: str) -> str | None:
    """Return the CFBundleIdentifier of the outermost .app containing `exe_path`, else of the
    innermost system extension containing it.

    A system extension runs from `/Library/SystemExtensions/<uuid>/<id>.systemextension`, in
    no .app (Avast's network extension on macOS 27.0.1). Its bundle has the same layout.
    """
    apps = enclosing_apps(exe_path)
    if apps:
        return bundle_id_for_app(apps[0])
    parts = PurePosixPath(exe_path).parts
    for i in range(len(parts) - 1, -1, -1):
        if parts[i].endswith(".systemextension"):
            return bundle_id_for_app(str(PurePosixPath(*parts[: i + 1])))
    return None


def _strip_brackets(addr: str) -> str:
    return addr[1:-1] if addr.startswith("[") and addr.endswith("]") else addr


def parse_lsof(output: str, now: float) -> list[NetworkConnection]:
    """Parse `lsof -nP -iTCP -iUDP -FpcPnT` field output."""
    conns: list[NetworkConnection] = []
    pid: int | None = None
    command = ""
    proto: Protocol | None = None
    name: str | None = None
    state = ""

    def flush() -> None:
        if pid is None or proto is None or name is None:
            return
        match = _LSOF_NAME_RE.match(name)
        if not match:
            return
        lport = match["lport"]
        conns.append(
            NetworkConnection(
                pid=pid,
                process_name=command,
                protocol=proto,
                local_address=_strip_brackets(match["laddr"]),
                local_port=0 if lport == "*" else int(lport),
                remote_address=_strip_brackets(match["raddr"]),
                remote_port=int(match["rport"]),
                status=state or ("NONE" if proto is Protocol.UDP else ""),
                first_seen=now,
            )
        )

    for line in output.splitlines():
        if not line:
            continue
        field, value = line[0], line[1:]
        if field == "p":
            flush()
            pid, command, proto, name, state = int(value), "", None, None, ""
        elif field == "c":
            command = value
        elif field == "f":
            flush()
            proto, name, state = None, None, ""
        elif field == "P":
            proto = Protocol.TCP if value == "TCP" else Protocol.UDP if value == "UDP" else None
        elif field == "n":
            name = value
        elif field == "T" and value.startswith("ST="):
            state = value[3:]
    flush()
    return conns


def snapshot_lsof(now: float) -> list[NetworkConnection]:
    """Snapshot TCP/UDP sockets by running `lsof`; the fallback when psutil is denied access."""
    proc = subprocess.run(
        ["/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP", "-FpcPnT"],
        capture_output=True,
        text=True,
        check=False,
    )
    return parse_lsof(proc.stdout, now)


class _ProcessInfoCache:
    """pid -> (name, exe) lookups cached across polls; `retain` drops pids that are gone."""

    def __init__(self) -> None:
        self._cache: dict[int, tuple[str, str | None]] = {}

    def get(self, pid: int) -> tuple[str, str | None]:
        if (hit := self._cache.get(pid)) is not None:
            return hit
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            try:
                exe: str | None = proc.exe() or None
            except (psutil.AccessDenied, psutil.ZombieProcess):
                exe = None
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            name, exe = f"pid:{pid}", None
        self._cache[pid] = (name, exe)
        return name, exe

    def retain(self, pids: Iterable[int]) -> None:
        keep = set(pids)
        self._cache = {k: v for k, v in self._cache.items() if k in keep}


class PsutilSnapshot:
    """Snapshot of inet sockets via psutil (needs root on macOS to see other users' sockets)."""

    def __init__(self) -> None:
        self._procs = _ProcessInfoCache()

    def __call__(self, now: float) -> list[NetworkConnection]:
        conns: list[NetworkConnection] = []
        for c in psutil.net_connections(kind="inet"):
            if c.pid is None:
                continue
            proto = Protocol.TCP if c.type == socket.SOCK_STREAM else Protocol.UDP
            laddr_ip, laddr_port = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
            raddr_ip, raddr_port = (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0)
            name, exe = self._procs.get(c.pid)
            conns.append(
                NetworkConnection(
                    pid=c.pid,
                    process_name=name,
                    protocol=proto,
                    local_address=laddr_ip,
                    local_port=laddr_port,
                    remote_address=raddr_ip,
                    remote_port=raddr_port,
                    status=c.status,
                    first_seen=now,
                    exe_path=exe,
                )
            )
        self._procs.retain(c.pid for c in conns)
        return conns


def default_snapshot() -> Snapshot:
    """Pick `PsutilSnapshot` when psutil can list sockets, else fall back to `snapshot_lsof`."""
    try:
        psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return snapshot_lsof
    return PsutilSnapshot()


def outbound_only(
    conns: Iterable[NetworkConnection], include_loopback: bool = False
) -> list[NetworkConnection]:
    """Keep sockets this host initiated: connected, not accepted on a listening port."""
    conns = list(conns)
    listening = {
        (c.protocol, c.local_port)
        for c in conns
        if c.status == LISTEN_STATE and not c.remote_address
    }
    out: list[NetworkConnection] = []
    for c in conns:
        if not c.remote_address or c.remote_port == 0:
            continue
        if c.protocol is Protocol.TCP and c.status not in OUTBOUND_TCP_STATES:
            continue
        if (c.protocol, c.local_port) in listening:
            continue
        if not include_loopback and c.is_loopback:
            continue
        out.append(c)
    return out


def _reverse_lookup(ip: str) -> str | None:
    try:
        return socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)[0]
    except OSError:
        return None


class HostnameResolver:
    """Reverse DNS that can never stall the socket poller.

    Lookups run on a dedicated small thread pool (a hung `getnameinfo` cannot be cancelled, so
    it must not occupy the default executor that the poller uses). Callers either `prefetch`
    (fire-and-forget) or `resolve` with a hard timeout; late answers still land in the cache.
    """

    def __init__(
        self,
        timeout_s: float = 0.1,
        max_entries: int = 4096,
        max_workers: int = 4,
        max_pending: int = 64,
        lookup: Callable[[str], str | None] = _reverse_lookup,
    ) -> None:
        self._timeout_s = timeout_s
        self._max_entries = max_entries
        self._max_pending = max_pending
        self._lookup = lookup
        self._executor = ThreadPoolExecutor(max_workers, thread_name_prefix="safemaxxing-dns")
        self._cache: dict[str, str | None] = {}
        self._pending: dict[str, asyncio.Future[str | None]] = {}

    def cached(self, ip: str) -> str | None:
        """Return the cached hostname for `ip` without any lookup (None if unknown or failed)."""
        return self._cache.get(ip)

    def _store(self, ip: str, host: str | None) -> None:
        if len(self._cache) >= self._max_entries:
            self._cache.clear()
        self._cache[ip] = host

    def _settle(self, ip: str, future: asyncio.Future[str | None]) -> None:
        self._pending.pop(ip, None)
        failed = future.cancelled() or future.exception() is not None
        self._store(ip, None if failed else future.result())

    def _start(self, ip: str) -> asyncio.Future[str | None] | None:
        if ip in self._cache:
            return None
        if (pending := self._pending.get(ip)) is not None:
            return pending
        try:
            routable = ipaddress.ip_address(ip).is_global
        except ValueError:
            routable = False
        if not routable:
            self._store(ip, None)
            return None
        if len(self._pending) >= self._max_pending:
            return None
        future = asyncio.get_running_loop().run_in_executor(self._executor, self._lookup, ip)
        self._pending[ip] = future
        future.add_done_callback(lambda f: self._settle(ip, f))
        return future

    def prefetch(self, ip: str) -> None:
        """Start a background lookup for `ip` and return at once; the answer lands in the cache."""
        self._start(ip)

    async def resolve(self, ip: str) -> str | None:
        """Look up `ip`, waiting at most `timeout_s`; return None if it is not answered in time.

        A lookup that misses the timeout keeps running and fills the cache for later calls.
        """
        future = self._start(ip)
        if future is None:
            return self._cache.get(ip)
        try:
            await asyncio.wait_for(asyncio.shield(future), self._timeout_s)
        except TimeoutError:
            return None
        # The done-callback may not have run yet; settle now so the cache is never behind.
        self._settle(ip, future)
        return self._cache.get(ip)

    def close(self) -> None:
        """Stop the lookup pool without waiting; queued lookups are cancelled."""
        self._executor.shutdown(wait=False, cancel_futures=True)


class NetworkMonitor:
    """Polls the socket table and yields connections the first time they are seen."""

    def __init__(
        self,
        snapshot: Snapshot | None = None,
        interval_s: float = 0.2,
        include_loopback: bool = False,
        resolver: HostnameResolver | None = None,
    ) -> None:
        self._snapshot = snapshot
        self._interval_s = interval_s
        self._include_loopback = include_loopback
        self._resolver = resolver
        self._active: dict[tuple[object, ...], NetworkConnection] = {}

    def _named(self, conn: NetworkConnection) -> NetworkConnection:
        if conn.hostname is not None or self._resolver is None:
            return conn
        host = self._resolver.cached(conn.remote_address)
        return dataclasses.replace(conn, hostname=host) if host else conn

    @property
    def active(self) -> tuple[NetworkConnection, ...]:
        """Outbound connections currently open, with hostnames filled in from the cache."""
        return tuple(self._named(c) for c in self._active.values())

    def poll_once(self, now: float | None = None) -> list[NetworkConnection]:
        """Take one snapshot and return the outbound connections not seen in the previous poll.

        The snapshot source is chosen lazily (`default_snapshot`) on the first call. Hostnames
        are only read from the resolver cache, never looked up here.
        """
        if self._snapshot is None:
            self._snapshot = default_snapshot()
        now = time.time() if now is None else now
        current = outbound_only(self._snapshot(now), self._include_loopback)
        fresh: list[NetworkConnection] = []
        active: dict[tuple[object, ...], NetworkConnection] = {}
        for conn in current:
            known = self._active.get(conn.key)
            if known is not None:
                active[conn.key] = known
                continue
            if conn.bundle_id is None and conn.exe_path:
                conn = dataclasses.replace(conn, bundle_id=bundle_id_for_exe(conn.exe_path))
            conn = self._named(conn)
            active[conn.key] = conn
            fresh.append(conn)
        self._active = active
        return fresh

    def _prefetch(self, conns: Iterable[NetworkConnection]) -> None:
        if self._resolver is None:
            return
        for conn in conns:
            if conn.hostname is None:
                self._resolver.prefetch(conn.remote_address)

    async def connections(self) -> AsyncGenerator[NetworkConnection]:
        """Yield new outbound sockets; DNS is only prefetched, never awaited, here."""
        loop = asyncio.get_running_loop()
        # Sockets already open at startup cannot be the effect of a future sensor event.
        self._prefetch(await asyncio.to_thread(self.poll_once))
        deadline = loop.time()
        while True:
            deadline += self._interval_s
            await asyncio.sleep(max(0.0, deadline - loop.time()))
            deadline = max(deadline, loop.time())
            fresh = await asyncio.to_thread(self.poll_once)
            self._prefetch(fresh)
            for conn in fresh:
                yield conn
