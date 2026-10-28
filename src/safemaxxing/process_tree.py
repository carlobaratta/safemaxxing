"""Process-tree attribution: trace a socket's owner back to the app accountable for it.

Many macOS apps never open their own sockets. They hand the transfer to a shared system
daemon (`nsurlsessiond` backs every `URLSession`, `cloudd` backs CloudKit), spawn a helper
(`curl`, a Sparkle updater) or route it through an XPC service that runs as its own process.
The socket the poller sees is then owned by that delegate, whose pid and bundle id do not
match the process that touched the sensor, so `same_actor` finds no link and the egress is
missed.

Two relationships recover the real owner:

* **Ancestry.** A spawned helper (`curl`, an updater) is a child of the app, so walking
  parent pids up to `launchd` reaches it. This is read from `libproc`'s `proc_bsdinfo`.
* **Responsible pid.** macOS records, per process, the process it holds accountable for
  another's actions -- the identity that drives TCC prompts and `responsible for` in
  `launchd`. A few daemons set it to the app on whose behalf they act, which is the only
  link when the delegate is *not* a descendant (a system daemon is a child of `launchd`).
  It is read best-effort through a private libsystem symbol; when that is unavailable the
  ancestry alone is used.

`ProcessChainResolver.chain(pid)` returns the ordered set of pids accountable for `pid` --
itself, its responsible pid, then its ancestors -- so the correlation engine can treat a
connection as belonging to a sensor event whose pid appears anywhere on that chain.

Lookups are never cached here: a pid is reused the moment the kernel wraps its number
space, and a cached parent would then attribute a stranger's socket to the wrong app. The
resolver is pure given its injected lookups, so tests drive it with a plain dict.
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable

# launchd owns pid 1 and is every daemon's ancestor; a chain reaching it stops. pid 0 is the
# kernel. Neither is a meaningful actor, so both terminate the walk.
LAUNCHD_PID = 1

# Real delegation chains are two to four deep (app -> XPC service -> helper). The cap turns a
# corrupted ppid cycle, which `proc_bsdinfo` can report after pid reuse, into a bounded walk.
MAX_CHAIN = 8

# libproc flavor selector and the exact size its `proc_bsdinfo` payload must fill.
_PROC_PIDTBSDINFO = 3
_MAXCOMLEN = 16

type ParentLookup = Callable[[int], int | None]
type ResponsibleLookup = Callable[[int], int | None]


class _ProcBsdInfo(ctypes.Structure):
    """`struct proc_bsdinfo` from `<sys/proc_info.h>`; only `pbi_ppid` is read, but the whole
    layout is declared so `ctypes.sizeof` matches the size the kernel insists on writing."""

    _fields_ = (  # noqa: RUF012 - ctypes reads this attribute by name; a tuple is fine.
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * _MAXCOMLEN),
        ("pbi_name", ctypes.c_char * (2 * _MAXCOMLEN)),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    )


def _load_proc_pidinfo() -> Callable[..., int] | None:
    """Bind `libproc.proc_pidinfo`, or None off macOS / where libproc is absent."""
    try:
        lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    except OSError:
        return None
    fn = lib.proc_pidinfo
    fn.restype = ctypes.c_int
    fn.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int)
    return fn


def _load_responsible() -> ResponsibleLookup | None:
    """Bind the private `responsibility_get_pid_responsible_for_pid`, or None if unexported.

    The symbol lives in libsystem and is not in any SDK header, so its absence is normal and
    never an error: callers fall back to ancestry. It takes a pid and returns the responsible
    pid (itself for a process responsible for its own actions), or a negative value on failure.
    """
    try:
        fn = ctypes.CDLL(None, use_errno=True).responsibility_get_pid_responsible_for_pid
    except (OSError, AttributeError):
        return None
    fn.restype = ctypes.c_int
    fn.argtypes = (ctypes.c_int,)

    def lookup(pid: int) -> int | None:
        responsible = int(fn(pid))
        return responsible if responsible > LAUNCHD_PID else None

    return lookup


_PROC_PIDINFO = _load_proc_pidinfo()


def libproc_ppid(pid: int) -> int | None:
    """Parent pid of `pid` from `proc_bsdinfo`, or None if libproc is unavailable, the process
    is gone, or the call is not permitted (reading another user's process needs root)."""
    if _PROC_PIDINFO is None:
        return None
    info = _ProcBsdInfo()
    size = ctypes.sizeof(info)
    written = _PROC_PIDINFO(pid, _PROC_PIDTBSDINFO, 0, ctypes.byref(info), size)
    # proc_pidinfo returns the bytes written: the full struct on success, 0 on error.
    if written != size:
        return None
    return int(info.pbi_ppid)


class ProcessChainResolver:
    """Resolves the pids accountable for a given pid: itself, its responsible pid, its ancestry.

    `parent` and `responsible` are injected so the walk is deterministic in tests; in
    production they read `libproc` and the private responsibility symbol. When neither
    resolves anything (off macOS, or without the privilege to inspect a process), `chain`
    degrades to just the pid itself, which leaves correlation exactly as pid-equality would.
    """

    def __init__(
        self,
        parent: ParentLookup = libproc_ppid,
        responsible: ResponsibleLookup | None = None,
        max_chain: int = MAX_CHAIN,
    ) -> None:
        self._parent = parent
        self._responsible = responsible if responsible is not None else (_load_responsible())
        self._max_chain = max_chain

    def chain(self, pid: int) -> frozenset[int]:
        """Pids accountable for `pid`, walking responsible pid then parent at each step.

        The walk stops at `launchd` (pid 1), the kernel (pid 0) and any already-seen pid, and
        never grows past `max_chain` entries, so a reused-pid cycle cannot loop. An unknown or
        inaccessible pid yields just itself.
        """
        if pid <= LAUNCHD_PID:
            return frozenset()
        accountable: set[int] = set()
        frontier = [pid]
        while frontier and len(accountable) < self._max_chain:
            current = frontier.pop()
            if current <= LAUNCHD_PID or current in accountable:
                continue
            accountable.add(current)
            responsible = self._responsible(current) if self._responsible is not None else None
            for nxt in (responsible, self._parent(current)):
                if nxt is not None and nxt > LAUNCHD_PID and nxt not in accountable:
                    frontier.append(nxt)
        return frozenset(accountable)
