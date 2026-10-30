"""launchd daemon that keeps `safemaxxing watch --json` running as root in the background.

Unlike the boot job, which runs only `/bin/sh` and `/sbin/pfctl`, this job runs safemaxxing
itself as root. It therefore installs only from a build no other user can change: the frozen
bundle the `.pkg` puts under `/usr/local/libexec`, owned by root and writable by nobody else.
A source checkout, a virtualenv or Homebrew's prefix belong to the user who made them, so a
root daemon pointing there would let that user, and anything running as them, run code as
root.
"""

from __future__ import annotations

import contextlib
import json
import os
import plistlib
import re
import stat
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from safemaxxing.boot import LaunchdJob
from safemaxxing.firewall import Runner, run_command

LABEL = "io.github.carlobaratta.safemaxxing.watch"
PLIST = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
# Alerts, one JSON object per line (`watch --json`); errors and tracebacks go to ERR_LOG.
LOG = Path("/var/log/safemaxxing-watch.log")
ERR_LOG = Path("/var/log/safemaxxing-watch.err")
# launchd restarts the job when it exits; this is the least time between two starts.
THROTTLE_S = 10


@dataclass(frozen=True, slots=True)
class WatchOptions:
    """The `watch` options the daemon is installed with (the same defaults as `watch`)."""

    window_ms: int = 2000
    decay_window_ms: int = 0
    poll_ms: int = 200
    include_loopback: bool = False
    no_dns: bool = False
    ignore: tuple[str, ...] = ()
    include_system: bool = False
    include_dns: bool = False
    udp_flows: bool = False
    tcp_flows: bool = False
    throughput: bool = False
    auto_block: bool = False
    auto_suspend: bool = False
    min_severity: str = "high"

    def arguments(self) -> list[str]:
        """`watch` arguments: every value, so the plist says exactly what runs."""
        args = [
            "--json",
            f"--window-ms={self.window_ms}",
            f"--decay-window-ms={self.decay_window_ms}",
            f"--poll-ms={self.poll_ms}",
            f"--min-severity={self.min_severity}",
        ]
        for name in sorted(set(self.ignore)):
            args.append(f"--ignore={name}")
        flags = {
            "--include-loopback": self.include_loopback,
            "--no-dns": self.no_dns,
            "--include-system": self.include_system,
            "--include-dns": self.include_dns,
            "--udp-flows": self.udp_flows,
            "--tcp-flows": self.tcp_flows,
            "--throughput": self.throughput,
            "--auto-block": self.auto_block,
            "--auto-suspend": self.auto_suspend,
        }
        args += [flag for flag, on in flags.items() if on]
        return args


def daemon_plist(executable: str, options: WatchOptions) -> bytes:
    """Return the job's property list: start at load, restart whenever `watch` exits."""
    return plistlib.dumps(
        {
            "Label": LABEL,
            "ProgramArguments": [executable, "watch", *options.arguments()],
            "RunAtLoad": True,
            "KeepAlive": True,
            "ThrottleInterval": THROTTLE_S,
            "StandardOutPath": str(LOG),
            "StandardErrorPath": str(ERR_LOG),
        }
    )


def _unsafe_entry(path: Path, owners: frozenset[int]) -> str:
    st = os.lstat(path)
    if st.st_uid not in owners:
        return f"{path} is owned by uid {st.st_uid}, not root"
    if not stat.S_ISLNK(st.st_mode) and st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{path} is writable by its group or by everyone"
    return ""


def unsafe_reason(
    executable: Path,
    *,
    frozen: bool,
    owners: frozenset[int] = frozenset({0}),
    top: Path = Path("/"),
) -> str:
    """Why `executable` must not run as a root daemon, or '' when it may.

    It must be the frozen binary, and every file of its bundle and every directory above it
    must be owned by root and writable by no one else, so only root can swap the code out.
    A symlink inside the bundle must point inside the bundle. `owners` and `top` (where the
    climb up the parents stops) let the tests use a temporary directory.
    """
    if not frozen:
        return (
            "the daemon runs as root, so it only installs from the root-owned build the .pkg "
            "puts in /usr/local/libexec/safemaxxing; a source checkout or virtualenv can be "
            "changed by the user who owns it"
        )
    executable = executable.resolve()
    bundle = executable.parent
    top = top.resolve()
    for directory in (bundle, *bundle.parents):
        if problem := _unsafe_entry(directory, owners):
            return problem
        if directory == top:
            break
    for root, dirs, files in os.walk(bundle):
        for name in (*dirs, *files):
            path = Path(root, name)
            if problem := _unsafe_entry(path, owners):
                return problem
            if path.is_symlink() and not path.resolve().is_relative_to(bundle):
                return f"{path} points outside {bundle}"
    return ""


@dataclass(frozen=True, slots=True)
class DaemonStatus:
    """The plist and launchd's view of the job: state, pid and the last exit code."""

    installed: bool
    loaded: bool
    state: str | None = None
    pid: int | None = None
    last_exit: str | None = None
    arguments: tuple[str, ...] = ()


_PRINT_FIELD_RE = re.compile(
    r"^\s*(state|pid|last exit code|last terminating signal) = (.+?)\s*$", re.MULTILINE
)


def parse_print(text: str) -> tuple[str | None, int | None, str | None]:
    """State, pid and how the job last ended from `launchctl print system/<label>`.

    The job's own fields come first; nested endpoint blocks repeat `state`, so the first of
    each wins. A job killed by a signal has `last terminating signal` instead of an exit code.
    """
    fields: dict[str, str] = {}
    for key, value in _PRINT_FIELD_RE.findall(text):
        fields.setdefault(key, value)
    pid = fields.get("pid")
    return (
        fields.get("state"),
        int(pid) if pid and pid.isdigit() else None,
        fields.get("last terminating signal") or fields.get("last exit code"),
    )


class WatchDaemon(LaunchdJob):
    """Installs, removes and inspects the `watch` daemon (install and uninstall need root)."""

    def __init__(self, runner: Runner = run_command, plist: Path = PLIST) -> None:
        super().__init__(LABEL, plist, runner)

    async def install(self, executable: str, options: WatchOptions) -> str:
        """Write the plist and (re)load it, which starts `watch`; return a problem or ''."""
        return await self.load(daemon_plist(executable, options))

    async def daemon_status(self) -> DaemonStatus:
        """Read the plist's command line and launchd's state for the job."""
        arguments: tuple[str, ...] = ()
        with contextlib.suppress(OSError, plistlib.InvalidFileException, KeyError, TypeError):
            arguments = tuple(plistlib.loads(self.plist.read_bytes())["ProgramArguments"])
        text = await self.print()
        if text is None:
            return DaemonStatus(self.plist.exists(), False, arguments=arguments)
        state, pid, last_exit = parse_print(text)
        return DaemonStatus(self.plist.exists(), True, state, pid, last_exit, arguments)


def recent_alerts(path: Path = LOG, count: int = 5) -> list[str]:
    """The last `count` alerts in the daemon's log as one-line summaries (oldest first)."""
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            lines = deque(fh, maxlen=count)
    except OSError:
        return []
    alerts = []
    for line in lines:
        try:
            alert = json.loads(line)
            alerts.append(f"[{alert['severity']}] {alert['summary']}")
        except (ValueError, KeyError, TypeError):
            alerts.append(line.strip())
    return alerts
