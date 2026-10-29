"""Environment probes for `safemaxxing doctor` and `safemaxxing sample`."""

from __future__ import annotations

import asyncio
import os
import platform
import pwd
import subprocess
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath

import psutil

from safemaxxing import tcc_inspector
from safemaxxing.firewall import (
    ANCHOR,
    PARENT_ANCHOR_RULE,
    PFCTL,
    TABLE,
    CommandResult,
    anchor_missing,
    meaningful_stderr,
    parse_pf_status,
)
from safemaxxing.network import PsutilSnapshot
from safemaxxing.pktap import TCPDUMP_BINARY, pktap_command, pktap_unavailable
from safemaxxing.sensors import (
    DISCOVERY_PREDICATE,
    LOG_BINARY,
    REDACTED_RE,
    SensorEventParser,
    SensorListener,
    log_stream_command,
    parse_attributions,
)

LSOF = "/usr/sbin/lsof"
SYSTEM_TCC_DB = "/Library/Application Support/com.apple.TCC/TCC.db"

SyncRunner = Callable[[Sequence[str], float], CommandResult]


class Status(StrEnum):
    """Outcome of a check: OK is healthy, WARN degrades coverage, FAIL breaks the tool."""

    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class Check:
    """One doctor result: what was probed, its `Status` and a human-readable detail."""

    name: str
    status: Status
    detail: str = ""


def run_sync(argv: Sequence[str], timeout_s: float) -> CommandResult:
    """Run `argv` synchronously; a missing binary is exit 127 and a timeout exit -1."""
    try:
        proc = subprocess.run(
            list(argv), capture_output=True, text=True, timeout=timeout_s, check=False
        )
    except FileNotFoundError:
        return CommandResult(127, "", f"{argv[0]}: not found")
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else ""
        return CommandResult(-1, exc.stdout if isinstance(exc.stdout, str) else out, "timeout")
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def check_platform() -> Check:
    """FAIL unless running on macOS (Darwin)."""
    if platform.system() != "Darwin":
        return Check("macOS", Status.FAIL, f"running on {platform.system()}")
    release, _, machine = platform.mac_ver()
    return Check("macOS", Status.OK, f"{release} ({machine})")


def check_root(euid: int | None = None) -> Check:
    """FAIL unless the effective uid is 0; pfctl and system-wide socket listing need root."""
    euid = os.geteuid() if euid is None else euid
    if euid == 0:
        return Check("root privileges", Status.OK, "euid 0")
    return Check("root privileges", Status.FAIL, f"euid {euid}: re-run with sudo")


def check_binaries(paths: Iterable[str] = (LOG_BINARY, PFCTL, LSOF)) -> list[Check]:
    """One check per required tool (`log`, `pfctl`, `lsof`): FAIL if not executable."""
    return [
        Check(path, Status.OK, "present")
        if os.access(path, os.X_OK)
        else Check(path, Status.FAIL, "missing")
        for path in paths
    ]


def _pf_denied(stderr: str) -> bool:
    """`/dev/pf` is root-only: without sudo every pfctl query fails the same way."""
    return "Permission denied" in stderr


_PF_NEEDS_ROOT = "needs root (/dev/pf: Permission denied)"


def check_pf_status(run: SyncRunner = run_sync) -> Check:
    """Report whether pf is enabled; never FAIL.

    WARN when pf is disabled (it is enabled on the first block), when `pfctl` needs root, or
    when its output cannot be read.
    """
    res = run([PFCTL, "-s", "info"], 5.0)
    enabled = parse_pf_status(res.stdout)
    if enabled is None and _pf_denied(res.stderr):
        return Check("pf status", Status.WARN, _PF_NEEDS_ROOT)
    if enabled is None:
        detail = "; ".join(meaningful_stderr(res.stderr)) or "unrecognised `pfctl -s info` output"
        return Check("pf status", Status.WARN, detail)
    if enabled:
        return Check("pf status", Status.OK, "Enabled")
    return Check("pf status", Status.WARN, "Disabled (enabled automatically on first block)")


def check_pf_anchor(run: SyncRunner = run_sync) -> list[Check]:
    """Check the pf parent anchor rule and our own anchor; returns two checks.

    Without root both are WARN ("needs root") rather than FAIL, since check_root already fails.
    Otherwise FAIL if the parent anchor rule is missing from the main ruleset or our anchor
    errors; an anchor that does not exist yet is OK (it loads on the first block).
    """
    main = run([PFCTL, "-s", "rules"], 5.0)
    if _pf_denied(main.stderr):
        # Root is already reported as FAIL; don't claim the ruleset is broken.
        return [
            Check("pf parent anchor", Status.WARN, _PF_NEEDS_ROOT),
            Check(f"anchor {ANCHOR}", Status.WARN, _PF_NEEDS_ROOT),
        ]
    if PARENT_ANCHOR_RULE in main.stdout:
        parent = Check("pf parent anchor", Status.OK, f"main ruleset has {PARENT_ANCHOR_RULE}")
    else:
        parent = Check(
            "pf parent anchor",
            Status.FAIL,
            f"{PARENT_ANCHOR_RULE} missing from main ruleset: sudo pfctl -f /etc/pf.conf",
        )
    ours = run([PFCTL, "-a", ANCHOR, "-s", "rules"], 5.0)
    problems = meaningful_stderr(ours.stderr)
    if anchor_missing(ours.stderr):
        anchor = Check(f"anchor {ANCHOR}", Status.OK, "not created yet (loads on first block)")
    elif ours.returncode != 0 or problems:
        detail = "; ".join(problems) or f"exit {ours.returncode}"
        anchor = Check(f"anchor {ANCHOR}", Status.FAIL, detail)
    elif f"<{TABLE}>" in ours.stdout:
        anchor = Check(f"anchor {ANCHOR}", Status.OK, ours.stdout.strip())
    else:
        anchor = Check(f"anchor {ANCHOR}", Status.OK, "empty (rules load on first block)")
    return [parent, anchor]


def parse_lsof_owners(output: str) -> dict[int, str]:
    """Map pid -> login from `lsof -F pL` output."""
    owners: dict[int, str] = {}
    pid: int | None = None
    for line in output.splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("L") and pid is not None:
            owners[pid] = line[1:]
    return owners


def _is_system_login(login: str) -> bool:
    # Darwin daemons run as root or as underscore accounts (_mdnsresponder, _locationd, ...).
    return login == "root" or login.startswith("_")


def check_socket_visibility(run: SyncRunner = run_sync, user: str | None = None) -> Check:
    """Can we see sockets owned by other users and system daemons? (root; lsof is the reference).

    This is a root matter, not Full Disk Access: FDA does not widen what lsof can see.
    """
    user = user or pwd.getpwuid(os.geteuid()).pw_name
    res = run([LSOF, "-nP", "-iTCP", "-iUDP", "-FpL"], 15.0)
    owners = parse_lsof_owners(res.stdout)
    # lsof exits 1 when some descriptors are unreadable; only an empty result is a failure.
    if not owners and res.returncode != 0:
        detail = res.stderr.strip() or f"exit {res.returncode}"
        return Check("foreign sockets", Status.FAIL, f"lsof failed: {detail}")
    foreign = {login for login in owners.values() if login != user}
    daemons = sorted(login for login in foreign if _is_system_login(login))
    if daemons:
        sample = ", ".join(daemons[:4])
        return Check(
            "foreign sockets", Status.OK, f"{len(owners)} pids visible incl. daemons {sample}"
        )
    if foreign:
        sample = ", ".join(sorted(foreign)[:4])
        return Check(
            "foreign sockets",
            Status.WARN,
            f"{len(owners)} pids visible incl. {sample}, but no system-daemon sockets",
        )
    return Check(
        "foreign sockets",
        Status.WARN,
        f"only {user}'s sockets visible ({len(owners)} pids): run as root",
    )


def check_full_disk_access(path: str = SYSTEM_TCC_DB) -> Check:
    """FDA is a TCC grant on the terminal, probed by reading the system TCC database."""
    try:
        with open(path, "rb") as fh:
            fh.read(16)
    except PermissionError:
        return Check(
            "Full Disk Access",
            Status.WARN,
            "not granted to this terminal (optional today; needed for TCC.db inspection)",
        )
    except OSError as exc:
        return Check("Full Disk Access", Status.WARN, str(exc))
    return Check("Full Disk Access", Status.OK, "system TCC.db readable")


def check_snapshot_latency(
    poll_interval_s: float = 0.2, snapshot: Callable[[float], object] | None = None
) -> Check:
    """Time one socket snapshot; WARN if slower than the poll interval or psutil is denied."""
    try:
        take = snapshot or PsutilSnapshot()
        start = time.perf_counter()
        take(time.time())
        elapsed = time.perf_counter() - start
    except psutil.AccessDenied:
        detail = "needs root (psutil denied): lsof fallback, slower"
        return Check("socket snapshot", Status.WARN, detail)
    ms = elapsed * 1000
    status = Status.OK if elapsed < poll_interval_s else Status.WARN
    return Check(
        "socket snapshot",
        status,
        f"{ms:.0f} ms per poll (interval {poll_interval_s * 1000:.0f} ms)",
    )


def check_log_predicate(run: SyncRunner = run_sync) -> Check:
    """`log` rejects bad predicates immediately; still running after 2 s means accepted."""
    res = run(log_stream_command(), 2.0)
    if res.returncode == -1:
        return Check("log stream predicate", Status.OK, "accepted")
    detail = res.stderr.strip() or f"exit {res.returncode}"
    return Check("log stream predicate", Status.FAIL, detail)


def check_pktap(
    run: SyncRunner = run_sync, euid: int | None = None, binary: str = TCPDUMP_BINARY
) -> Check:
    """Whether `--udp-flows` can capture: tcpdump still running after 2 s has opened pktap.

    Never FAIL, the capture is optional: WARN without root or when tcpdump stops at once.
    """
    name = "pktap capture (--udp-flows)"
    if problem := pktap_unavailable(binary, euid):
        return Check(name, Status.WARN, problem)
    res = run(pktap_command(), 2.0)
    if res.returncode == -1:
        return Check(name, Status.OK, "tcpdump capturing")
    lines = res.stderr.strip().splitlines()
    return Check(name, Status.WARN, lines[-1] if lines else f"exit {res.returncode}")


def check_tcc_permissions(
    paths: tuple[str, ...] = (tcc_inspector.SYSTEM_TCC_DB, tcc_inspector.USER_TCC_DB),
) -> Check:
    """Summarise the standing TCC grants and flag high-risk holders of sensitive permissions.

    Needs Full Disk Access to read the databases; without it the check warns rather than fails,
    like `check_full_disk_access`. Path heuristics only (no per-binary codesign), so it stays
    fast; `safemaxxing permissions` shows the full breakdown.
    """
    entries, unavailable = tcc_inspector.inspect(paths)
    if not entries and unavailable:
        return Check("TCC permissions", Status.WARN, "; ".join(unavailable))
    risky = [
        e
        for e in entries
        if tcc_inspector.risk_reasons(e, exists=e.path is None or os.path.exists(e.path))
    ]
    summary = f"{len(entries)} sensitive grant(s)"
    if risky:
        names = sorted({PurePosixPath(e.client).name if e.path else e.client for e in risky})
        shown = ", ".join(names[:5]) + (" ..." if len(names) > 5 else "")
        summary += f", {len(risky)} high-risk: {shown}"
    else:
        summary += ", none high-risk"
    if unavailable:
        # One database unread (typically the system one, without root) hides the screen,
        # accessibility, input and full-disk grants: "none high-risk" would not be the full story.
        return Check("TCC permissions", Status.WARN, f"{summary}; unread: {'; '.join(unavailable)}")
    status = Status.WARN if risky else Status.OK
    return Check("TCC permissions", status, summary)


def run_doctor(poll_interval_s: float = 0.2) -> list[Check]:
    """Run every check in order; on a non-macOS host return after the basic checks."""
    checks = [check_platform(), check_root(), *check_binaries()]
    if checks[0].status is Status.FAIL:
        return checks
    checks += [check_pf_status(), *check_pf_anchor(), check_socket_visibility()]
    checks += [check_full_disk_access(), check_snapshot_latency(poll_interval_s)]
    checks += [check_log_predicate(), check_pktap(), check_tcc_permissions()]
    return checks


@dataclass(slots=True)
class SubsystemStats:
    """Per-subsystem-family counters and examples gathered by `summarize_sample`."""

    entries: int = 0
    redacted_message: int = 0
    redacted_image_path: int = 0
    missing_pid: int = 0
    parsed: int = 0
    with_pid: int = 0
    with_bundle: int = 0
    processes: Counter[str] = field(default_factory=Counter)
    unparsed_examples: list[str] = field(default_factory=list)
    parsed_examples: list[str] = field(default_factory=list)
    sensors: Counter[str] = field(default_factory=Counter)
    # messageType of parsed entries: the runtime streams at --level info, so Debug ones are missed.
    levels: Counter[str] = field(default_factory=Counter)
    # Every Control Center indicator list, in order: the timeline of which app holds which sensor.
    indicator_updates: list[str] = field(default_factory=list)


def _family(subsystem: str) -> str:
    for prefix in ("com.apple.TCC", "com.apple.locationd", "com.apple.coreaudio", "com.apple.cmio"):
        if subsystem.startswith(prefix):
            return prefix
    return subsystem or "<none>"


def summarize_sample(
    entries: Iterable[Mapping[str, object]], max_examples: int = 3
) -> dict[str, SubsystemStats]:
    """Group log entries by subsystem family and count what the sensor parser extracts.

    Tracks redacted fields, missing pids, parsed events per sensor and level, and keeps up to
    `max_examples` parsed and unparsed lines per family (plus one example per sensor kind).
    """
    stats: dict[str, SubsystemStats] = {}
    parser = SensorEventParser()
    for entry in entries:
        subsystem = entry.get("subsystem")
        s = stats.setdefault(
            _family(subsystem if isinstance(subsystem, str) else ""), SubsystemStats()
        )
        s.entries += 1
        message = entry.get("eventMessage")
        message = message if isinstance(message, str) else ""
        image = entry.get("processImagePath")
        image = image if isinstance(image, str) else ""
        if REDACTED_RE.search(message):
            s.redacted_message += 1
        if not image or REDACTED_RE.fullmatch(image):
            s.redacted_image_path += 1
        else:
            s.processes[image.rsplit("/", 1)[-1]] += 1
        if not isinstance(entry.get("processID"), int):
            s.missing_pid += 1
        events = parser.parse(entry)
        if (attributions := parse_attributions(message)) is not None:
            s.indicator_updates.append(
                "[" + ", ".join(f"{kind}:{who}" for kind, who in sorted(attributions)) + "]"
            )
            if not events:
                continue  # Handled: the update only removed attributions.
        if not events:
            if len(s.unparsed_examples) < max_examples:
                category = entry.get("category")
                prefix = f"[{category}] " if isinstance(category, str) and category else ""
                s.unparsed_examples.append(prefix + message[:240])
            continue
        level = entry.get("messageType")
        level = level if isinstance(level, str) else "?"
        for event in events:
            # Keep the first example of every sensor kind, even past max_examples.
            if len(s.parsed_examples) < max_examples or event.sensor.value not in s.sensors:
                s.parsed_examples.append(
                    f"{event.sensor.value} {event.identity} pid={event.pid} [{level}] "
                    f"{message[:160]}"
                )
            s.sensors[event.sensor.value] += 1
            s.levels[level] += 1
            s.parsed += 1
            s.with_pid += event.pid is not None
            s.with_bundle += event.bundle_id is not None
    return stats


async def collect_log_sample(
    seconds: float,
    command: Sequence[str] | None = None,
    level: str = "info",
    predicate: str = DISCOVERY_PREDICATE,
) -> list[dict[str, object]]:
    """Capture with a broad predicate: the point is to see lines the runtime filter drops."""
    entries: list[dict[str, object]] = []
    listener = SensorListener(command=command or log_stream_command(predicate, level))
    try:
        async with asyncio.timeout(seconds):
            async for entry in listener.entries():
                entries.append(entry)
    except TimeoutError:
        pass
    return entries
