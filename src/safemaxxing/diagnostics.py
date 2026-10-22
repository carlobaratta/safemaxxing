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

import psutil

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
from safemaxxing.sensors import (
    DISCOVERY_PREDICATE,
    LOG_BINARY,
    REDACTED_RE,
    SensorListener,
    log_stream_command,
    parse_entry,
)

LSOF = "/usr/sbin/lsof"
SYSTEM_TCC_DB = "/Library/Application Support/com.apple.TCC/TCC.db"

SyncRunner = Callable[[Sequence[str], float], CommandResult]


class Status(StrEnum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: Status
    detail: str = ""


def run_sync(argv: Sequence[str], timeout_s: float) -> CommandResult:
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
    if platform.system() != "Darwin":
        return Check("macOS", Status.FAIL, f"running on {platform.system()}")
    release, _, machine = platform.mac_ver()
    return Check("macOS", Status.OK, f"{release} ({machine})")


def check_root(euid: int | None = None) -> Check:
    euid = os.geteuid() if euid is None else euid
    if euid == 0:
        return Check("root privileges", Status.OK, "euid 0")
    return Check("root privileges", Status.FAIL, f"euid {euid}: re-run with sudo")


def check_binaries(paths: Iterable[str] = (LOG_BINARY, PFCTL, LSOF)) -> list[Check]:
    return [
        Check(path, Status.OK, "present")
        if os.access(path, os.X_OK)
        else Check(path, Status.FAIL, "missing")
        for path in paths
    ]


def check_pf_status(run: SyncRunner = run_sync) -> Check:
    res = run([PFCTL, "-s", "info"], 5.0)
    enabled = parse_pf_status(res.stdout)
    if enabled is None:
        detail = "; ".join(meaningful_stderr(res.stderr)) or "unrecognised `pfctl -s info` output"
        return Check("pf status", Status.WARN, detail)
    if enabled:
        return Check("pf status", Status.OK, "Enabled")
    return Check("pf status", Status.WARN, "Disabled (enabled automatically on first block)")


def check_pf_anchor(run: SyncRunner = run_sync) -> list[Check]:
    main = run([PFCTL, "-s", "rules"], 5.0)
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


def check_socket_visibility(run: SyncRunner = run_sync, user: str | None = None) -> Check:
    """Can we see sockets owned by other users? (requires root; lsof is the reference)."""
    user = user or pwd.getpwuid(os.geteuid()).pw_name
    res = run([LSOF, "-nP", "-iTCP", "-iUDP", "-FpL"], 15.0)
    owners = parse_lsof_owners(res.stdout)
    foreign = {login for login in owners.values() if login != user}
    if foreign:
        sample = ", ".join(sorted(foreign)[:4])
        return Check("foreign sockets", Status.OK, f"{len(owners)} pids visible incl. {sample}")
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
    try:
        take = snapshot or PsutilSnapshot()
        start = time.perf_counter()
        take(time.time())
        elapsed = time.perf_counter() - start
    except psutil.AccessDenied:
        return Check("socket snapshot", Status.WARN, "psutil denied: lsof fallback (slow)")
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


def run_doctor(poll_interval_s: float = 0.2) -> list[Check]:
    checks = [check_platform(), check_root(), *check_binaries()]
    if checks[0].status is Status.FAIL:
        return checks
    checks += [check_pf_status(), *check_pf_anchor(), check_socket_visibility()]
    checks += [check_full_disk_access(), check_snapshot_latency(poll_interval_s)]
    checks.append(check_log_predicate())
    return checks


@dataclass(slots=True)
class SubsystemStats:
    entries: int = 0
    redacted_message: int = 0
    redacted_image_path: int = 0
    missing_pid: int = 0
    parsed: int = 0
    with_pid: int = 0
    with_bundle: int = 0
    processes: Counter[str] = field(default_factory=Counter)
    unparsed_examples: list[str] = field(default_factory=list)


def _family(subsystem: str) -> str:
    for prefix in ("com.apple.TCC", "com.apple.locationd", "com.apple.coreaudio", "com.apple.cmio"):
        if subsystem.startswith(prefix):
            return prefix
    return subsystem or "<none>"


def summarize_sample(
    entries: Iterable[Mapping[str, object]], max_examples: int = 3
) -> dict[str, SubsystemStats]:
    stats: dict[str, SubsystemStats] = {}
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
        event = parse_entry(entry)
        if event is None:
            if len(s.unparsed_examples) < max_examples:
                s.unparsed_examples.append(message[:240])
            continue
        s.parsed += 1
        s.with_pid += event.pid is not None
        s.with_bundle += event.bundle_id is not None
    return stats


async def collect_log_sample(
    seconds: float, command: Sequence[str] | None = None
) -> list[dict[str, object]]:
    """Capture with the broad predicate: the point is to see lines the runtime filter drops."""
    entries: list[dict[str, object]] = []
    listener = SensorListener(command=command or log_stream_command(DISCOVERY_PREDICATE))
    try:
        async with asyncio.timeout(seconds):
            async for entry in listener.entries():
                entries.append(entry)
    except TimeoutError:
        pass
    return entries
