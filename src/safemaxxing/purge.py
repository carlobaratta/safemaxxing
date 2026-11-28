"""`safemaxxing purge`: remove everything safemaxxing put on this Mac, after asking.

What goes, in this order:

1. the launchd jobs (watch daemon, boot restore job, Paranoia Mode watchdog), unloaded first so
   nothing adds a block or a log line while the rest goes;
2. pf: every table in `com.apple/safemaxxing` flushed, the grants sub-anchor's rules flushed,
   the anchor's ruleset replaced by an empty one (checked with `pfctl -n` first), then
   safemaxxing's pf reference released (`pfctl -X`, never `pfctl -d`). pf stays on if anything
   else holds it; `/etc/pf.conf` and the system's own rules are never touched;
3. the saved state (block list, pf reference and its lock, pinned Team IDs, DNS blocklist
   cache) and its directory, the run files in `/var/run/safemaxxing`, and the logs in
   `/var/log`.

Only the names safemaxxing itself writes are removed, each with `unlink`, which removes a
symlink rather than what it points to; anything else found in its directories is reported and
left in place. Refused while Paranoia Mode is on or another `tui`, `watch` or `menubar` runs:
both keep pf state of their own that a purge underneath them would leave inconsistent.
The installed program itself (the `.pkg` bundle) stays; the CLI prints how to remove it.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import psutil

from safemaxxing import boot, daemon
from safemaxxing.boot import LaunchdJob
from safemaxxing.firewall import (
    ANCHOR,
    BLOCKLIST,
    PF_REFERENCE,
    PFCTL,
    STATE_DIR,
    TABLE,
    CommandResult,
    FirewallError,
    PfReference,
    Runner,
    anchor_missing,
    meaningful_stderr,
    run_command,
    table_missing,
)
from safemaxxing.lockdown import watchdog
from safemaxxing.lockdown.controller import LOCK, PINS
from safemaxxing.lockdown.dns import BLOCKLIST_CACHE
from safemaxxing.lockdown.rules import (
    APPLE_TABLE,
    DNS_TABLE,
    GRANTS_ANCHOR,
    NTP_TABLE,
    USER_TABLE,
)

TABLES = (TABLE, DNS_TABLE, NTP_TABLE, APPLE_TABLE, USER_TABLE)
# Subcommands that keep pf or lockdown state in memory while they run.
LONG_RUNNING = frozenset({"tui", "watch", "menubar"})

type Instances = Callable[[], list[tuple[int, str]]]


@dataclass(frozen=True, slots=True)
class PurgeStep:
    """One thing removed (or that would be, in a dry run), and how it went."""

    name: str
    ok: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class PurgeTargets:
    """Everything a purge removes; the defaults are the real paths, tests pass temp ones."""

    jobs: tuple[LaunchdJob, ...]
    reference: PfReference
    state_dir: Path = STATE_DIR
    state_files: tuple[Path, ...] = (
        BLOCKLIST,
        PF_REFERENCE,
        PF_REFERENCE.with_name(PF_REFERENCE.name + ".lock"),
        PINS,
        BLOCKLIST_CACHE,
    )
    run_dir: Path = watchdog.RUN_DIR
    run_files: tuple[Path, ...] = (watchdog.HEARTBEAT, LOCK)
    armed_flag: Path = watchdog.ARMED
    logs: tuple[Path, ...] = (boot.LOG, daemon.LOG, daemon.ERR_LOG, watchdog.LOG)


def default_targets(runner: Runner = run_command) -> PurgeTargets:
    """The real launchd jobs, files and pf reference."""
    jobs = (daemon.WatchDaemon(runner), boot.BootJob(runner), watchdog.WatchdogJob(runner))
    return PurgeTargets(jobs=jobs, reference=PfReference())


def running_instances() -> list[tuple[int, str]]:
    """Other safemaxxing processes that hold state while they run: (pid, command line)."""
    mine = {os.getpid(), *(p.pid for p in psutil.Process().parents())}
    found: list[tuple[int, str]] = []
    for proc in psutil.process_iter(["pid", "cmdline"]):
        argv = proc.info.get("cmdline") or []
        if proc.info["pid"] in mine or not argv:
            continue
        names = [Path(arg).name for arg in argv]
        if "safemaxxing" in names and LONG_RUNNING.intersection(argv):
            found.append((proc.info["pid"], " ".join(argv)))
    return found


def blocker(targets: PurgeTargets, instances: Instances = running_instances) -> str:
    """Why a purge must not run now, or ''."""
    if targets.armed_flag.exists():
        return "Paranoia Mode is on: leave it first (P in the TUI), then purge"
    if running := instances():
        pids = ", ".join(str(pid) for pid, _ in running)
        return f"safemaxxing is still running (pid {pids}): quit it first, then purge"
    return ""


def _leftovers(directory: Path, known: Iterable[Path]) -> tuple[list[Path], list[str]]:
    """Our files in `directory` (known names and our temp files), and the names of others."""
    names = {p.name for p in known}
    ours, others = [], []
    try:
        entries = sorted(os.listdir(directory))
    except FileNotFoundError:
        return [], []
    for name in entries:
        temp = name.startswith(".") and any(name.startswith(f".{n}-") for n in names)
        if name in names or temp:
            ours.append(directory / name)
        else:
            others.append(name)
    return ours, others


def _exists(path: Path) -> bool:
    return os.path.lexists(path)


async def planned(targets: PurgeTargets) -> list[str]:
    """What a purge would remove right now, one line each, for the confirmation prompt."""
    lines: list[str] = []
    for job in targets.jobs:
        status = await job.status()
        if status.installed or status.loaded:
            lines.append(f"launchd job {job.label} ({job.plist})")
    lines.append(f"pf: the tables and rules in anchor {ANCHOR}, and safemaxxing's pf reference")
    for directory, known in (
        (targets.state_dir, targets.state_files),
        (targets.run_dir, targets.run_files),
    ):
        ours, _ = _leftovers(directory, known)
        lines += [str(path) for path in ours]
    lines += [str(log) for log in targets.logs if _exists(log)]
    return lines


async def _purge_pf(run: Runner, reference: PfReference) -> list[PurgeStep]:
    steps: list[PurgeStep] = []
    async with reference.locked():
        failed = []
        for table in TABLES:
            res = await run([PFCTL, "-a", ANCHOR, "-t", table, "-T", "flush"])
            if res.returncode != 0 and not table_missing(res.stderr):
                failed.append(f"{table}: {'; '.join(meaningful_stderr(res.stderr)) or 'failed'}")
        steps.append(PurgeStep("pf tables emptied", not failed, "; ".join(failed)))
        res = await run([PFCTL, "-a", GRANTS_ANCHOR, "-F", "rules"])
        ok = res.returncode == 0 or anchor_missing(res.stderr)
        steps.append(PurgeStep(f"pf rules in {GRANTS_ANCHOR}", ok, _problem(res, ok)))
        # An empty ruleset replaces every rule type in the anchor at once (filter and rdr).
        for argv in ([PFCTL, "-a", ANCHOR, "-n", "-f", "-"], [PFCTL, "-a", ANCHOR, "-f", "-"]):
            res = await run(argv, stdin="")
            ok = (res.returncode == 0 and not meaningful_stderr(res.stderr)) or anchor_missing(
                res.stderr
            )
            if not ok:
                break
        steps.append(PurgeStep(f"pf rules in {ANCHOR}", ok, _problem(res, ok)))
        steps.append(PurgeStep("pf reference", True, await reference.release(run)))
    return steps


def _problem(res: CommandResult, ok: bool) -> str:
    if ok:
        return ""
    return "; ".join(meaningful_stderr(res.stderr)) or f"exit {res.returncode}"


def _unlink(path: Path) -> PurgeStep | None:
    """Remove `path` (a symlink itself, never its target); None if it was not there."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return PurgeStep(str(path), False, str(exc))
    return PurgeStep(str(path), True, "removed")


def _purge_dir(directory: Path, known: Iterable[Path]) -> list[PurgeStep]:
    ours, others = _leftovers(directory, known)
    steps = [step for path in ours if (step := _unlink(path)) is not None]
    if others:
        kept = ", ".join(others)
        steps.append(PurgeStep(str(directory), True, f"kept: not created by safemaxxing: {kept}"))
    elif _exists(directory):
        try:
            os.rmdir(directory)
        except OSError as exc:
            steps.append(PurgeStep(str(directory), False, str(exc)))
        else:
            steps.append(PurgeStep(str(directory), True, "removed"))
    return steps


async def purge(targets: PurgeTargets, run: Runner = run_command) -> list[PurgeStep]:
    """Remove everything in `targets`, in the module docstring's order; never raises for one
    step that fails, so the others still happen. Check `blocker` first."""
    steps: list[PurgeStep] = []
    for job in targets.jobs:
        status = await job.status()
        if not (status.installed or status.loaded):
            continue
        await job.uninstall()
        after = await job.status()
        steps.append(
            PurgeStep(
                f"launchd job {job.label}",
                not (after.installed or after.loaded),
                "unloaded and removed" if not after.installed else "still installed",
            )
        )
    try:
        steps += await _purge_pf(run, targets.reference)
    except (OSError, FirewallError) as exc:
        steps.append(PurgeStep("pf", False, str(exc)))
    steps += _purge_dir(targets.state_dir, targets.state_files)
    steps += _purge_dir(targets.run_dir, targets.run_files)
    for log in targets.logs:
        if (step := _unlink(log)) is not None:
            steps.append(step)
    return steps
