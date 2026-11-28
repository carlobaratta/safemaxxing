"""`safemaxxing report`: what safemaxxing enforces on this Mac right now, to read or to share.

The report gathers the same facts `doctor`, `blocked`, `boot status` and `daemon status` print
one by one (pf's state, the anchor's rules, live and saved blocks, the launchd jobs, Paranoia
Mode, the environment checks, the daemon's last alerts) and renders them as Markdown, JSON or
plain text. Nothing leaves the machine: the report is printed or written to a file the user
names, 0600.

`redact` makes a copy fit for a public bug report: home directories, the user's login, the
host name and every IP address (each distinct one becomes `<ip-N>`, so the report still shows
which lines name the same address) are replaced.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import getpass
import ipaddress
import json
import os
import platform
import re
import socket
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from safemaxxing import __version__, boot, daemon
from safemaxxing.diagnostics import Check, Status, run_doctor
from safemaxxing.firewall import (
    ANCHOR,
    PFCTL,
    BlockList,
    PfFirewall,
    PfReference,
    Runner,
    is_root,
    parse_pf_status,
    run_command,
)
from safemaxxing.lockdown import watchdog

ISSUES_URL = "https://github.com/carlobaratta/safemaxxing/issues/new/choose"


class ReportFormat(StrEnum):
    """How `report` renders: Markdown (default), JSON, or plain text for a printer."""

    MARKDOWN = "markdown"
    JSON = "json"
    TEXT = "text"


@dataclass(frozen=True, slots=True)
class JobState:
    """One launchd job as `launchctl print` and the plist on disk show it."""

    name: str
    label: str
    installed: bool
    loaded: bool


@dataclass(frozen=True, slots=True)
class SecurityReport:
    """Everything the report shows. None means "could not be read" (usually: needs root)."""

    generated: str
    version: str
    macos: str
    root: bool
    pf_enabled: bool | None
    anchor_rules: tuple[str, ...] | None
    blocked_live: tuple[str, ...] | None
    blocked_saved: tuple[str, ...] | None
    jobs: tuple[JobState, ...]
    paranoia_armed: bool
    pf_reference_held: bool | None
    checks: tuple[Check, ...] = ()
    recent_alerts: tuple[str, ...] | None = None


async def _pf_state(run: Runner) -> tuple[bool | None, tuple[str, ...] | None]:
    info = await run([PFCTL, "-s", "info"])
    enabled = parse_pf_status(info.stdout)
    if enabled is None:
        return None, None
    rules = await run([PFCTL, "-a", ANCHOR, "-s", "rules"])
    lines = tuple(line.strip() for line in rules.stdout.splitlines() if line.strip())
    return enabled, lines if rules.returncode == 0 else ()


def _saved_blocks(store: BlockList) -> tuple[str, ...] | None:
    try:
        return tuple(store.load())
    except (OSError, ValueError):
        return None


def _recent_alerts(count: int = 10) -> tuple[str, ...] | None:
    if not os.access(daemon.LOG, os.R_OK):
        return None if daemon.LOG.exists() else ()
    return tuple(daemon.recent_alerts(count=count))


async def collect_report(
    run: Runner = run_command,
    checks: bool = True,
    doctor: Callable[[], list[Check]] = run_doctor,
    root: Callable[[], bool] = is_root,
    jobs: Iterable[tuple[str, boot.LaunchdJob]] | None = None,
    clock: Callable[[], float] = time.time,
    store: BlockList | None = None,
    reference: PfReference | None = None,
    armed_flag: Path = watchdog.ARMED,
    alerts: Callable[[], tuple[str, ...] | None] = _recent_alerts,
) -> SecurityReport:
    """Gather the report; nothing here changes pf, launchd or a file. Every source is a
    parameter, so the tests never read this Mac's own state."""
    privileged = root()
    enabled, rules = await _pf_state(run) if privileged else (None, None)
    live = tuple(await PfFirewall(runner=run).blocked()) if privileged else None
    if jobs is None:
        jobs = (
            ("watch daemon", daemon.WatchDaemon(run)),
            ("boot restore", boot.BootJob(run)),
            ("Paranoia watchdog", watchdog.WatchdogJob(run)),
        )
    states = []
    for name, job in jobs:
        status = await job.status()
        states.append(JobState(name, job.label, status.installed, status.loaded))
    reference = reference or PfReference()
    held = reference.load() is not None if privileged else None
    found = tuple(await asyncio.to_thread(doctor)) if checks else ()
    return SecurityReport(
        generated=time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(clock())),
        version=__version__,
        macos=f"{platform.mac_ver()[0] or platform.system()} ({platform.machine()})",
        root=privileged,
        pf_enabled=enabled,
        anchor_rules=rules,
        blocked_live=live,
        blocked_saved=_saved_blocks(store or BlockList()),
        jobs=tuple(states),
        paranoia_armed=armed_flag.exists(),
        pf_reference_held=held,
        checks=found,
        recent_alerts=alerts() if privileged else None,
    )


def _yes_no(value: bool | None, yes: str = "yes", no: str = "no") -> str:
    return "needs root" if value is None else yes if value else no


def _summary(report: SecurityReport) -> list[tuple[str, str]]:
    live = report.blocked_live
    saved = report.blocked_saved
    return [
        ("Generated", report.generated),
        ("safemaxxing", report.version),
        ("macOS", report.macos),
        ("Running as root", _yes_no(report.root)),
        ("pf", _yes_no(report.pf_enabled, "enabled", "disabled")),
        ("Paranoia Mode", "on" if report.paranoia_armed else "off"),
        ("Blocked now", "needs root" if live is None else str(len(live))),
        ("Saved for reboot", "unreadable" if saved is None else str(len(saved))),
        ("pf reference held", _yes_no(report.pf_reference_held)),
    ]


_STATUS_MARK = {Status.OK: "ok", Status.WARN: "warn", Status.FAIL: "FAIL"}


def render_markdown(report: SecurityReport) -> str:
    """The report as Markdown: a summary table, then one section per topic."""
    out = ["# safemaxxing security report", "", "| | |", "| --- | --- |"]
    out += [f"| {key} | {value} |" for key, value in _summary(report)]
    out += ["", "## launchd jobs", "", "| Job | Label | Installed | Loaded |"]
    out += ["| --- | --- | --- | --- |"]
    out += [
        f"| {j.name} | `{j.label}` | {_yes_no(j.installed)} | {_yes_no(j.loaded)} |"
        for j in report.jobs
    ]
    out += ["", f"## pf rules in `{ANCHOR}`", ""]
    if report.anchor_rules is None:
        out.append("_Needs root._")
    elif not report.anchor_rules:
        out.append("_None loaded (they load with the first block)._")
    else:
        out += ["```", *report.anchor_rules, "```"]
    for title, ips in (
        ("Blocked addresses (live)", report.blocked_live),
        ("Blocked addresses (saved for reboot)", report.blocked_saved),
    ):
        out += ["", f"## {title}", ""]
        if ips is None:
            out.append("_Needs root._")
        else:
            out += [f"- `{ip}`" for ip in ips] or ["_None._"]
    if report.checks:
        out += ["", "## Environment checks", "", "| Check | Status | Detail |"]
        out += ["| --- | --- | --- |"]
        out += [
            f"| {c.name} | {_STATUS_MARK[c.status]} | {c.detail.replace('|', '/')} |"
            for c in report.checks
        ]
    out += ["", "## Recent daemon alerts", ""]
    if report.recent_alerts is None:
        out.append("_Needs root (the daemon's log is readable by root only)._")
    else:
        out += [f"- {line}" for line in report.recent_alerts] or ["_None._"]
    out += [
        "",
        "---",
        "",
        "Generated locally by `safemaxxing report`; nothing was sent anywhere.",
        f"Bug reports: {ISSUES_URL} (attach `safemaxxing report --redact`).",
        "",
    ]
    return "\n".join(out)


def render_text(report: SecurityReport) -> str:
    """The report as plain text, for a terminal or a printer."""
    width = max(len(key) for key, _ in _summary(report))
    out = ["safemaxxing security report", "=" * 27, ""]
    out += [f"{key:<{width}}  {value}" for key, value in _summary(report)]
    out += ["", "launchd jobs"]
    out += [
        f"  {j.name:<18} installed={_yes_no(j.installed)} loaded={_yes_no(j.loaded)}"
        for j in report.jobs
    ]
    out += ["", f"pf rules in {ANCHOR}"]
    if report.anchor_rules is None:
        out.append("  needs root")
    else:
        out += [f"  {line}" for line in report.anchor_rules] or ["  none loaded"]
    for title, ips in (("blocked (live)", report.blocked_live), ("saved", report.blocked_saved)):
        out += ["", title]
        out += ["  needs root"] if ips is None else [f"  {ip}" for ip in ips] or ["  none"]
    if report.checks:
        out += ["", "environment checks"]
        out += [f"  [{_STATUS_MARK[c.status]:>4}] {c.name}: {c.detail}" for c in report.checks]
    out += ["", "recent daemon alerts"]
    if report.recent_alerts is None:
        out.append("  needs root")
    else:
        out += [f"  {line}" for line in report.recent_alerts] or ["  none"]
    return "\n".join(out) + "\n"


def render_json(report: SecurityReport) -> str:
    """The report as one JSON object (Check statuses as their string values)."""
    payload = dataclasses.asdict(report)
    payload["checks"] = [
        {"name": c.name, "status": c.status.value, "detail": c.detail} for c in report.checks
    ]
    return json.dumps(payload, indent=2) + "\n"


RENDERERS: dict[ReportFormat, Callable[[SecurityReport], str]] = {
    ReportFormat.MARKDOWN: render_markdown,
    ReportFormat.JSON: render_json,
    ReportFormat.TEXT: render_text,
}

_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
_HOME_RE = re.compile(r"/Users/[^/\s\"'`|)]+")
# Not personal: the addresses every Mac has.
_KEEP = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})


def _identity_words() -> set[str]:
    words = {os.environ.get(name, "") for name in ("SUDO_USER", "USER", "LOGNAME")}
    with contextlib.suppress(KeyError, OSError):
        words.add(getpass.getuser())
    host = socket.gethostname()
    words |= {host, host.split(".", 1)[0]}
    return {w for w in words if len(w) >= 3 and w not in {"root", "localhost"}}


def redact(text: str, identities: Iterable[str] | None = None) -> str:
    """`text` without what identifies the person or the machine: home directories, login and
    host names, and IP addresses (`<ip-1>`, `<ip-2>`, ... per distinct address)."""
    seen: dict[str, str] = {}

    def address(match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            canonical = str(ipaddress.ip_address(raw))
        except ValueError:
            return raw
        if canonical in _KEEP:
            return raw
        return seen.setdefault(canonical, f"<ip-{len(seen) + 1}>")

    text = _HOME_RE.sub("/Users/<user>", text)
    text = _IPV4_RE.sub(address, text)
    text = _IPV6_RE.sub(address, text)
    words = sorted(_identity_words() if identities is None else set(identities), key=len)
    for word in reversed(words):
        text = re.sub(rf"(?<![\w-]){re.escape(word)}(?![\w-])", "<redacted>", text)
    return text
