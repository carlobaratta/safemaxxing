"""Panels and bars of the dashboard, each a Static fed with an immutable snapshot.

The app gathers the numbers (pf status, poller and pktap counters, lockdown state) and hands
them over; the `render_*` functions turn a snapshot into Rich renderables and are tested
without Textual.

The posture bar at the top answers the first question anyone has, in plain words: is anything
wrong right now? It never says more than the program can stand behind: safemaxxing watches and
can block, so a quiet screen reads "Watching", never "Safe".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text
from textual.widgets import Static

from safemaxxing.lockdown.controller import LockdownState
from safemaxxing.models import Alert, Event, NetworkConnection, Severity
from safemaxxing.tui.badges import (
    clock,
    mitigation_badges,
    sensor_pills,
    severity_badge,
    severity_ink,
)
from safemaxxing.tui.palette import current
from safemaxxing.tui.timeline import event_source


def good() -> str:
    """Style of a state that is working."""
    return f"bold {current().ok}"


def warn() -> str:
    """Style of a state that needs a look."""
    return f"bold {current().caution}"


def bad() -> str:
    """Style of a state that is broken or dangerous."""
    return f"bold {current().danger}"


def muted() -> str:
    """Style of labels and secondary text."""
    return current().muted


def strong() -> str:
    """Style of the value that matters on a line."""
    return f"bold {current().strong}"


@dataclass(frozen=True, slots=True)
class PfStatus:
    """What the last pf poll found; `enabled`/`anchor_loaded` are None when unknown.

    `checked` is the wall-clock time of the poll (not compared, so two polls that found the
    same state are equal)."""

    enabled: bool | None
    anchor_loaded: bool | None
    blocked: tuple[str, ...] = ()
    error: str | None = None
    checked: float | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class RuntimeStats:
    """Counters sampled once a second: poller, pktap, DNS cache, process CPU and rates."""

    cpu_percent: float | None = None
    poll_ms: float | None = None
    poll_interval_ms: float | None = None
    sockets: int = 0
    pktap: bool = False
    pktap_packets_per_s: float = 0.0
    pktap_flows_per_s: float = 0.0
    pktap_restarts: int = 0
    pktap_unparsed: int = 0
    dns_entries: int | None = None
    events_per_s: float = 0.0
    alerts: int = 0
    live: bool = True


@dataclass(frozen=True, slots=True)
class Selection:
    """The connection the inspector shows and the actions act on, with its alert if any."""

    connection: NetworkConnection
    alert: Alert | None = None
    events: tuple[Event, ...] = ()


class DaemonState(StrEnum):
    """The launchd watch daemon as the header shows it."""

    UNKNOWN = "checking"
    RUNNING = "on"
    STOPPED = "stopped"
    ABSENT = "off"


@dataclass(frozen=True, slots=True)
class Posture:
    """Everything the posture bar needs: is the watch running, and does anything need you.

    `review` counts the alerts of HIGH severity or above whose address is not blocked and
    whose process is not paused; `contained` the alerts that are one or the other.
    `lockdown` is None when Paranoia Mode is unavailable (not root). `starting` holds until
    the socket poller's first pass; `error` says why a stopped supervisor stopped and what to
    do. The right-hand side shows the profile, the live block count (None: unknown), the
    watch daemon and the time of the last sensor event or alert.
    """

    live: bool = True
    lockdown: LockdownState | None = None
    alerts: int = 0
    review: int = 0
    worst: Severity | None = None
    contained: int = 0
    enforce: bool = True
    starting: bool = False
    error: str | None = None
    profile: str = ""
    blocks: int | None = None
    daemon: DaemonState = DaemonState.UNKNOWN
    last_event: float | None = None


@dataclass(frozen=True, slots=True)
class ModeStatus:
    """Paranoia Mode as the side card shows it; `state` None means it needs root."""

    state: LockdownState | None
    leases: tuple[str, ...] = ()
    grants: int = 0
    denied: int = 0
    profile: str = ""


def stop_hint(exc: BaseException) -> str:
    """What a supervisor failure means, and what to do about it, in one line."""
    text = str(exc).lower()
    if isinstance(exc, PermissionError) or "not permitted" in text or "permission" in text:
        return (
            "permission denied: quit (q), run `sudo safemaxxing tui`, and give the terminal "
            "Full Disk Access (System Settings › Privacy & Security)"
        )
    if "tcpdump" in text or "pktap" in text:
        return "the pktap capture failed: it needs sudo; or start without --udp-flows/--tcp-flows"
    if isinstance(exc, FileNotFoundError):
        return "a system tool is missing: quit (q) and run `safemaxxing doctor`"
    return f"{exc}: quit (q) and run `safemaxxing doctor` to find out why"


def verdict(p: Posture) -> tuple[str, str, str]:
    """`(style, headline, detail)` for the posture bar, most urgent state first."""
    if not p.live:
        return bad(), "■ Stopped", p.error or "the supervisor exited: nothing is being watched"
    if p.lockdown is LockdownState.ON:
        return bad(), "■ Paranoia Mode", "egress denied except the apps you granted"
    if p.lockdown is LockdownState.ARMING:
        return warn(), "◆ Arming Paranoia Mode", "loading the default-deny rules"
    if p.lockdown is LockdownState.TRIPPED:
        return warn(), "▲ Paranoia Mode tripped", "the watchdog restored the normal rules"
    if p.starting:
        return (
            f"bold {current().accent}",
            "◌ Starting",
            "launching `log stream` and the socket poller…",
        )
    if p.review:
        noun = "alert" if p.review == 1 else "alerts"
        style = severity_ink(p.worst) if p.worst is not None else warn()
        action = "b blocks the address, s pauses the app" if p.enforce else "blocking needs sudo"
        return style, f"▲ {p.review} {noun} to review", f"select one: {action}"
    parts = []
    if not p.alerts:
        parts.append("no exfiltration pattern seen")
    else:
        parts.append(f"nothing high-risk open · {p.alerts} in the feed")
    if p.contained:
        parts.append(f"{p.contained} contained")
    if not p.enforce:
        parts.append("read-only without sudo")
    return good(), "● Watching", " · ".join(parts)


def _profile(p: Posture) -> str:
    if p.lockdown is LockdownState.ON:
        return f"Paranoia ({p.profile})" if p.profile else "Paranoia"
    if p.lockdown is LockdownState.ARMING:
        return "Arming"
    return "Normal"


def status_line(p: Posture, now: str, compact: bool = False) -> Text:
    """The header's right-hand side: profile, blocks, daemon, last event and the clock."""
    quiet = muted()
    if p.lockdown is LockdownState.ON and p.live:
        quiet = current().lockdown_quiet
    blocks = "?" if p.blocks is None else str(p.blocks)
    if compact:
        return Text(f"{_profile(p)} · {blocks} blk · {now}", style=quiet)
    marks = {
        DaemonState.RUNNING: "●",
        DaemonState.STOPPED: "▲",
        DaemonState.ABSENT: "○",
        DaemonState.UNKNOWN: "◌",
    }
    daemon = f"daemon {marks[p.daemon]} {p.daemon.value}"
    last = "no events yet" if p.last_event is None else f"last event {clock(p.last_event)[:8]}"
    return Text(f"{_profile(p)} · {blocks} blocked · {daemon} · {last} · {now}", style=quiet)


def render_posture(p: Posture, now: str, compact: bool = False) -> RenderableType:
    """One line: the name and the verdict in words on the left; on the right the profile,
    the block count, the watch daemon, the last event and the clock (fewer when `compact`)."""
    style, headline, detail = verdict(p)
    palette = current()
    brand, quiet = f"bold {palette.accent}", muted()
    if p.lockdown is LockdownState.ON and p.live:
        # The bar itself turns dark red (tcss): red ink on it would not read.
        ink = f"bold {palette.lockdown_ink}"
        brand, style, quiet = ink, ink, palette.lockdown_quiet
    left = Text.assemble(("safemaxxing", brand), "   ", (headline, style), ("  " + detail, quiet))
    # Two cells apart, so a cut verdict never runs into the status on the right.
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
    grid.add_column(justify="right", no_wrap=True)
    grid.add_row(left, status_line(p, now, compact))
    return grid


def render_mode(mode: ModeStatus) -> RenderableType:
    """The Paranoia Mode card: its state and, while on, what it lets through."""
    if mode.state is None:
        return Group(
            Text("○ Unavailable", style=warn()),
            Text("Needs root: start the dashboard with sudo.", style=muted()),
        )
    if mode.state is LockdownState.ON:
        grid = _grid()
        grid.add_row("leases", ", ".join(mode.leases) or Text("none", style=muted()))
        grid.add_row("grants", str(mode.grants))
        grid.add_row("denied", str(mode.denied))
        if mode.profile:
            grid.add_row("profile", mode.profile)
        return Group(Text("■ On · egress denied by default", style=bad()), grid)
    if mode.state is LockdownState.ARMING:
        return Group(
            Text("◆ Arming…", style=warn()),
            Text("Watchdog first, then the default-deny rules.", style=muted()),
        )
    head = Text("○ Off", style=strong())
    if mode.state is LockdownState.TRIPPED:
        head = Text("▲ Tripped: back to normal rules", style=warn())
    lines: list[RenderableType] = [
        head,
        Text(
            "Denies every connection except apps using a sensor or granted with g.",
            style=muted(),
        ),
    ]
    if mode.profile:
        lines.append(Text(f"profile {mode.profile}", style=muted()))
    return Group(*lines)


def _grid() -> Table:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style=muted(), no_wrap=True, min_width=8)
    grid.add_column(overflow="fold")
    return grid


def _flag(value: bool | None, yes: str, no: str, needed: bool) -> Text:
    """`yes` in green, or `no`: red only when something depends on it, else just grey."""
    if value is None:
        return Text("unknown", style=warn())
    if value:
        return Text(yes, style=good())
    return Text(no, style=bad() if needed else muted())


def render_firewall(pf: PfStatus | None, stats: RuntimeStats) -> RenderableType:
    """pf state, anchor, block-table size, socket poller and pktap capture, one per line."""
    grid = _grid()
    if pf is None:
        grid.add_row("pf", Text("checking…", style=muted()))
    elif pf.error:
        grid.add_row("pf", Text(pf.error, style=warn()))
    else:
        # pf and the anchor come up with the first block: off with nothing blocked is normal.
        count = len(pf.blocked)
        state = _flag(pf.enabled, "● enabled", "○ disabled", needed=count > 0)
        anchor = _flag(pf.anchor_loaded, "● loaded", "○ not loaded", needed=count > 0)
        if count and (pf.enabled is False or pf.anchor_loaded is False):
            state.append(" · blocks not enforced", style=bad())
        elif pf.anchor_loaded is False:
            anchor.append(" until a block", style=muted())
        grid.add_row("pf", state)
        grid.add_row("anchor", anchor)
        noun = "address" if count == 1 else "addresses"
        grid.add_row("blocked", Text(f"{count} {noun}", style=strong() if count else muted()))
    if stats.poll_ms is None:
        grid.add_row("sockets", Text("starting…", style=muted()))
    else:
        interval = stats.poll_interval_ms or 0.0
        late = interval > 0 and stats.poll_ms > interval
        poll = Text(f"{stats.poll_ms:.0f} ms", style=bad() if late else good())
        poll.append(f" / {interval:.0f} ms · {stats.sockets} open", style=muted())
        grid.add_row("sockets", poll)
    if not stats.pktap:
        grid.add_row("pktap", Text("off · --udp-flows", style=muted()))
    else:
        pktap = Text("● capturing", style=good())
        pktap.append(f" {stats.pktap_packets_per_s:.0f} pkt/s", style=strong())
        if stats.pktap_restarts:
            pktap.append(f" · {stats.pktap_restarts} restarts", style=warn())
        grid.add_row("pktap", pktap)
    if stats.dns_entries is None:
        grid.add_row("names", Text("off · --no-dns", style=muted()))
    else:
        grid.add_row("names", Text(f"{stats.dns_entries} cached", style=muted()))
    if pf is not None and pf.checked is not None:
        grid.add_row("checked", Text(f"pf at {clock(pf.checked)[:8]}", style=muted()))
    return grid


def render_inspector(
    selection: Selection | None, signature: str | None, blocked: bool, suspended: bool
) -> RenderableType:
    """Who (process, bundle, signature), where to (address, socket), and why (sensors)."""
    if selection is None:
        return Group(
            Text("Nothing selected.", style=strong()),
            Text("Select an alert or a connection to see who it is and where it goes.", muted()),
        )
    conn, alert = selection.connection, selection.alert
    parts: list[RenderableType] = []
    if alert is not None:
        parts.append(
            Text.assemble(
                severity_badge(alert.severity),
                (f"  alert #{alert.id}", strong()),
                (f" · {alert.finding.delta_s * 1000:.0f} ms after the sensor", muted()),
            )
        )
        parts.append(Text(""))
    who = _grid()
    who.add_row("process", Text.assemble((conn.process_name, strong()), "  pid ", str(conn.pid)))
    who.add_row("bundle", conn.bundle_id or Text("—", style=muted()))
    who.add_row("path", conn.exe_path or Text("—", style=muted()))
    if conn.exe_path:
        who.add_row("signed", Text(signature or "checking…", style="" if signature else muted()))
    parts.append(who)
    parts.append(Text(""))
    where = _grid()
    destination = Text(conn.remote, style=strong())
    if conn.hostname:
        destination.append(f"  {conn.hostname}", style=muted())
    where.add_row("remote", destination)
    where.add_row("socket", f"{conn.protocol.value} {conn.status} · seen {clock(conn.first_seen)}")
    if blocked or suspended:
        where.add_row("state", mitigation_badges(blocked, suspended))
    sensors = alert.sensors if alert is not None else {e.sensor for e in selection.events}
    where.add_row("sensors", sensor_pills(sensors) if sensors else Text("none", style=muted()))
    parts.append(where)
    if selection.events:
        recent = Table.grid(padding=(0, 1))
        recent.add_column(style=muted(), no_wrap=True)
        recent.add_column(no_wrap=True)
        recent.add_column(overflow="ellipsis", no_wrap=True)
        for event in selection.events[-6:]:
            recent.add_row(
                clock(event.timestamp)[-9:],
                sensor_pills([event.sensor]),
                Text(f"{event_source(event)} {event.service or ''}", style=muted()),
            )
        parts += [Text(""), Text("recent sensor events", style=muted()), recent]
    return Group(*parts)


def render_status(stats: RuntimeStats) -> Text:
    """One-line summary: liveness, CPU, pktap rates, DNS cache, event rate and alert count."""
    sep = ("   ", "")
    live = Text("● LIVE", style=good()) if stats.live else Text("■ STOPPED", style=bad())
    cpu = "—" if stats.cpu_percent is None else f"{stats.cpu_percent:.1f}%"
    parts: list[Text | tuple[str, str] | str] = [live, sep, ("CPU ", muted()), cpu]
    if stats.pktap:
        parts += [
            sep,
            ("UDP ", muted()),
            f"{stats.pktap_packets_per_s:.0f} pkt/s · {stats.pktap_flows_per_s:.1f} flows/s",
        ]
    if stats.dns_entries is not None:
        parts += [sep, ("DNS ", muted()), f"{stats.dns_entries}"]
    parts += [sep, ("events ", muted()), f"{stats.events_per_s:.1f}/s"]
    parts += [sep, ("alerts ", muted()), Text(str(stats.alerts), style=strong())]
    return Text.assemble(*parts)


class PostureBar(Static):
    """Top bar: the verdict in words, and the clock."""

    # Below this width the right-hand side keeps only the profile, blocks and clock.
    COMPACT_WIDTH = 130

    def show(self, posture: Posture, now: str) -> None:
        """Redraw from the latest posture, compact on a narrow terminal."""
        compact = 0 < self.size.width < self.COMPACT_WIDTH
        self.update(render_posture(posture, now, compact))


class ModePanel(Static):
    """Side card above the panic button: Paranoia Mode's state and what it lets through."""

    def show(self, mode: ModeStatus) -> None:
        """Redraw from the lockdown controller's latest state."""
        self.update(render_mode(mode))


class FirewallPanel(Static):
    """Side panel: pf, block table, socket poller and pktap at a glance."""

    def show(self, pf: PfStatus | None, stats: RuntimeStats) -> None:
        """Redraw from the latest pf poll and runtime counters."""
        self.update(render_firewall(pf, stats))


class InspectorPanel(Static):
    """Side panel: details of the selected alert or connection."""

    def show(
        self, selection: Selection | None, signature: str | None, blocked: bool, suspended: bool
    ) -> None:
        """Redraw for `selection`, its code signature and mitigation state."""
        self.update(render_inspector(selection, signature, blocked, suspended))


class StatusBar(Static):
    """One-line bar above the key footer."""

    def show(self, stats: RuntimeStats) -> None:
        """Redraw from the latest runtime counters."""
        self.update(render_status(stats))
