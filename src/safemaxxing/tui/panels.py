"""Panels and bars of the dashboard, each a Static fed with an immutable snapshot.

The app gathers the numbers (pf status, poller and pktap counters, lockdown state) and hands
them over; the `render_*` functions turn a snapshot into Rich renderables and are tested
without Textual.

The posture bar at the top answers the first question anyone has, in plain words: is anything
wrong right now? It never says more than the program can stand behind: safemaxxing watches and
can block, so a quiet screen reads "Watching", never "Safe".
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text
from textual.widgets import Static

from safemaxxing.lockdown.controller import LockdownState
from safemaxxing.models import Alert, Event, NetworkConnection, Severity
from safemaxxing.tui.badges import (
    SEVERITY_INK,
    clock,
    mitigation_badges,
    sensor_pills,
    severity_badge,
)
from safemaxxing.tui.palette import ACCENT, CAUTION, DANGER, MUTED, OK, STRONG
from safemaxxing.tui.timeline import event_source

GOOD = f"bold {OK}"
WARN = f"bold {CAUTION}"
BAD = f"bold {DANGER}"
LABEL = MUTED


@dataclass(frozen=True, slots=True)
class PfStatus:
    """What the last pf poll found; `enabled`/`anchor_loaded` are None when unknown."""

    enabled: bool | None
    anchor_loaded: bool | None
    blocked: tuple[str, ...] = ()
    error: str | None = None


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


@dataclass(frozen=True, slots=True)
class Posture:
    """Everything the posture bar needs: is the watch running, and does anything need you.

    `review` counts the alerts of HIGH severity or above whose address is not blocked and
    whose process is not paused; `contained` the alerts that are one or the other.
    `lockdown` is None when Paranoia Mode is unavailable (not root).
    """

    live: bool = True
    lockdown: LockdownState | None = None
    alerts: int = 0
    review: int = 0
    worst: Severity | None = None
    contained: int = 0
    enforce: bool = True


@dataclass(frozen=True, slots=True)
class ModeStatus:
    """Paranoia Mode as the side card shows it; `state` None means it needs root."""

    state: LockdownState | None
    leases: tuple[str, ...] = ()
    grants: int = 0
    denied: int = 0


def verdict(p: Posture) -> tuple[str, str, str]:
    """`(style, headline, detail)` for the posture bar, most urgent state first."""
    if not p.live:
        return BAD, "■ Stopped", "the supervisor exited: nothing is being watched"
    if p.lockdown is LockdownState.ON:
        return BAD, "■ Paranoia Mode", "egress denied except the apps you granted"
    if p.lockdown is LockdownState.ARMING:
        return WARN, "◆ Arming Paranoia Mode", "loading the default-deny rules"
    if p.lockdown is LockdownState.TRIPPED:
        return WARN, "▲ Paranoia Mode tripped", "the watchdog restored the normal rules"
    if p.review:
        noun = "alert" if p.review == 1 else "alerts"
        style = SEVERITY_INK[p.worst] if p.worst is not None else WARN
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
    return GOOD, "● Watching", " · ".join(parts)


def render_posture(p: Posture, now: str) -> RenderableType:
    """One line: the name, the verdict in words, and the wall clock on the right."""
    style, headline, detail = verdict(p)
    brand, quiet = f"bold {ACCENT}", MUTED
    if p.lockdown is LockdownState.ON and p.live:
        # The bar itself turns dark red (tcss): red ink on it would not read.
        brand, style, quiet = "bold #ffffff", "bold #ffffff", "#f3c6cd"
    left = Text.assemble(("safemaxxing", brand), "   ", (headline, style), ("  " + detail, quiet))
    grid = Table.grid(expand=True)
    grid.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
    grid.add_column(justify="right", no_wrap=True)
    grid.add_row(left, Text(now, style=quiet))
    return grid


def render_mode(mode: ModeStatus) -> RenderableType:
    """The Paranoia Mode card: its state and, while on, what it lets through."""
    if mode.state is None:
        return Group(
            Text("○ Unavailable", style=WARN),
            Text("Needs root: start the dashboard with sudo.", style=MUTED),
        )
    if mode.state is LockdownState.ON:
        grid = _grid()
        grid.add_row("leases", ", ".join(mode.leases) or Text("none", style=MUTED))
        grid.add_row("grants", str(mode.grants))
        grid.add_row("denied", str(mode.denied))
        return Group(Text("■ On · egress denied by default", style=BAD), grid)
    if mode.state is LockdownState.ARMING:
        return Group(
            Text("◆ Arming…", style=WARN),
            Text("Watchdog first, then the default-deny rules.", style=MUTED),
        )
    head = Text("○ Off", style=f"bold {STRONG}")
    if mode.state is LockdownState.TRIPPED:
        head = Text("▲ Tripped: back to normal rules", style=WARN)
    return Group(
        head,
        Text("Denies every connection except apps using a sensor or granted with g.", style=MUTED),
    )


def _grid() -> Table:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style=LABEL, no_wrap=True, min_width=8)
    grid.add_column(overflow="fold")
    return grid


def _flag(value: bool | None, yes: str, no: str, needed: bool) -> Text:
    """`yes` in green, or `no`: red only when something depends on it, else just grey."""
    if value is None:
        return Text("unknown", style=WARN)
    if value:
        return Text(yes, style=GOOD)
    return Text(no, style=BAD if needed else MUTED)


def render_firewall(pf: PfStatus | None, stats: RuntimeStats) -> RenderableType:
    """pf state, anchor, block-table size, socket poller and pktap capture, one per line."""
    grid = _grid()
    if pf is None:
        grid.add_row("pf", Text("checking…", style=MUTED))
    elif pf.error:
        grid.add_row("pf", Text(pf.error, style=WARN))
    else:
        # pf and the anchor come up with the first block: off with nothing blocked is normal.
        count = len(pf.blocked)
        state = _flag(pf.enabled, "● enabled", "○ disabled", needed=count > 0)
        anchor = _flag(pf.anchor_loaded, "● loaded", "○ not loaded", needed=count > 0)
        if count and (pf.enabled is False or pf.anchor_loaded is False):
            state.append(" · blocks not enforced", style=BAD)
        elif pf.anchor_loaded is False:
            anchor.append(" until a block", style=MUTED)
        grid.add_row("pf", state)
        grid.add_row("anchor", anchor)
        noun = "address" if count == 1 else "addresses"
        grid.add_row("blocked", Text(f"{count} {noun}", style=f"bold {STRONG}" if count else MUTED))
    if stats.poll_ms is None:
        grid.add_row("sockets", Text("starting…", style=MUTED))
    else:
        interval = stats.poll_interval_ms or 0.0
        late = interval > 0 and stats.poll_ms > interval
        poll = Text(f"{stats.poll_ms:.0f} ms", style=BAD if late else GOOD)
        poll.append(f" / {interval:.0f} ms · {stats.sockets} open", style=MUTED)
        grid.add_row("sockets", poll)
    if not stats.pktap:
        grid.add_row("pktap", Text("off · --udp-flows", style=MUTED))
    else:
        pktap = Text("● capturing", style=GOOD)
        pktap.append(f" {stats.pktap_packets_per_s:.0f} pkt/s", style=f"bold {STRONG}")
        if stats.pktap_restarts:
            pktap.append(f" · {stats.pktap_restarts} restarts", style=WARN)
        grid.add_row("pktap", pktap)
    if stats.dns_entries is None:
        grid.add_row("names", Text("off · --no-dns", style=MUTED))
    else:
        grid.add_row("names", Text(f"{stats.dns_entries} cached", style=MUTED))
    return grid


def render_inspector(
    selection: Selection | None, signature: str | None, blocked: bool, suspended: bool
) -> RenderableType:
    """Who (process, bundle, signature), where to (address, socket), and why (sensors)."""
    if selection is None:
        return Group(
            Text("Nothing selected.", style=f"bold {STRONG}"),
            Text("Select an alert or a connection to see who it is and where it goes.", MUTED),
        )
    conn, alert = selection.connection, selection.alert
    parts: list[RenderableType] = []
    if alert is not None:
        parts.append(
            Text.assemble(
                severity_badge(alert.severity),
                (f"  alert #{alert.id}", f"bold {STRONG}"),
                (f" · {alert.finding.delta_s * 1000:.0f} ms after the sensor", MUTED),
            )
        )
        parts.append(Text(""))
    who = _grid()
    who.add_row(
        "process", Text.assemble((conn.process_name, f"bold {STRONG}"), "  pid ", str(conn.pid))
    )
    who.add_row("bundle", conn.bundle_id or Text("—", style=MUTED))
    who.add_row("path", conn.exe_path or Text("—", style=MUTED))
    if conn.exe_path:
        who.add_row("signed", Text(signature or "checking…", style="" if signature else MUTED))
    parts.append(who)
    parts.append(Text(""))
    where = _grid()
    destination = Text(conn.remote, style=f"bold {STRONG}")
    if conn.hostname:
        destination.append(f"  {conn.hostname}", style=MUTED)
    where.add_row("remote", destination)
    where.add_row("socket", f"{conn.protocol.value} {conn.status} · seen {clock(conn.first_seen)}")
    if blocked or suspended:
        where.add_row("state", mitigation_badges(blocked, suspended))
    sensors = alert.sensors if alert is not None else {e.sensor for e in selection.events}
    where.add_row("sensors", sensor_pills(sensors) if sensors else Text("none", style=MUTED))
    parts.append(where)
    if selection.events:
        recent = Table.grid(padding=(0, 1))
        recent.add_column(style=MUTED, no_wrap=True)
        recent.add_column(no_wrap=True)
        recent.add_column(overflow="ellipsis", no_wrap=True)
        for event in selection.events[-6:]:
            recent.add_row(
                clock(event.timestamp)[-9:],
                sensor_pills([event.sensor]),
                Text(f"{event_source(event)} {event.service or ''}", style=MUTED),
            )
        parts += [Text(""), Text("recent sensor events", style=LABEL), recent]
    return Group(*parts)


def render_status(stats: RuntimeStats) -> Text:
    """One-line summary: liveness, CPU, pktap rates, DNS cache, event rate and alert count."""
    sep = ("   ", "")
    live = Text("● LIVE", style=GOOD) if stats.live else Text("■ STOPPED", style=BAD)
    cpu = "—" if stats.cpu_percent is None else f"{stats.cpu_percent:.1f}%"
    parts: list[Text | tuple[str, str] | str] = [live, sep, ("CPU ", LABEL), cpu]
    if stats.pktap:
        parts += [
            sep,
            ("UDP ", LABEL),
            f"{stats.pktap_packets_per_s:.0f} pkt/s · {stats.pktap_flows_per_s:.1f} flows/s",
        ]
    if stats.dns_entries is not None:
        parts += [sep, ("DNS ", LABEL), f"{stats.dns_entries}"]
    parts += [sep, ("events ", LABEL), f"{stats.events_per_s:.1f}/s"]
    parts += [sep, ("alerts ", LABEL), Text(str(stats.alerts), style=f"bold {STRONG}")]
    return Text.assemble(*parts)


class PostureBar(Static):
    """Top bar: the verdict in words, and the clock."""

    def show(self, posture: Posture, now: str) -> None:
        """Redraw from the latest posture."""
        self.update(render_posture(posture, now))


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
