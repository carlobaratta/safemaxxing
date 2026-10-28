"""Side panels and status bar of the dashboard, each a Static fed with an immutable snapshot.

The app gathers the numbers (pf status, poller and pktap counters) and hands them over; the
`render_*` functions turn a snapshot into Rich renderables and are tested without Textual.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text
from textual.widgets import Static

from safemaxxing.models import Alert, Event, NetworkConnection
from safemaxxing.tui.badges import (
    MUTED,
    clock,
    mitigation_badges,
    pill,
    sensor_pills,
    severity_badge,
)
from safemaxxing.tui.timeline import event_source

OK = "bold #98c379"
WARN = "bold #e5c07b"
BAD = "bold #e06c75"
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


def _grid() -> Table:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style=LABEL, no_wrap=True)
    grid.add_column(overflow="fold")
    return grid


def _flag(value: bool | None, yes: str, no: str) -> Text:
    if value is None:
        return Text("unknown", style=WARN)
    return Text(yes, style=OK) if value else Text(no, style=BAD)


def render_firewall(pf: PfStatus | None, stats: RuntimeStats) -> RenderableType:
    """pf state, anchor, block-table size, socket poller and pktap capture, one per line."""
    grid = _grid()
    if pf is None:
        grid.add_row("pf", Text("checking…", style=MUTED))
    elif pf.error:
        grid.add_row("pf", Text(pf.error, style=WARN))
    else:
        grid.add_row("pf", _flag(pf.enabled, "● ENABLED", "○ DISABLED"))
        grid.add_row("anchor", _flag(pf.anchor_loaded, "● ACTIVE", "○ INACTIVE"))
        count = len(pf.blocked)
        grid.add_row("blocked", Text(f"{count} IP" + ("" if count == 1 else "s"), style="bold"))
    if stats.poll_ms is None:
        grid.add_row("poller", Text("starting…", style=MUTED))
    else:
        interval = stats.poll_interval_ms or 0.0
        late = interval > 0 and stats.poll_ms > interval
        poll = Text(f"{stats.poll_ms:.0f} ms", style=BAD if late else OK)
        poll.append(f" / {interval:.0f} ms · {stats.sockets} sockets", style=MUTED)
        grid.add_row("poller", poll)
    if not stats.pktap:
        grid.add_row("pktap", Text("off (--udp-flows)", style=MUTED))
    else:
        pktap = Text("● CAPTURING", style=OK)
        pktap.append(f" {stats.pktap_packets_per_s:.0f} pkt/s", style="bold")
        if stats.pktap_restarts:
            pktap.append(f" · {stats.pktap_restarts} restarts", style=WARN)
        grid.add_row("pktap", pktap)
    dns = "off (--no-dns)" if stats.dns_entries is None else f"{stats.dns_entries} entries"
    grid.add_row("dns cache", dns)
    return grid


def render_inspector(
    selection: Selection | None, signature: str | None, blocked: bool, suspended: bool
) -> RenderableType:
    """Process identity, signature, destination and the sensors seen for the selection."""
    if selection is None:
        return Text("Select an alert or a connection.", style=MUTED)
    conn, alert = selection.connection, selection.alert
    grid = _grid()
    if alert is not None:
        head = Text.assemble(severity_badge(alert.severity), " ", (f"alert #{alert.id}", "bold"))
        grid.add_row("alert", head)
    grid.add_row("process", Text(conn.process_name, style="bold"))
    grid.add_row("pid", str(conn.pid))
    grid.add_row("bundle", conn.bundle_id or Text("—", style=MUTED))
    grid.add_row("path", conn.exe_path or Text("—", style=MUTED))
    if conn.exe_path:
        grid.add_row("signed", Text(signature or "checking…", style="" if signature else MUTED))
    destination = Text(conn.remote, style="bold")
    if conn.hostname:
        destination.append(f"  {conn.hostname}", style=MUTED)
    grid.add_row("remote", destination)
    grid.add_row("socket", f"{conn.protocol.value} {conn.status} · seen {clock(conn.first_seen)}")
    if blocked or suspended:
        grid.add_row("state", mitigation_badges(blocked, suspended))
    sensors = alert.sensors if alert is not None else {e.sensor for e in selection.events}
    grid.add_row("sensors", sensor_pills(sensors) if sensors else Text("none", style=MUTED))
    if alert is not None:
        grid.add_row("delay", f"{alert.finding.delta_s * 1000:.0f} ms after the sensor")
    if not selection.events:
        return grid
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
    return Group(grid, Text(""), Text("recent sensor events", style=LABEL), recent)


def render_status(stats: RuntimeStats) -> Text:
    """One-line summary: liveness, CPU, pktap rates, DNS cache, event rate and alert count."""
    sep = (" │ ", MUTED)
    live = pill("LIVE", "bold #0a0e14 on #98c379") if stats.live else pill("STOPPED", BAD)
    cpu = "—" if stats.cpu_percent is None else f"{stats.cpu_percent:.1f}%"
    parts: list[Text | tuple[str, str] | str] = [live, " ", ("CPU ", LABEL), cpu]
    if stats.pktap:
        parts += [
            sep,
            ("UDP ", LABEL),
            f"{stats.pktap_packets_per_s:.0f} pkt/s · {stats.pktap_flows_per_s:.1f} flows/s",
        ]
    if stats.dns_entries is not None:
        parts += [sep, ("DNS ", LABEL), f"{stats.dns_entries}"]
    parts += [sep, ("events ", LABEL), f"{stats.events_per_s:.1f}/s"]
    parts += [sep, ("alerts ", LABEL), Text(str(stats.alerts), style="bold")]
    return Text.assemble(*parts)


class FirewallPanel(Static):
    """Top side panel: pf, block table, socket poller and pktap at a glance."""

    def show(self, pf: PfStatus | None, stats: RuntimeStats) -> None:
        """Redraw from the latest pf poll and runtime counters."""
        self.update(render_firewall(pf, stats))


class InspectorPanel(Static):
    """Bottom side panel: details of the selected alert or connection."""

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
