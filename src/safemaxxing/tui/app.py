"""Textual dashboard: live correlation feed, pf and pktap status, inspector and timeline.

Layout (`safemaxxing.tcss`):

    ┌ LIVE FEED (alerts, `/` filter) ─────────┐┌ FIREWALL ───────────────┐
    │                                         ││ pf, anchor, block table │
    │                                         ││ poller, pktap, DNS      │
    ├ Sensor events │ Active egress ──────────┤├ INSPECTOR ──────────────┤
    │                                         ││ selected process        │
    └─────────────────────────────────────────┘└─────────────────────────┘
    status bar · key footer

The app only consumes `Supervisor.stream()` and reads counters the core already keeps; the
sensor log is written in batches, so a busy `--udp-flows` capture never floods the screen.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import time
from collections import deque
from collections.abc import Awaitable, Callable
from typing import ClassVar

import psutil
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult, ScreenStackError
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.events import DescendantFocus
from textual.timer import Timer
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    RichLog,
    TabbedContent,
    TabPane,
)

from safemaxxing.codesign import signing_identity
from safemaxxing.firewall import BlockList, PfFirewall, ProcessController, is_root
from safemaxxing.lockdown.controller import LockdownController, LockdownNotice, LockdownState
from safemaxxing.lockdown.leases import LeaseSource
from safemaxxing.models import (
    PKTAP_STATUS,
    ActionResult,
    Alert,
    Event,
    NetworkConnection,
    Severity,
)
from safemaxxing.network import bundle_id_for_exe
from safemaxxing.supervisor import Supervisor
from safemaxxing.tui.badges import (
    MUTED,
    SEVERITY_INK,
    clock,
    mitigation_badges,
    sensor_pills,
    severity_badge,
)
from safemaxxing.tui.panels import (
    FirewallPanel,
    InspectorPanel,
    PfStatus,
    RuntimeStats,
    Selection,
    StatusBar,
)
from safemaxxing.tui.screens import ConfirmScreen, TimelineScreen
from safemaxxing.tui.timeline import merge_events, related_events, timeline_steps

# Oldest alerts are dropped past this, so a long session keeps a bounded feed.
MAX_FEED = 1000
# The egress table shows the newest sockets only: pktap can track thousands of flows.
MAX_EGRESS_ROWS = 300
PF_POLL_S = 5.0
LOG_FLUSH_S = 0.1
# Sensor lines waiting for the next flush; older ones are dropped and counted.
MAX_PENDING_LINES = 500

FEED_COLUMNS = (
    ("id", "#"),
    ("time", "time"),
    ("sev", "severity"),
    ("sensors", "sensors"),
    ("actor", "app · pid"),
    ("dest", "destination"),
    ("delta", "Δ ms"),
    ("state", "state"),
)
# Feed cells are cut to these widths so the table fits beside the side panels at ~170 columns;
# the inspector shows the full values.
ACTOR_WIDTH = 26
DEST_WIDTH = 32
EGRESS_COLUMNS = (
    ("pid", "pid"),
    ("process", "process"),
    ("proto", "proto"),
    ("dest", "destination"),
    ("host", "host"),
    ("source", "source"),
    ("state", "state"),
)

type Signer = Callable[[str], Awaitable[str]]


def _normal_ip(raw: str) -> str:
    """`raw` in pfctl's spelling, so a socket's address and a block-table entry compare."""
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return raw


def _conn_key(conn: NetworkConnection) -> str:
    return "|".join(map(str, conn.key))


class CpuMeter:
    """CPU use of this process and its children (tcpdump under `--udp-flows`), in % of a core.

    psutil measures between two calls on the same `Process`, so the objects are kept.
    """

    def __init__(self) -> None:
        self._me = psutil.Process()
        self._known: dict[int, psutil.Process] = {}

    def sample(self) -> float | None:
        """Percent since the previous call; None if the process table cannot be read."""
        try:
            procs = [self._me, *self._me.children(recursive=True)]
        except psutil.Error:
            return None
        total = 0.0
        alive: dict[int, psutil.Process] = {}
        for proc in procs:
            known = self._known.get(proc.pid, proc)
            try:
                total += known.cpu_percent(None)
            except psutil.Error:
                continue
            alive[proc.pid] = known
        self._known = alive
        return total


class SafemaxxingApp(App[None]):
    """SOC-style dashboard fed by a `Supervisor`.

    Block, unblock, suspend, resume, kill and the timeline act on the selection the inspector
    shows: the highlighted row of the feed, or of the egress table while it has focus. Kill
    asks for confirmation first.
    """

    TITLE = "safemaxxing"
    SUB_TITLE = "sensor → egress correlation"
    CSS_PATH = "safemaxxing.tcss"
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("b", "block", "Block IP"),
        Binding("u", "unblock", "Unblock"),
        Binding("s", "suspend", "SIGSTOP"),
        Binding("r", "resume", "SIGCONT"),
        Binding("k", "kill", "SIGKILL"),
        Binding("space", "timeline", "Timeline"),
        Binding("slash", "filter", "Filter", key_display="/"),
        Binding("escape", "clear_filter", "Clear filter", show=False),
        Binding("c", "clear_feed", "Clear feed"),
        # Not a priority binding: typed into the filter box, P is just a letter.
        Binding("P", "panic", "PANIC", key_display="P"),
        Binding("g", "lease", "Grant app"),
        Binding("q", "quit", "Quit"),
    ]
    PANIC_OFF = "◉ PANIC · LOCKDOWN"
    PANIC_ON = "■ LOCKDOWN ON · press to leave"
    BLINK_S = 0.5

    def __init__(
        self,
        supervisor: Supervisor,
        firewall: PfFirewall | None = None,
        processes: ProcessController | None = None,
        signer: Signer = signing_identity,
        root: Callable[[], bool] = is_root,
        lockdown: LockdownController | None = None,
    ) -> None:
        super().__init__()
        self.supervisor = supervisor
        self.firewall = firewall or PfFirewall(store=BlockList())
        self.processes = processes or ProcessController()
        # Built by the CLI only when root; None leaves the panic button explaining why.
        self.lockdown = lockdown
        if lockdown is not None:
            lockdown.notify = self.show_notice
        self._blink_timer: Timer | None = None
        self._signer = signer
        self._root = root
        self.alerts: dict[str, Alert] = {}
        self._alert_events: dict[str, tuple[Event, ...]] = {}
        self._connections: dict[str, NetworkConnection] = {}
        self._row_state: dict[str, tuple[str, bool, bool]] = {}
        self.selection: Selection | None = None
        self._signatures: dict[str, str] = {}
        self.blocked: set[str] = set()
        self.suspended: set[int] = set()
        self.pf_status: PfStatus | None = None
        self.filter_text = ""
        self._pending: deque[Text] = deque(maxlen=MAX_PENDING_LINES)
        self._pending_total = 0
        self._events_seen = 0
        self._flows_seen = 0
        self._live = True
        self._cpu = CpuMeter()
        self._last_sample = (time.monotonic(), 0, 0, 0)
        self.stats = RuntimeStats()

    # Layout

    def compose(self) -> ComposeResult:
        """Feed and detail tabs on the left, firewall and inspector panels on the right."""
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="main"):
                with Vertical(id="feed-pane", classes="pane"):
                    yield Input(placeholder="filter: process, bundle id, IP or host", id="filter")
                    yield DataTable(id="feed", cursor_type="row")
                with TabbedContent(id="detail-tabs"):
                    with TabPane("Sensor events", id="tab-events"):
                        yield RichLog(
                            id="events", markup=False, highlight=False, wrap=True, max_lines=2000
                        )
                    with TabPane("Active egress", id="tab-egress"):
                        yield DataTable(id="connections", cursor_type="row")
            with Vertical(id="side"):
                yield Button(self.PANIC_OFF, id="panic", variant="error")
                yield FirewallPanel(id="firewall", classes="pane")
                yield InspectorPanel(id="inspector", classes="pane")
        yield StatusBar(id="status")
        yield Footer()

    def on_mount(self) -> None:
        """Set up columns and titles, start the timers and the supervisor consumer."""
        feed = self.query_one("#feed", DataTable)
        for key, label in FEED_COLUMNS:
            feed.add_column(label, key=key)
        connections = self.query_one("#connections", DataTable)
        for key, label in EGRESS_COLUMNS:
            connections.add_column(label, key=key)
        self.query_one("#feed-pane").border_title = "LIVE FEED"
        self.query_one("#firewall").border_title = "FIREWALL · PF"
        self.query_one("#inspector").border_title = "INSPECTOR"
        self._update_feed_subtitle()
        self.set_interval(1.0, self.tick)
        self.set_interval(LOG_FLUSH_S, self.flush_log)
        self.set_interval(PF_POLL_S, self.poll_firewall)
        self.poll_firewall()
        self.tick()
        self.consume()
        feed.focus()

    # Supervisor stream

    @work(exclusive=True, group="supervisor")
    async def consume(self) -> None:
        """Feed supervisor alerts and events into the UI; on failure log it and notify."""
        try:
            async for update in self.supervisor.stream():
                if isinstance(update, Alert):
                    self.add_alert(update)
                elif isinstance(update, Event):
                    self._events_seen += 1
                    self.log_event(update)
                elif isinstance(update, NetworkConnection):
                    if update.status == PKTAP_STATUS:
                        self._flows_seen += 1
                    if self.lockdown is not None:
                        self.lockdown.audit_flow(update)
        except Exception as exc:
            self.log_line(Text(f"supervisor stopped: {exc}", style="bold #e06c75"))
            self.notify(f"Supervisor stopped: {exc}", severity="error", timeout=10)
        finally:
            self._live = False

    def log_line(self, text: Text) -> None:
        """Queue a line for the sensor event log; it is written on the next flush."""
        self._pending.append(text)
        self._pending_total += 1

    def flush_log(self) -> None:
        """Write the queued lines in one go, noting how many were dropped since the last flush."""
        if not self._pending_total or not self.is_running:
            return
        log = self.query_one("#events", RichLog)
        dropped = self._pending_total - len(self._pending)
        if dropped:
            log.write(Text(f"… {dropped} lines dropped (log flood)", style=MUTED))
        while self._pending:
            log.write(self._pending.popleft())
        self._pending_total = 0

    def log_event(self, event: Event) -> None:
        """Log a sensor event, skipping system events unless `include_system` is configured."""
        if event.system and not self.supervisor.engine.config.include_system:
            return
        line = Text.assemble(
            (clock(event.timestamp), MUTED),
            " ",
            sensor_pills([event.sensor]),
            f" {event.identity}",
            (f" pid={event.pid}" if event.pid is not None else "", MUTED),
            (f" {event.service}" if event.service else "", "#c678dd"),
        )
        self.log_line(line)

    # Feed

    def _hostname(self, conn: NetworkConnection) -> str | None:
        if conn.hostname:
            return conn.hostname
        resolver = self.supervisor.resolver
        return resolver.cached(conn.remote_address) if resolver is not None else None

    def _named(self, conn: NetworkConnection) -> NetworkConnection:
        host = self._hostname(conn)
        return dataclasses.replace(conn, hostname=host) if host != conn.hostname else conn

    def _mitigated(self, conn: NetworkConnection) -> tuple[bool, bool]:
        return _normal_ip(conn.remote_address) in self.blocked, conn.pid in self.suspended

    def _destination(self, conn: NetworkConnection) -> Text:
        text = Text(conn.remote)
        if host := self._hostname(conn):
            text.append(f" {host}", style=MUTED)
        text.truncate(DEST_WIDTH, overflow="ellipsis")
        return text

    def _feed_row(self, alert: Alert) -> tuple[str | Text, ...]:
        ev, conn = alert.finding.event, alert.finding.connection
        actor = Text.assemble((ev.identity, "bold"), (f" {conn.pid}", MUTED))
        actor.truncate(ACTOR_WIDTH, overflow="ellipsis")
        return (
            str(alert.id),
            Text(clock(ev.timestamp)[:8], style=MUTED),
            severity_badge(alert.severity),
            sensor_pills(alert.sensors or {ev.sensor}),
            actor,
            self._destination(conn),
            f"{alert.finding.delta_s * 1000:.0f}",
            mitigation_badges(*self._mitigated(conn), compact=True),
        )

    def _matches(self, *fields: str | int | None) -> bool:
        needle = self.filter_text
        return not needle or any(needle in str(f).lower() for f in fields if f is not None)

    def _alert_matches(self, alert: Alert) -> bool:
        ev, conn = alert.finding.event, alert.finding.connection
        return self._matches(
            ev.identity,
            ev.process_name,
            conn.process_name,
            conn.bundle_id,
            conn.pid,
            conn.remote_address,
            self._hostname(conn),
        )

    def _conn_matches(self, conn: NetworkConnection) -> bool:
        return self._matches(
            conn.process_name, conn.bundle_id, conn.pid, conn.remote_address, self._hostname(conn)
        )

    def add_alert(self, alert: Alert) -> None:
        """Add the alert to the feed, or update its row in place when it is re-emitted.

        Rings the bell and notifies only for HIGH or above, and only for a new alert or an
        escalation in severity. The actor's sensor events are snapshotted now for the
        timeline, while the engine still holds them.
        """
        key = str(alert.id)
        conn = alert.finding.connection
        previous = self.alerts.get(key)
        self.alerts[key] = alert
        config = self.supervisor.engine.config
        snapshot = (
            *related_events(conn, self.supervisor.engine.events, config),
            alert.finding.event,
        )
        self._alert_events[key] = merge_events(self._alert_events.get(key, ()), snapshot)
        table = self.query_one("#feed", DataTable)
        if self._alert_matches(alert):
            if key in table.rows:
                for (column, _), value in zip(FEED_COLUMNS, self._feed_row(alert), strict=True):
                    table.update_cell(key, column, value, update_width=True)
            else:
                follow = table.row_count == 0 or table.cursor_row >= table.row_count - 1
                table.add_row(*self._feed_row(alert), key=key)
                if follow:
                    table.move_cursor(row=table.row_count - 1)
        self._trim_feed()
        verb = " updated" if previous is not None else ""
        ink = SEVERITY_INK[alert.severity]
        line = Text.assemble(severity_badge(alert.severity), (f" ALERT #{key}{verb}: ", ink))
        self.log_line(line.append(alert.summary, style=ink))
        selected = self.selection.alert if self.selection is not None else None
        if selected is not None and selected.id == alert.id:
            self.selection = Selection(conn, alert, self._alert_events[key])
            self._show_inspector()
        self._update_feed_subtitle()
        escalated = previous is None or alert.severity > previous.severity
        if alert.severity >= Severity.HIGH and escalated:
            self.bell()
            self.notify(alert.summary, title="Exfiltration pattern", severity="warning")

    def _trim_feed(self) -> None:
        table = self.query_one("#feed", DataTable)
        while len(self.alerts) > MAX_FEED:
            oldest = next(iter(self.alerts))
            del self.alerts[oldest]
            self._alert_events.pop(oldest, None)
            self._row_state.pop(oldest, None)
            if oldest in table.rows:
                table.remove_row(oldest)

    def _rebuild_feed(self) -> None:
        """Refill the feed from the held alerts under the current filter, keeping the cursor."""
        table = self.query_one("#feed", DataTable)
        selected = self.selection.alert if self.selection is not None else None
        table.clear()
        self._row_state.clear()
        for key, alert in self.alerts.items():
            if self._alert_matches(alert):
                table.add_row(*self._feed_row(alert), key=key)
        if selected is not None and str(selected.id) in table.rows:
            table.move_cursor(row=table.get_row_index(str(selected.id)))
        self._update_feed_subtitle()

    def _refresh_feed_rows(self) -> None:
        """Update destination and mitigation cells whose hostname or state changed."""
        table = self.query_one("#feed", DataTable)
        for key, alert in self.alerts.items():
            if key not in table.rows:
                continue
            conn = alert.finding.connection
            state = (self._hostname(conn) or "", *self._mitigated(conn))
            if self._row_state.get(key) == state:
                continue
            self._row_state[key] = state
            table.update_cell(key, "dest", self._destination(conn), update_width=True)
            badges = mitigation_badges(state[1], state[2], compact=True)
            table.update_cell(key, "state", badges, update_width=True)

    def _update_feed_subtitle(self) -> None:
        shown = self.query_one("#feed", DataTable).row_count
        pane = self.query_one("#feed-pane")
        if self.filter_text:
            pane.border_subtitle = f"filter “{self.filter_text}” · {shown}/{len(self.alerts)}"
        else:
            pane.border_subtitle = f"{len(self.alerts)} alerts"

    # Egress table

    def refresh_connections(self) -> None:
        """Rebuild the egress table (newest first, filtered), keeping the cursor on its row."""
        table = self.query_one("#connections", DataTable)
        current = None
        if table.row_count:
            current = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        active = sorted(self.supervisor.active_connections(), key=lambda c: -c.first_seen)
        table.clear()
        self._connections.clear()
        for conn in active:
            if len(self._connections) >= MAX_EGRESS_ROWS:
                break
            if not self._conn_matches(conn):
                continue
            key = _conn_key(conn)
            self._connections[key] = conn
            table.add_row(
                str(conn.pid),
                conn.process_name,
                conn.protocol.value,
                conn.remote,
                Text(self._hostname(conn) or "", style=MUTED),
                Text("pktap" if conn.status == PKTAP_STATUS else conn.status, style=MUTED),
                mitigation_badges(*self._mitigated(conn), compact=True),
                key=key,
            )
        if current is not None and current in table.rows:
            table.move_cursor(row=table.get_row_index(current))

    # Periodic refresh

    def _sample_stats(self) -> RuntimeStats:
        now = time.monotonic()
        pktap = self.supervisor.pktap
        packets = pktap.packets if pktap is not None else 0
        last_t, last_packets, last_flows, last_events = self._last_sample
        elapsed = max(now - last_t, 1e-6)
        self._last_sample = (now, packets, self._flows_seen, self._events_seen)
        monitor = self.supervisor.monitor
        resolver = self.supervisor.resolver
        last_poll = monitor.last_poll_s if monitor is not None else None
        return RuntimeStats(
            cpu_percent=self._cpu.sample(),
            poll_ms=None if last_poll is None else last_poll * 1000,
            poll_interval_ms=monitor.interval_s * 1000 if monitor is not None else None,
            sockets=len(monitor.active) if monitor is not None else 0,
            pktap=pktap is not None,
            pktap_packets_per_s=(packets - last_packets) / elapsed,
            pktap_flows_per_s=(self._flows_seen - last_flows) / elapsed,
            pktap_restarts=pktap.restarts if pktap is not None else 0,
            pktap_unparsed=pktap.unparsed if pktap is not None else 0,
            dns_entries=len(resolver) if resolver is not None else None,
            events_per_s=(self._events_seen - last_events) / elapsed,
            alerts=len(self.alerts),
            live=self._live,
        )

    def tick(self) -> None:
        """Once a second: egress table, feed cells, counters, panels and status bar."""
        # Textual stops app timers only after removing the screens: a late tick finds no widgets.
        if not self.is_running:
            return
        self.refresh_connections()
        self._refresh_feed_rows()
        if self.lockdown is not None:
            self.sub_title = self.lockdown.summary()
            # The watchdog may have taken pf back on its own: drop the red theme with it.
            if self.lockdown.state is LockdownState.OFF and self._blink_timer is not None:
                self._set_lockdown_theme(False)
        self.stats = self._sample_stats()
        self.query_one(FirewallPanel).show(self.pf_status, self.stats)
        self.query_one(StatusBar).show(self.stats)
        self._show_inspector()

    @work(exclusive=True, group="pf")
    async def poll_firewall(self) -> None:
        """Read pf's state, our anchor and the block table; without root, say so instead."""
        if not self._root():
            self.pf_status = PfStatus(None, None, error="needs root (run with sudo)")
        else:
            try:
                enabled = await self.firewall.is_enabled()
                loaded = await self.firewall.anchor_loaded()
                blocked = tuple(await self.firewall.blocked())
            except OSError as exc:
                self.pf_status = PfStatus(None, None, error=f"pfctl failed: {exc}")
            else:
                self.pf_status = PfStatus(enabled, loaded, blocked)
                self.blocked = {_normal_ip(ip) for ip in blocked}
        # pfctl can outlast the app: it may have shut down while we awaited.
        if not self.is_running:
            return
        self.query_one(FirewallPanel).show(self.pf_status, self.stats)
        self._refresh_feed_rows()

    # Selection and inspector

    def _select_from(self, table: DataTable[object]) -> None:
        if not table.row_count:
            return
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value or ""
        if table.id == "feed":
            alert = self.alerts.get(key)
            if alert is None:
                return
            events = self._alert_events.get(key, ())
            self.selection = Selection(alert.finding.connection, alert, events)
        else:
            conn = self._connections.get(key)
            if conn is None:
                return
            engine = self.supervisor.engine
            events = related_events(conn, engine.events, engine.config)
            self.selection = Selection(conn, None, events)
        self._show_inspector()
        self._check_signature(self.selection.connection)

    @on(DataTable.RowHighlighted)
    def _row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.has_focus:
            self._select_from(event.data_table)

    @on(DescendantFocus)
    def _focus_changed(self, event: DescendantFocus) -> None:
        if isinstance(event.widget, DataTable):
            self._select_from(event.widget)

    @on(DataTable.RowSelected)
    def _row_selected(self, event: DataTable.RowSelected) -> None:
        self._select_from(event.data_table)
        self.action_timeline()

    def _show_inspector(self) -> None:
        # Focus moves while Textual tears the screen down, and the DescendantFocus that follows
        # (or a late signature lookup) finds no inspector (macos-15-intel, 2026-10-30).
        try:
            panel = self.query_one(InspectorPanel)
        except (NoMatches, ScreenStackError):
            return
        selection = self.selection
        if selection is None:
            panel.show(None, None, False, False)
            return
        conn = self._named(selection.connection)
        named = dataclasses.replace(selection, connection=conn)
        signature = self._signatures.get(conn.exe_path) if conn.exe_path else None
        panel.show(named, signature, *self._mitigated(conn))

    def _check_signature(self, conn: NetworkConnection) -> None:
        if conn.exe_path and conn.exe_path not in self._signatures:
            self.lookup_signature(conn.exe_path)

    @work(group="codesign")
    async def lookup_signature(self, exe_path: str) -> None:
        """Read `exe_path`'s code signature once, then redraw the inspector."""
        self._signatures[exe_path] = await self._signer(exe_path)
        self._show_inspector()

    # Actions

    def report(self, result: ActionResult) -> None:
        """Log an action result and show it as a notification (error severity on failure)."""
        verdict = "ok" if result.ok else "FAILED"
        message = f"{result.kind.value} {result.target}: {verdict} {result.detail}".strip()
        self.log_line(Text(message, style="#98c379" if result.ok else "bold #e06c75"))
        self.notify(message, severity="information" if result.ok else "error")
        self._refresh_feed_rows()
        self.refresh_connections()
        self._show_inspector()

    def _require_selection(self) -> NetworkConnection | None:
        if self.selection is None:
            self.notify("Select an alert or connection first", severity="warning")
            return None
        return self.selection.connection

    async def action_block(self) -> None:
        """Block the selected connection's remote IP in pf."""
        if conn := self._require_selection():
            result = await self.firewall.block(conn.remote_address)
            if result.ok:
                self.blocked.add(_normal_ip(result.target))
            self.report(result)

    async def action_unblock(self) -> None:
        """Unblock the selected connection's remote IP in pf."""
        if conn := self._require_selection():
            result = await self.firewall.unblock(conn.remote_address)
            if result.ok:
                self.blocked.discard(_normal_ip(result.target))
            self.report(result)

    def action_suspend(self) -> None:
        """Send SIGSTOP to the selected connection's process."""
        if conn := self._require_selection():
            result = self.processes.suspend(conn.pid)
            if result.ok:
                self.suspended.add(conn.pid)
            self.report(result)

    def action_resume(self) -> None:
        """Send SIGCONT to the selected connection's process."""
        if conn := self._require_selection():
            result = self.processes.resume(conn.pid)
            if result.ok:
                self.suspended.discard(conn.pid)
            self.report(result)

    def action_kill(self) -> None:
        """Send SIGKILL to the selected connection's process, after a confirmation dialog."""
        conn = self._require_selection()
        if conn is None:
            return

        def on_answer(confirmed: bool | None) -> None:
            if not confirmed:
                return
            result = self.processes.kill(conn.pid)
            if result.ok:
                self.suspended.discard(conn.pid)
            self.report(result)

        self.push_screen(ConfirmScreen(f"Kill {conn.process_name} (pid {conn.pid})?"), on_answer)

    def action_timeline(self) -> None:
        """Open the millisecond timeline of the selection: sensor events, then the egress."""
        selection = self.selection
        if selection is None:
            self.notify("Select an alert or connection first", severity="warning")
            return
        conn = self._named(selection.connection)
        steps = timeline_steps(conn, selection.events)
        if selection.alert is not None:
            title = f"ALERT #{selection.alert.id} · TIMELINE"
        else:
            title = f"{conn.process_name} · TIMELINE"
        self.push_screen(TimelineScreen(title, steps, selection.alert))

    def action_filter(self) -> None:
        """Show the filter box and move the focus into it."""
        box = self.query_one("#filter", Input)
        box.add_class("-open")
        box.focus()

    @on(Input.Changed, "#filter")
    def _filter_changed(self, event: Input.Changed) -> None:
        self.filter_text = event.value.strip().lower()
        self._rebuild_feed()
        self.refresh_connections()

    @on(Input.Submitted, "#filter")
    def _filter_submitted(self) -> None:
        self.query_one("#filter", Input).remove_class("-open")
        self.query_one("#feed", DataTable).focus()

    def action_clear_filter(self) -> None:
        """Empty and hide the filter box, showing every alert again."""
        box = self.query_one("#filter", Input)
        box.value = ""
        box.remove_class("-open")
        self.query_one("#feed", DataTable).focus()

    # Paranoia Mode

    def show_notice(self, notice: LockdownNotice) -> None:
        """A lockdown notice in the event log; HIGH and above also as a toast."""
        ink = SEVERITY_INK[notice.severity]
        self.log_line(Text.assemble(severity_badge(notice.severity), (f" {notice.message}", ink)))
        if notice.severity >= Severity.HIGH:
            self.notify(notice.message, title="Paranoia Mode", severity="error", timeout=10)
        if notice.severity is Severity.CRITICAL:
            self.bell()

    def _set_lockdown_theme(self, on: bool) -> None:
        """Turn the whole dashboard red with blinking borders, or back to normal."""
        screen = self.screen_stack[0]
        screen.set_class(on, "-lockdown")
        if self._blink_timer is not None:
            self._blink_timer.stop()
            self._blink_timer = None
        screen.remove_class("-blink")
        if on:
            self._blink_timer = self.set_interval(self.BLINK_S, self._blink)
        self.query_one("#panic", Button).label = self.PANIC_ON if on else self.PANIC_OFF

    def _blink(self) -> None:
        self.screen_stack[0].toggle_class("-blink")

    @on(Button.Pressed, "#panic")
    async def _panic_pressed(self) -> None:
        await self.action_panic()

    async def action_panic(self) -> None:
        """Enter Paranoia Mode at once; leaving asks first (it reopens egress)."""
        lockdown = self.lockdown
        if lockdown is None:
            self.notify("Paranoia Mode needs root (run with sudo)", severity="error")
            return
        if lockdown.state is LockdownState.ARMING:
            self.notify("Paranoia Mode is arming…", severity="warning")
            return
        if lockdown.state is LockdownState.OFF:
            # The red is shown before pf is touched, so the press is felt at once.
            self._set_lockdown_theme(True)
            result = await lockdown.enter()
            if not result.ok:
                self._set_lockdown_theme(False)
            self.report(result)
            return

        def on_answer(confirmed: bool | None) -> None:
            if confirmed:
                self.leave_lockdown()

        self.push_screen(ConfirmScreen("Leave Paranoia Mode and reopen egress?"), on_answer)

    @work(exclusive=True, group="lockdown")
    async def leave_lockdown(self) -> None:
        """Leave Paranoia Mode and drop the red theme once pf is back to v0.2."""
        assert self.lockdown is not None
        result = await self.lockdown.leave()
        if result.ok:
            self._set_lockdown_theme(False)
        self.report(result)

    def action_lease(self) -> None:
        """Grant (or withdraw) the selected connection's app a manual lease."""
        conn = self._require_selection()
        if conn is None or self.lockdown is None:
            return
        bundle_id = conn.bundle_id or (bundle_id_for_exe(conn.exe_path) if conn.exe_path else None)
        if bundle_id is None:
            self.notify(f"{conn.process_name} is not inside an app bundle", severity="warning")
            return
        lease = self.lockdown.leases.get(bundle_id)
        if lease is not None and LeaseSource.MANUAL in lease.sources:
            self.lockdown.release_manual(bundle_id)
            self.notify(f"manual lease withdrawn: {bundle_id}")
        else:
            self.lockdown.grant_manual(bundle_id)
            self.notify(f"manual lease granted: {bundle_id}")

    def action_clear_feed(self) -> None:
        """Empty the feed and the alerts held by the UI; the event log and pf are untouched."""
        self.alerts.clear()
        self._alert_events.clear()
        self._row_state.clear()
        self.query_one("#feed", DataTable).clear()
        if self.selection is not None and self.selection.alert is not None:
            self.selection = None
            self._show_inspector()
        self._update_feed_subtitle()
