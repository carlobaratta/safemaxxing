"""Textual dashboard: live correlation feed, pf and pktap status, inspector and timeline.

Layout (`safemaxxing.tcss`):

    safemaxxing  ● Watching  no exfiltration…   Normal · 2 blocked · daemon ● on · 10:57:46
    ┌ Alerts (`/` filter) ────────────────────┐┌ Paranoia Mode ──────────┐
    │ alerts, or a line saying there are none ││ state · [Enter … P]     │
    │                                         │├ Protection ─────────────┤
    │                                         ││ pf, anchor, blocks,     │
    ├ Sensor events │ Connections │ Blocked ──┤│ poller, pktap, names    │
    │                                         │├ Details ────────────────┤
    └─────────────────────────────────────────┘└ selected process ───────┘
    status bar · key footer (only the keys that apply to the selection)

The top line says in words whether anything needs you; severity colours appear only on
alerts, so a calm screen really is calm. Paranoia Mode turns the frame red and never blinks.
Below 110 columns the side panels move under the feed; T switches between the dark, high
contrast and light palettes, and ? lists every key.

The app only consumes `Supervisor.stream()` and reads counters the core already keeps; the
sensor log is written in batches, so a busy `--udp-flows` capture never floods the screen.
"""

from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import ClassVar

import psutil
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult, ScreenStackError
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.events import DescendantFocus
from textual.theme import Theme
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Input,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from safemaxxing.boot import LaunchdJob
from safemaxxing.codesign import signing_identity
from safemaxxing.daemon import WatchDaemon
from safemaxxing.firewall import (
    ANCHOR,
    TABLE,
    BlockList,
    PfFirewall,
    PfReference,
    ProcessController,
    is_root,
)
from safemaxxing.lockdown.controller import LockdownController, LockdownNotice, LockdownState
from safemaxxing.lockdown.leases import LeaseSource
from safemaxxing.models import (
    PKTAP_STATUS,
    ActionKind,
    ActionResult,
    Alert,
    Event,
    NetworkConnection,
    Severity,
)
from safemaxxing.network import bundle_id_for_exe
from safemaxxing.report import ISSUES_URL
from safemaxxing.supervisor import Supervisor
from safemaxxing.tui import palette
from safemaxxing.tui.badges import (
    SENSOR_CODE,
    clock,
    mitigation_badges,
    sensor_pills,
    severity_badge,
    severity_ink,
)
from safemaxxing.tui.palette import DARK, PALETTES, Palette
from safemaxxing.tui.panels import (
    DaemonState,
    FirewallPanel,
    InspectorPanel,
    ModePanel,
    ModeStatus,
    PfStatus,
    Posture,
    PostureBar,
    RuntimeStats,
    Selection,
    StatusBar,
    stop_hint,
)
from safemaxxing.tui.screens import ConfirmScreen, CopyScreen, HelpScreen, TimelineScreen
from safemaxxing.tui.timeline import merge_events, related_events, timeline_steps


def theme_name(palette_name: str) -> str:
    """The Textual theme registered for palette `palette_name`."""
    return f"safemaxxing-{palette_name}"


def css_variables(p: Palette) -> dict[str, str]:
    """The `$sm-*` variables `safemaxxing.tcss` reads, from palette `p`."""
    return {
        "sm-bg": p.bg,
        "sm-surface": p.surface,
        "sm-raised": p.raised,
        "sm-line": p.line,
        "sm-text": p.text,
        "sm-strong": p.strong,
        "sm-muted": p.muted,
        "sm-accent": p.accent,
        "sm-danger": p.danger,
        "sm-hover": p.hover,
        "sm-panic-hover": p.panic_hover,
        "sm-lockdown-bg": p.lockdown_bg,
        "sm-lockdown-bar": p.lockdown_bar,
        "sm-panic-fill": p.panic_fill,
        "sm-panic-fill-hover": p.panic_fill_hover,
        "sm-panic-ink": p.panic_ink,
    }


def theme_for(p: Palette) -> Theme:
    """Textual's own widgets (footer, tabs, toasts, row cursor, inputs) in palette `p`."""
    return Theme(
        name=theme_name(p.name),
        primary=p.accent,
        secondary=p.accent,
        accent=p.accent,
        foreground=p.text,
        background=p.bg,
        surface=p.surface,
        panel=p.raised,
        success=p.ok,
        warning=p.caution,
        error=p.danger,
        dark=p.dark,
        variables={
            "footer-background": p.bg,
            "footer-foreground": p.muted,
            "footer-description-foreground": p.text,
            "footer-item-background": "transparent",
            "footer-key-foreground": p.accent,
            "footer-key-background": "transparent",
            "block-cursor-background": p.cursor,
            "block-cursor-foreground": p.strong,
            # High contrast marks the cursor row by weight too, not by colour alone.
            "block-cursor-text-style": "bold" if p.name == "high-contrast" else "none",
            "block-cursor-blurred-background": p.cursor_blurred,
            "block-cursor-blurred-foreground": p.text,
            "button-focus-text-style": "bold reverse",
            "input-cursor-background": p.accent,
            "input-cursor-foreground": p.bg,
            "border": p.accent,
            "border-blurred": p.line,
            "scrollbar": p.line,
            "scrollbar-hover": p.scrollbar_hover,
            "scrollbar-active": p.accent,
            "scrollbar-background": p.surface,
            "scrollbar-background-hover": p.surface,
            "scrollbar-background-active": p.surface,
            "scrollbar-corner-color": p.surface,
            **css_variables(p),
        },
    )


THEMES: dict[str, Theme] = {name: theme_for(p) for name, p in PALETTES.items()}

# Oldest alerts are dropped past this, so a long session keeps a bounded feed.
MAX_FEED = 1000
# The egress table shows the newest sockets only: pktap can track thousands of flows.
MAX_EGRESS_ROWS = 300
PF_POLL_S = 5.0
DAEMON_POLL_S = 15.0
LOG_FLUSH_S = 0.1
# Sensor lines waiting for the next flush; older ones are dropped and counted.
MAX_PENDING_LINES = 500
# Lines kept to redraw the log under a new filter or palette (the RichLog keeps as many).
LOG_HISTORY = 2000
PBCOPY = "/usr/bin/pbcopy"

FEED_COLUMNS = (
    ("id", "#"),
    ("time", "time"),
    ("sev", "severity"),
    ("sensors", "sensors"),
    ("actor", "app · pid"),
    ("dest", "destination"),
    ("delta", "after"),
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
BLOCKED_COLUMNS = (("ip", "address"), ("host", "host"), ("alerts", "alerts"))
# Actions that need something selected; the footer hides the ones that would do nothing.
TARGET_ACTIONS = ("block", "unblock", "suspend", "resume", "kill", "timeline", "copy", "lease")
# Toast titles for a successful action.
DONE = {
    ActionKind.BLOCK_IP: "Blocked",
    ActionKind.UNBLOCK_IP: "Unblocked",
    ActionKind.SUSPEND: "Paused",
    ActionKind.RESUME: "Resumed",
    ActionKind.KILL: "Killed",
    ActionKind.LOCKDOWN_ON: "Paranoia Mode on",
    ActionKind.LOCKDOWN_OFF: "Paranoia Mode off",
}
MAX_PROFILE_DETAIL = (
    "The max profile verifies every app's code strictly (Brave's calls break), cuts the "
    "frontmost app off without a lease (g), revokes a grant on a blocked SNI and allows TCP 443 "
    "only to addresses DNS named. P again leaves it; the watchdog restores pf if this stops."
)
KEY_NAMES = {"slash": "/", "space": "space", "question_mark": "?", "escape": "esc"}

type Signer = Callable[[str], Awaitable[str]]
type Clipboard = Callable[[str], Awaitable[bool]]


@dataclass(frozen=True, slots=True)
class LogLine:
    """One line of the sensor log: how to draw it (in the palette of the moment) and the
    lower-case text the filter searches."""

    make: Callable[[], Text]
    haystack: str


def _normal_ip(raw: str) -> str:
    """`raw` in pfctl's spelling, so a socket's address and a block-table entry compare; an
    IPv4-mapped IPv6 address becomes the IPv4 address pf blocks."""
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def _ip_order(raw: str) -> tuple[int, int, str]:
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return (9, 0, raw)
    return (address.version, int(address), raw)


def _conn_key(conn: NetworkConnection) -> str:
    return "|".join(map(str, conn.key))


def pf_rule(ip: str) -> str:
    """A standalone pf rule with the effect safemaxxing's table entry for `ip` has."""
    return f"block drop out quick from any to {ip}"


def pf_command(ip: str) -> str:
    """The command that adds `ip` to safemaxxing's block table, as `block` does."""
    return f"sudo pfctl -a {ANCHOR} -t {TABLE} -T add {ip}"


async def pbcopy(text: str) -> bool:
    """Put `text` on the macOS pasteboard; False if pbcopy is missing, fails or hangs."""
    try:
        proc = await asyncio.create_subprocess_exec(
            PBCOPY,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        return False
    try:
        await asyncio.wait_for(proc.communicate(text.encode()), timeout=2)
    except TimeoutError:
        proc.kill()
        return False
    return proc.returncode == 0


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

    Block, unblock, suspend, resume, kill, copy and the timeline act on the selection the
    inspector shows: the highlighted row of the feed, or of the egress table while it has
    focus; on the Blocked tab, unblock and copy act on the highlighted address. Kill, pausing a
    macOS system process and entering Paranoia Mode's max profile ask for confirmation first.
    """

    TITLE = "safemaxxing"
    SUB_TITLE = "sensor → egress correlation"
    CSS_PATH = "safemaxxing.tcss"
    # The screen gets one of these classes by width; safemaxxing.tcss lays the panes out by it.
    HORIZONTAL_BREAKPOINTS = [
        (0, "-narrow"),
        (110, "-medium"),
        (150, "-wide"),
    ]
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("b", "block", "Block IP"),
        Binding("u", "unblock", "Unblock"),
        Binding("s", "suspend", "Pause app"),
        Binding("r", "resume", "Resume app"),
        Binding("k", "kill", "Kill"),
        Binding("space", "timeline", "Timeline"),
        Binding("y", "copy", "Copy"),
        # Early in the footer, so a narrow terminal still shows where every key is listed.
        Binding("question_mark", "help", "Help", key_display="?"),
        Binding("slash", "filter", "Filter", key_display="/"),
        Binding("escape", "clear_filter", "Clear filter", show=False),
        Binding("t", "top", "Top"),
        Binding("c", "clear_feed", "Clear feed"),
        # Not a priority binding: typed into the filter box, P is just a letter.
        Binding("P", "panic", "Paranoia", key_display="P"),
        Binding("g", "lease", "Grant app"),
        Binding("T", "cycle_theme", "Theme", key_display="T"),
        Binding("q", "quit", "Quit"),
    ]
    PANIC_OFF = "Enter Paranoia Mode · P"
    PANIC_ON = "Leave Paranoia Mode · P"

    def __init__(
        self,
        supervisor: Supervisor,
        firewall: PfFirewall | None = None,
        processes: ProcessController | None = None,
        signer: Signer = signing_identity,
        root: Callable[[], bool] = is_root,
        lockdown: LockdownController | None = None,
        theme: str = DARK.name,
        profile: str = "",
        clipboard: Clipboard = pbcopy,
        daemon: LaunchdJob | None = None,
    ) -> None:
        super().__init__()
        self.supervisor = supervisor
        self.firewall = firewall or PfFirewall(store=BlockList(), reference=PfReference())
        self.processes = processes or ProcessController()
        # Built by the CLI only when root; None leaves the panic button explaining why.
        self.lockdown = lockdown
        if lockdown is not None:
            lockdown.notify = self.show_notice
        self._signer = signer
        self._root = root
        self._palette_name = theme if theme in PALETTES else DARK.name
        self._profile = profile
        self._copier = clipboard
        self._daemon = daemon or WatchDaemon()
        self.daemon_state = DaemonState.UNKNOWN
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
        self._history: deque[LogLine] = deque(maxlen=LOG_HISTORY)
        self._pending: deque[LogLine] = deque(maxlen=MAX_PENDING_LINES)
        self._pending_total = 0
        self._log_dirty = False
        self._events_seen = 0
        self._flows_seen = 0
        self._live = True
        self._started = False
        self._stop_error: str | None = None
        self._last_event: float | None = None
        self._ui_ready = False
        self._bindings_state: tuple[bool | None, ...] = ()
        self._cpu = CpuMeter()
        self._last_sample = (time.monotonic(), 0, 0, 0)
        self.stats = RuntimeStats()

    def get_theme_variable_defaults(self) -> dict[str, str]:
        """The `$sm-*` variables before a theme is applied (the dark palette's)."""
        return css_variables(DARK)

    # Layout

    def compose(self) -> ComposeResult:
        """The verdict on top; feed and detail tabs on the left; mode, protection and details
        on the right."""
        yield PostureBar(id="posture")
        with Horizontal(id="body"):
            with Vertical(id="main"):
                with Vertical(id="feed-pane", classes="pane"):
                    yield Input(
                        placeholder="filter: app, bundle id, pid, IP, host or sensor (cam, mic)",
                        id="filter",
                    )
                    yield DataTable(id="feed", cursor_type="row")
                    yield Static(id="feed-empty")
                with TabbedContent(id="detail-tabs"):
                    with TabPane("Sensor events", id="tab-events"):
                        yield RichLog(
                            id="events",
                            markup=False,
                            highlight=False,
                            wrap=True,
                            max_lines=LOG_HISTORY,
                        )
                    with TabPane("Connections", id="tab-egress"):
                        yield DataTable(id="connections", cursor_type="row")
                    with TabPane("Blocked", id="tab-blocked"):
                        yield DataTable(id="blocked-table", cursor_type="row")
            with Vertical(id="side"):
                with Vertical(id="mode", classes="pane"):
                    yield ModePanel(id="mode-text")
                    yield Button(self.PANIC_OFF, id="panic", disabled=self.lockdown is None)
                yield FirewallPanel(id="firewall", classes="pane")
                yield InspectorPanel(id="inspector", classes="pane")
        yield StatusBar(id="status")
        yield Footer()

    def on_mount(self) -> None:
        """Set up themes, columns and titles, start the timers and the supervisor consumer."""
        for theme in THEMES.values():
            self.register_theme(theme)
        for table_id, columns in (
            ("#feed", FEED_COLUMNS),
            ("#connections", EGRESS_COLUMNS),
            ("#blocked-table", BLOCKED_COLUMNS),
        ):
            table = self.query_one(table_id, DataTable)
            for key, label in columns:
                table.add_column(label, key=key)
        self.query_one("#feed-pane").border_title = "Alerts"
        self.query_one("#mode").border_title = "Paranoia Mode"
        self.query_one("#firewall").border_title = "Protection"
        self.query_one("#inspector").border_title = "Details"
        self.theme = theme_name(self._palette_name)
        self._ui_ready = True
        self._update_feed_subtitle()
        self.log_line(
            lambda: Text("starting `log stream` and the socket poller…", style=self._muted())
        )
        self.set_interval(1.0, self.tick)
        self.set_interval(LOG_FLUSH_S, self.flush_log)
        self.set_interval(PF_POLL_S, self.poll_firewall)
        self.set_interval(DAEMON_POLL_S, self.poll_daemon)
        self.poll_firewall()
        self.poll_daemon()
        self.tick()
        self.consume()
        self.query_one("#feed", DataTable).focus()

    @staticmethod
    def _muted() -> str:
        return palette.current().muted

    # Theme

    def watch_theme(self, name: str) -> None:
        """Keep the Rich palette in step with the Textual theme, then redraw what it colours.

        A theme picked from Textual's command palette that is not one of ours maps to the
        dark or light palette by its brightness.
        """
        prefix = theme_name("")
        chosen = name.removeprefix(prefix) if name.startswith(prefix) else ""
        if chosen not in PALETTES:
            chosen = DARK.name if self.current_theme.dark else palette.LIGHT.name
        palette.use(chosen)
        self._palette_name = chosen
        if self._ui_ready:
            self._recolour()

    def _recolour(self) -> None:
        """Redraw everything that carries Rich colours: feed, tables, log and panels."""
        self._rebuild_feed()
        self.refresh_connections()
        self.refresh_blocked()
        self._log_dirty = True
        self.tick()

    def action_cycle_theme(self) -> None:
        """Switch to the next palette: dark, high contrast, light."""
        self.theme = theme_name(palette.next_name(self._palette_name))
        self.notify(f"Theme: {palette.current().label}", timeout=2)

    # Supervisor stream

    @work(exclusive=True, group="supervisor")
    async def consume(self) -> None:
        """Feed supervisor alerts and events into the UI; on failure say why and what to do."""
        try:
            async for update in self.supervisor.stream():
                self._mark_started()
                if isinstance(update, Alert):
                    self._last_event = update.finding.event.timestamp
                    self.add_alert(update)
                elif isinstance(update, Event):
                    self._events_seen += 1
                    self._last_event = update.timestamp
                    self.log_event(update)
                elif isinstance(update, NetworkConnection):
                    if update.status == PKTAP_STATUS:
                        self._flows_seen += 1
                    if self.lockdown is not None:
                        self.lockdown.audit_flow(update)
        except Exception as exc:
            hint = stop_hint(exc)
            self._stop_error = hint
            self.log_line(lambda: Text(f"supervisor stopped: {hint}", style=self._bad()))
            self.notify(hint, title="Supervisor stopped", severity="error", timeout=15)
        finally:
            self._live = False

    @staticmethod
    def _bad() -> str:
        return f"bold {palette.current().danger}"

    def _mark_started(self) -> None:
        if not self._started:
            self._started = True
            self.log_line(lambda: Text("watching: sensor events and sockets are live", "dim"))

    def log_line(self, line: Text | Callable[[], Text], haystack: str | None = None) -> None:
        """Queue a line for the sensor event log; it is written on the next flush.

        A callable is called again whenever the log is redrawn (filter or theme change), so
        its colours follow the palette; a plain `Text` keeps the colours it has.
        """
        if isinstance(line, Text):
            text = line

            def make() -> Text:
                return text

        else:
            make = line
        entry = LogLine(make, (haystack if haystack is not None else make().plain).lower())
        self._history.append(entry)
        if self._log_matches(entry):
            self._pending.append(entry)
            self._pending_total += 1

    def _log_matches(self, entry: LogLine) -> bool:
        return not self.filter_text or self.filter_text in entry.haystack

    def flush_log(self) -> None:
        """Write the queued lines in one go, noting how many were dropped since the last flush;
        after a filter or theme change, redraw the log from its history instead."""
        if not self.is_running:
            return
        try:
            log = self.query_one("#events", RichLog)
        except (NoMatches, ScreenStackError):
            return
        if not log.auto_scroll and log.is_vertical_scroll_end:
            # Back at the bottom after `t`: follow new lines again.
            log.auto_scroll = True
        if self._log_dirty:
            self._log_dirty = False
            log.clear()
            self._pending.clear()
            self._pending_total = 0
            for entry in self._history:
                if self._log_matches(entry):
                    log.write(entry.make())
            return
        if not self._pending_total:
            return
        dropped = self._pending_total - len(self._pending)
        if dropped:
            log.write(Text(f"… {dropped} lines dropped (log flood)", style=self._muted()))
        while self._pending:
            log.write(self._pending.popleft().make())
        self._pending_total = 0

    def _event_line(self, event: Event) -> Text:
        muted = self._muted()
        return Text.assemble(
            (clock(event.timestamp), muted),
            " ",
            sensor_pills([event.sensor]),
            f" {event.identity}",
            (f" pid={event.pid}" if event.pid is not None else "", muted),
            (f" {event.service}" if event.service else "", muted),
        )

    def log_event(self, event: Event) -> None:
        """Log a sensor event, skipping system events unless `include_system` is configured."""
        if event.system and not self.supervisor.engine.config.include_system:
            return
        haystack = " ".join(
            str(part)
            for part in (
                event.identity,
                event.process_name,
                event.pid,
                event.service,
                event.sensor.value,
                SENSOR_CODE[event.sensor],
            )
            if part is not None
        )
        self.log_line(lambda: self._event_line(event), haystack)

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
            text.append(f" {host}", style=self._muted())
        text.truncate(DEST_WIDTH, overflow="ellipsis")
        return text

    def _feed_row(self, alert: Alert) -> tuple[str | Text, ...]:
        ev, conn = alert.finding.event, alert.finding.connection
        p = palette.current()
        actor = Text.assemble((ev.identity, f"bold {p.strong}"), (f" {conn.pid}", p.muted))
        actor.truncate(ACTOR_WIDTH, overflow="ellipsis")
        return (
            str(alert.id),
            Text(clock(ev.timestamp)[:8], style=p.muted),
            severity_badge(alert.severity),
            sensor_pills(alert.sensors or {ev.sensor}),
            actor,
            self._destination(conn),
            Text(f"{alert.finding.delta_s * 1000:.0f} ms", style=p.muted),
            mitigation_badges(*self._mitigated(conn), compact=True),
        )

    def _matches(self, *fields: str | int | None) -> bool:
        needle = self.filter_text
        return not needle or any(needle in str(f).lower() for f in fields if f is not None)

    def _alert_matches(self, alert: Alert) -> bool:
        ev, conn = alert.finding.event, alert.finding.connection
        sensors = alert.sensors or {ev.sensor}
        return self._matches(
            ev.identity,
            ev.process_name,
            conn.process_name,
            conn.bundle_id,
            conn.pid,
            conn.remote_address,
            self._hostname(conn),
            alert.severity.name,
            *(SENSOR_CODE[s] for s in sensors),
            *(s.value for s in sensors),
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

        def line() -> Text:
            ink = severity_ink(alert.severity)
            head = Text.assemble(severity_badge(alert.severity), (f" ALERT #{key}{verb}: ", ink))
            return head.append(alert.summary, style=ink)

        self.log_line(line, f"alert {key} {alert.severity.name} {alert.summary}")
        selected = self.selection.alert if self.selection is not None else None
        if selected is not None and selected.id == alert.id:
            self.selection = Selection(conn, alert, self._alert_events[key])
            self._show_inspector()
        self._update_feed_subtitle()
        self._sync_bindings()
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
        """Count the alerts in the pane's border; with none shown, say why in the pane."""
        shown = self.query_one("#feed", DataTable).row_count
        pane = self.query_one("#feed-pane")
        if self.filter_text:
            pane.border_subtitle = f"filter “{self.filter_text}” · {shown}/{len(self.alerts)}"
        else:
            noun = "alert" if len(self.alerts) == 1 else "alerts"
            pane.border_subtitle = f"{len(self.alerts)} {noun}"
        pane.set_class(shown == 0, "-empty")
        if shown == 0:
            self.query_one("#feed-empty", Static).update(self._empty_feed())

    def _empty_feed(self) -> Text:
        p = palette.current()
        if self.filter_text:
            return Text.assemble(
                (f"No alert matches “{self.filter_text}”.", f"bold {p.strong}"),
                ("\nesc clears the filter.", p.muted),
            )
        window = self.supervisor.engine.config.window_s * 1000
        return Text.assemble(
            ("● No exfiltration pattern seen", f"bold {p.ok}"),
            (
                "\n\nAn alert appears here when an app uses the camera, microphone, screen or "
                f"location and opens a connection out within {window:.0f} ms. Every sensor "
                "event and open connection is listed below as it happens. ? lists the keys.",
                p.muted,
            ),
        )

    # Egress and block tables

    @staticmethod
    def _cursor_key(table: DataTable[object]) -> str | None:
        if not table.row_count:
            return None
        return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value

    def refresh_connections(self) -> None:
        """Rebuild the egress table (newest first, filtered), keeping the cursor on its row."""
        table = self.query_one("#connections", DataTable)
        current = self._cursor_key(table)
        active = sorted(self.supervisor.active_connections(), key=lambda c: -c.first_seen)
        muted = self._muted()
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
                Text(self._hostname(conn) or "", style=muted),
                Text("pktap" if conn.status == PKTAP_STATUS else conn.status, style=muted),
                mitigation_badges(*self._mitigated(conn), compact=True),
                key=key,
            )
        if current is not None and current in table.rows:
            table.move_cursor(row=table.get_row_index(current))

    def refresh_blocked(self) -> None:
        """Rebuild the Blocked tab: every address in pf's table, filtered, with its host name
        and how many alerts in the feed went to it."""
        table = self.query_one("#blocked-table", DataTable)
        current = self._cursor_key(table)
        resolver = self.supervisor.resolver
        hits: dict[str, int] = {}
        for alert in self.alerts.values():
            ip = _normal_ip(alert.finding.connection.remote_address)
            hits[ip] = hits.get(ip, 0) + 1
        muted = self._muted()
        table.clear()
        for ip in sorted(self.blocked, key=_ip_order):
            host = resolver.cached(ip) if resolver is not None else None
            if not self._matches(ip, host):
                continue
            count = hits.get(ip, 0)
            table.add_row(
                ip,
                Text(host or "", style=muted),
                str(count) if count else Text("—", style=muted),
                key=ip,
            )
        if current is not None and current in table.rows:
            table.move_cursor(row=table.get_row_index(current))

    def _blocked_row(self) -> str | None:
        """The highlighted address while the Blocked tab's table has the focus, else None."""
        focused = self.focused
        if isinstance(focused, DataTable) and focused.id == "blocked-table":
            return self._cursor_key(focused)
        return None

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
        """Once a second: tables, feed cells, counters, panels, status bar and footer keys."""
        # Textual stops app timers only after removing the screens: a late tick finds no widgets.
        if not self.is_running:
            return
        try:
            self.refresh_connections()
            self.refresh_blocked()
        except (NoMatches, ScreenStackError):
            return
        self._refresh_feed_rows()
        if self.lockdown is not None:
            # The watchdog may have taken pf back on its own: drop the red theme with it.
            lockdown_shown = self.screen_stack[0].has_class("-lockdown")
            if self.lockdown.state is LockdownState.OFF and lockdown_shown:
                self._set_lockdown_theme(False)
        self.stats = self._sample_stats()
        if self.stats.poll_ms is not None:
            self._mark_started()
        self._show_state()
        self.query_one(FirewallPanel).show(self.pf_status, self.stats)
        self.query_one(StatusBar).show(self.stats)
        self._show_inspector()
        self._sync_bindings()

    def _posture(self) -> Posture:
        """Count what needs you: HIGH-or-worse alerts neither blocked nor paused."""
        review, contained = 0, 0
        worst: Severity | None = None
        for alert in self.alerts.values():
            if any(self._mitigated(alert.finding.connection)):
                contained += 1
            elif alert.severity >= Severity.HIGH:
                review += 1
                worst = alert.severity if worst is None else max(worst, alert.severity)
        pf = self.pf_status
        return Posture(
            live=self._live,
            lockdown=self.lockdown.state if self.lockdown is not None else None,
            alerts=len(self.alerts),
            review=review,
            worst=worst,
            contained=contained,
            enforce=self._root(),
            starting=not self._started,
            error=self._stop_error,
            profile=self._profile,
            blocks=len(self.blocked) if pf is not None and pf.error is None else None,
            daemon=self.daemon_state,
            last_event=self._last_event,
        )

    def _mode(self) -> ModeStatus:
        lockdown = self.lockdown
        if lockdown is None:
            return ModeStatus(None)
        now = time.monotonic()
        leases = tuple(
            f"{lease.bundle_id.rsplit('.', 1)[-1]}({len(lease.grants)})"
            + (f" {max(0.0, lease.deadline - now):.0f}s" if lease.deadline else "")
            for lease in lockdown.leases
        )
        grants = len({g for lease in lockdown.leases for g in lease.grants})
        return ModeStatus(lockdown.state, leases, grants, lockdown.denied, self._profile)

    def _show_state(self) -> None:
        """Redraw the posture bar and the Paranoia Mode card."""
        try:
            posture = self.query_one(PostureBar)
            mode = self.query_one(ModePanel)
        except (NoMatches, ScreenStackError):
            return
        posture.show(self._posture(), time.strftime("%H:%M:%S"))
        mode.show(self._mode())

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
                self.pf_status = PfStatus(enabled, loaded, blocked, checked=time.time())
                self.blocked = {_normal_ip(ip) for ip in blocked}
        # pfctl can outlast the app: it may have shut down while we awaited.
        if not self.is_running:
            return
        self.query_one(FirewallPanel).show(self.pf_status, self.stats)
        self._refresh_feed_rows()
        self.refresh_blocked()

    @work(exclusive=True, group="daemon")
    async def poll_daemon(self) -> None:
        """Ask launchd whether the background `watch` daemon is installed and loaded."""
        try:
            status = await self._daemon.status()
        except OSError:
            self.daemon_state = DaemonState.UNKNOWN
        else:
            if status.loaded:
                self.daemon_state = DaemonState.RUNNING
            elif status.installed:
                self.daemon_state = DaemonState.STOPPED
            else:
                self.daemon_state = DaemonState.ABSENT
        if self.is_running:
            self._show_state()

    # Footer: only the keys that would do something now.

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        """Hide the selection's actions that would do nothing (block an address already
        blocked, resume a process that runs), so the footer lists what applies."""
        if action == "clear_feed":
            return bool(self.alerts)
        if action not in TARGET_ACTIONS:
            return True
        if self._blocked_row() is not None:
            return action in ("unblock", "copy")
        if action == "lease" and self.lockdown is None:
            return False
        if self.selection is None:
            return False
        blocked, suspended = self._mitigated(self.selection.connection)
        return {
            "block": not blocked,
            "unblock": blocked,
            "suspend": not suspended,
            "resume": suspended,
        }.get(action, True)

    def _sync_bindings(self) -> None:
        """Redraw the footer when the set of applicable keys changed."""
        state = tuple(self.check_action(a, ()) for a in (*TARGET_ACTIONS, "clear_feed"))
        if state != self._bindings_state:
            self._bindings_state = state
            self.refresh_bindings()

    # Selection and inspector

    def _select_from(self, table: DataTable[object]) -> None:
        if not table.row_count or table.id == "blocked-table":
            self._sync_bindings()
            return
        key = self._cursor_key(table) or ""
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
        self._sync_bindings()

    @on(DataTable.RowHighlighted)
    def _row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.has_focus:
            self._select_from(event.data_table)

    @on(DescendantFocus)
    def _focus_changed(self, event: DescendantFocus) -> None:
        if isinstance(event.widget, DataTable):
            self._select_from(event.widget)
        else:
            self._sync_bindings()

    @on(DataTable.RowSelected)
    def _row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "blocked-table":
            return
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
        """Log an action result and show it as a short toast (an error stays longer)."""
        verdict = "ok" if result.ok else "FAILED"
        message = f"{result.kind.value} {result.target}: {verdict} {result.detail}".strip()
        style = palette.current().ok if result.ok else self._bad()
        self.log_line(Text(message, style=style))
        if result.ok:
            text = f"{result.target} {result.detail}".strip()
            self.notify(text, title=DONE.get(result.kind, "Done"), timeout=3)
        else:
            self.notify(message, title="Failed", severity="error", timeout=10)
        self._refresh_feed_rows()
        self.refresh_connections()
        self.refresh_blocked()
        self._show_inspector()
        self._show_state()
        self._sync_bindings()

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
            # Re-read pf at once, so the Protection panel agrees with the header.
            self.poll_firewall()

    async def action_unblock(self) -> None:
        """Unblock the highlighted address of the Blocked tab, or the selection's remote IP."""
        ip = self._blocked_row()
        if ip is None:
            conn = self._require_selection()
            if conn is None:
                return
            ip = conn.remote_address
        result = await self.firewall.unblock(ip)
        if result.ok:
            self.blocked.discard(_normal_ip(result.target))
        self.report(result)
        self.poll_firewall()

    def _system_warning(self, conn: NetworkConnection) -> str:
        exe = self.processes.system_binary(conn.pid, conn.exe_path)
        if exe is None:
            return ""
        return (
            f"{exe} is a macOS system process: stopping it can freeze the desktop, cut the "
            "sound or log you out."
        )

    def action_suspend(self) -> None:
        """Send SIGSTOP to the selected connection's process; asks first for a macOS system
        process."""
        conn = self._require_selection()
        if conn is None:
            return

        def pause(confirmed: bool | None = True) -> None:
            if not confirmed:
                return
            result = self.processes.suspend(conn.pid)
            if result.ok:
                self.suspended.add(conn.pid)
            self.report(result)

        warning = self._system_warning(conn)
        if not warning:
            pause()
            return
        self.push_screen(
            ConfirmScreen(
                f"Pause {conn.process_name} (pid {conn.pid})?",
                f"{warning} r resumes it.",
                confirm="Pause anyway",
            ),
            pause,
        )

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

        warning = self._system_warning(conn)
        detail = (
            "SIGKILL cannot be undone: the app stops at once and loses unsaved work. "
            "s pauses it instead."
        )
        self.push_screen(
            ConfirmScreen(
                f"Kill {conn.process_name} (pid {conn.pid})?",
                f"{warning} {detail}" if warning else detail,
                confirm="Kill system process" if warning else "Kill process",
            ),
            on_answer,
        )

    def action_timeline(self) -> None:
        """Open the millisecond timeline of the selection: sensor events, then the egress."""
        selection = self.selection
        if selection is None:
            self.notify("Select an alert or connection first", severity="warning")
            return
        conn = self._named(selection.connection)
        steps = timeline_steps(conn, selection.events)
        if selection.alert is not None:
            title = f"Alert #{selection.alert.id} · timeline"
        else:
            title = f"{conn.process_name} · timeline"
        self.push_screen(TimelineScreen(title, steps, selection.alert))

    def _copy_items(self) -> tuple[str, list[tuple[str, str]]] | None:
        ip = self._blocked_row()
        if ip is not None:
            return ip, [("IP", ip), ("pf rule", pf_rule(ip)), ("pf command", pf_command(ip))]
        if self.selection is None:
            return None
        conn = self._named(self.selection.connection)
        items = [("PID", str(conn.pid)), ("Process", conn.process_name)]
        if conn.exe_path:
            items.append(("Path", conn.exe_path))
        if conn.bundle_id:
            items.append(("Bundle", conn.bundle_id))
        items.append(("IP", conn.remote_address))
        if conn.hostname:
            items.append(("Host", conn.hostname))
        items += [("pf rule", pf_rule(conn.remote_address))]
        items += [("pf command", pf_command(conn.remote_address))]
        return f"{conn.process_name} · pid {conn.pid}", items

    def action_copy(self) -> None:
        """Pick a value of the selection (PID, path, IP, host, pf rule) to copy."""
        found = self._copy_items()
        if found is None:
            self.notify("Select an alert or connection first", severity="warning")
            return
        title, items = found

        def on_pick(value: str | None) -> None:
            if value is not None:
                label = next(label for label, v in items if v == value)
                self.copy_value(label, value)

        self.push_screen(CopyScreen(f"Copy · {title}", items), on_pick)

    @work(group="clipboard")
    async def copy_value(self, label: str, value: str) -> None:
        """Copy `value` with pbcopy, and through the terminal (OSC 52) for remote sessions."""
        self.copy_to_clipboard(value)
        if await self._copier(value):
            self.notify(value, title=f"Copied {label}", timeout=3)
        else:
            self.notify(
                "pbcopy failed; sent to the terminal's clipboard instead (OSC 52), if it "
                "accepts that",
                title=f"Copy {label}",
                severity="warning",
                timeout=6,
            )

    def action_top(self) -> None:
        """Jump to the first row of the focused table, or the top of the sensor log."""
        widget = self.focused
        if isinstance(widget, RichLog):
            # Stop following new lines until the log is scrolled back to the bottom.
            widget.auto_scroll = False
            widget.scroll_home(animate=False)
            return
        if not isinstance(widget, DataTable):
            widget = self.query_one("#feed", DataTable)
            widget.focus()
        if widget.row_count:
            widget.move_cursor(row=0, animate=False)
        widget.scroll_home(animate=False)

    def help_keys(self) -> list[tuple[str, str]]:
        """Every key the dashboard answers to, for the help screen."""
        keys = []
        for binding in self.BINDINGS:
            if not isinstance(binding, Binding):
                continue
            key = binding.key_display or KEY_NAMES.get(binding.key, binding.key)
            keys.append((key, binding.description))
        keys += [
            ("enter", "Timeline of the highlighted row"),
            ("tab", "Next pane (shift+tab goes back)"),
            ("y / esc", "In a dialog: confirm / cancel (Cancel has the focus)"),
            ("ctrl+p", "Command palette"),
        ]
        return keys

    def action_help(self) -> None:
        """Show the keys, the FAQ and how to report a bug."""
        self.push_screen(HelpScreen(self.help_keys(), ISSUES_URL))

    def action_filter(self) -> None:
        """Show the filter box and move the focus into it."""
        box = self.query_one("#filter", Input)
        box.add_class("-open")
        box.focus()

    def _apply_filter(self, text: str) -> None:
        self.filter_text = text
        self._rebuild_feed()
        self.refresh_connections()
        self.refresh_blocked()
        self._log_dirty = True

    @on(Input.Changed, "#filter")
    def _filter_changed(self, event: Input.Changed) -> None:
        self._apply_filter(event.value.strip().lower())

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

        def line() -> Text:
            ink = severity_ink(notice.severity)
            return Text.assemble(severity_badge(notice.severity), (f" {notice.message}", ink))

        self.log_line(line, f"paranoia {notice.message}")
        if notice.severity >= Severity.HIGH:
            self.notify(notice.message, title="Paranoia Mode", severity="error", timeout=10)
        if notice.severity is Severity.CRITICAL:
            self.bell()

    def _set_lockdown_theme(self, on: bool) -> None:
        """Turn the whole dashboard red with steady borders (nothing blinks), or back to normal."""
        self.screen_stack[0].set_class(on, "-lockdown")
        self.query_one("#panic", Button).label = self.PANIC_ON if on else self.PANIC_OFF
        self._show_state()

    @on(Button.Pressed, "#panic")
    async def _panic_pressed(self) -> None:
        await self.action_panic()

    async def action_panic(self) -> None:
        """Enter Paranoia Mode at once (the max profile asks first); leaving asks first too,
        since it reopens egress."""
        lockdown = self.lockdown
        if lockdown is None:
            self.notify("Paranoia Mode needs root (run with sudo)", severity="error")
            return
        if lockdown.state is LockdownState.ARMING:
            self.notify("Paranoia Mode is arming…", severity="warning")
            return
        if lockdown.state is LockdownState.OFF:
            if self._profile != "max":
                await self._enter_lockdown()
                return

            def on_enter(confirmed: bool | None) -> None:
                if confirmed:
                    self.enter_lockdown()

            self.push_screen(
                ConfirmScreen(
                    "Enter Paranoia Mode with the max profile?",
                    MAX_PROFILE_DETAIL,
                    confirm="Enter max mode",
                ),
                on_enter,
            )
            return

        def on_answer(confirmed: bool | None) -> None:
            if confirmed:
                self.leave_lockdown()

        self.push_screen(
            ConfirmScreen(
                "Leave Paranoia Mode?",
                "Every app can reach the network again, under the normal block list.",
                confirm="Reopen egress",
            ),
            on_answer,
        )

    async def _enter_lockdown(self) -> None:
        assert self.lockdown is not None
        # The red is shown before pf is touched, so the press is felt at once.
        self._set_lockdown_theme(True)
        result = await self.lockdown.enter()
        if not result.ok:
            self._set_lockdown_theme(False)
        self.report(result)

    @work(exclusive=True, group="lockdown")
    async def enter_lockdown(self) -> None:
        """Enter Paranoia Mode (after the max profile's confirmation)."""
        await self._enter_lockdown()

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
            self.notify(bundle_id, title="Manual lease withdrawn", timeout=3)
        else:
            self.lockdown.grant_manual(bundle_id)
            self.notify(bundle_id, title="Manual lease granted", timeout=3)

    def action_clear_feed(self) -> None:
        """Empty the feed and the alerts held by the UI; the event log and pf are untouched."""
        self.alerts.clear()
        self._alert_events.clear()
        self._row_state.clear()
        self.query_one("#feed", DataTable).clear()
        if self.selection is not None and self.selection.alert is not None:
            self.selection = None
            self._show_inspector()
        self._show_state()
        self._update_feed_subtitle()
        self._sync_bindings()
