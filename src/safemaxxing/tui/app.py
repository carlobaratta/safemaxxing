"""Textual dashboard: live sensor stream, active egress sockets and correlation alerts."""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Label, RichLog

from safemaxxing.firewall import BlockList, PfFirewall, ProcessController
from safemaxxing.models import ActionResult, Alert, Event, NetworkConnection, Severity
from safemaxxing.supervisor import Supervisor

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.LOW: "dim",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}


def _clock(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]


class ConfirmScreen(ModalScreen[bool]):
    """Modal yes/no dialog; dismisses with True only when Confirm is pressed."""

    DEFAULT_CSS = """
    ConfirmScreen { align: center middle; }
    #dialog { width: 60; height: auto; padding: 1 2; border: thick $error; background: $surface; }
    #buttons { height: auto; align-horizontal: right; margin-top: 1; }
    #buttons Button { margin-left: 1; }
    """

    def __init__(self, prompt: str) -> None:
        super().__init__()
        self._prompt = prompt

    def compose(self) -> ComposeResult:
        """Lay out the prompt with Cancel and Confirm buttons."""
        with Vertical(id="dialog"):
            yield Label(self._prompt)
            with Horizontal(id="buttons"):
                yield Button("Cancel", id="no")
                yield Button("Confirm", id="yes", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dismiss with True for Confirm, False for Cancel."""
        self.dismiss(event.button.id == "yes")


class SafemaxxingApp(App[None]):
    """Dashboard of alerts, active egress sockets and sensor events fed by a `Supervisor`.

    Block, unblock, suspend, resume and kill act on the selected connection: the highlighted row
    of the connections table when it has focus, otherwise the connection of the highlighted alert.
    Kill asks for confirmation first.
    """

    TITLE = "safemaxxing"
    SUB_TITLE = "sensor → egress correlation"
    CSS = """
    #top { height: 1fr; }
    .pane { width: 1fr; border: round $primary; }
    .pane:focus-within { border: round $accent; }
    .title { padding: 0 1; text-style: bold; }
    #events-pane { height: 1fr; border: round $primary; }
    DataTable { height: 1fr; }
    """
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("b", "block", "Block IP"),
        Binding("u", "unblock", "Unblock IP"),
        Binding("s", "suspend", "SIGSTOP"),
        Binding("r", "resume", "SIGCONT"),
        Binding("k", "kill", "SIGKILL"),
        Binding("c", "clear_alerts", "Clear alerts"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(
        self,
        supervisor: Supervisor,
        firewall: PfFirewall | None = None,
        processes: ProcessController | None = None,
    ) -> None:
        super().__init__()
        self.supervisor = supervisor
        self.firewall = firewall or PfFirewall(store=BlockList())
        self.processes = processes or ProcessController()
        self.alerts: dict[str, Alert] = {}
        self._connections: dict[str, NetworkConnection] = {}

    def compose(self) -> ComposeResult:
        """Lay out the alerts and connections tables above the sensor event log."""
        yield Header()
        with Horizontal(id="top"):
            with Vertical(classes="pane"):
                yield Label("Alerts", classes="title")
                yield DataTable(id="alerts", cursor_type="row", zebra_stripes=True)
            with Vertical(classes="pane"):
                yield Label("Active egress", classes="title")
                yield DataTable(id="connections", cursor_type="row", zebra_stripes=True)
        with Vertical(id="events-pane"):
            yield Label("Sensor events", classes="title")
            yield RichLog(id="events", markup=False, highlight=False, max_lines=2000)
        yield Footer()

    def on_mount(self) -> None:
        """Set up table columns, refresh connections every second and start consuming updates."""
        self.query_one("#alerts", DataTable).add_columns(
            "#", "time", "sev", "sensor", "app", "pid", "destination", "Δms"
        )
        self.query_one("#connections", DataTable).add_columns(
            "pid", "process", "proto", "destination", "host", "state"
        )
        self.set_interval(1.0, self.refresh_connections)
        self.consume()

    @work(exclusive=True, group="supervisor")
    async def consume(self) -> None:
        """Feed supervisor alerts and events into the UI; on failure log it and notify."""
        try:
            async for update in self.supervisor.stream():
                if isinstance(update, Alert):
                    self.add_alert(update)
                elif isinstance(update, Event):
                    self.log_event(update)
        except Exception as exc:
            self.log_line(Text(f"supervisor stopped: {exc}", style="bold red"))
            self.notify(f"Supervisor stopped: {exc}", severity="error", timeout=10)

    def log_line(self, text: Text) -> None:
        """Append a line to the sensor event log."""
        self.query_one("#events", RichLog).write(text)

    def log_event(self, event: Event) -> None:
        """Log a sensor event, skipping system events unless `include_system` is configured."""
        if event.system and not self.supervisor.engine.config.include_system:
            return
        line = Text.assemble(
            (_clock(event.timestamp), "dim"),
            " ",
            (f"{event.sensor.value:<14}", "cyan"),
            f" {event.identity}",
            (f" pid={event.pid}" if event.pid is not None else "", "dim"),
            (f" {event.service}" if event.service else "", "magenta"),
        )
        self.log_line(line)

    def add_alert(self, alert: Alert) -> None:
        """Add or replace the alert's table row and log it.

        Rings the bell and notifies only for HIGH or above, and only for a new alert or an
        escalation in severity.
        """
        ev, conn = alert.finding.event, alert.finding.connection
        style = SEVERITY_STYLE[alert.severity]
        destination = conn.hostname or conn.remote
        table = self.query_one("#alerts", DataTable)
        previous = self.alerts.get(str(alert.id))
        if previous is not None:
            table.remove_row(str(alert.id))
        self.alerts[str(alert.id)] = alert
        table.add_row(
            str(alert.id),
            _clock(ev.timestamp),
            Text(alert.severity.label, style=style),
            alert.sensor_label,
            ev.identity,
            str(conn.pid),
            destination,
            f"{alert.finding.delta_s * 1000:.0f}",
            key=str(alert.id),
        )
        verb = "updated" if previous is not None else ""
        self.log_line(Text(f"ALERT #{alert.id} {verb}: {alert.summary}", style=style))
        escalated = previous is None or alert.severity > previous.severity
        if alert.severity >= Severity.HIGH and escalated:
            self.bell()
            self.notify(alert.summary, title="Exfiltration pattern", severity="warning")

    def refresh_connections(self) -> None:
        """Rebuild the connections table (oldest first), keeping the cursor row where possible."""
        table = self.query_one("#connections", DataTable)
        row = table.cursor_row
        table.clear()
        self._connections.clear()
        for conn in sorted(self.supervisor.active_connections(), key=lambda c: c.first_seen):
            key = "|".join(map(str, conn.key))
            self._connections[key] = conn
            table.add_row(
                str(conn.pid),
                conn.process_name,
                conn.protocol.value,
                conn.remote,
                conn.hostname or "",
                conn.status,
                key=key,
            )
        if table.row_count:
            table.move_cursor(row=min(row, table.row_count - 1))

    def _selected(self) -> NetworkConnection | None:
        focused = self.focused
        if isinstance(focused, DataTable) and focused.id == "connections" and focused.row_count:
            key = focused.coordinate_to_cell_key(focused.cursor_coordinate).row_key.value
            return self._connections.get(key or "")
        alerts = self.query_one("#alerts", DataTable)
        if not alerts.row_count:
            return None
        key = alerts.coordinate_to_cell_key(alerts.cursor_coordinate).row_key.value
        alert = self.alerts.get(key or "")
        return alert.finding.connection if alert else None

    def report(self, result: ActionResult) -> None:
        """Log an action result and show it as a notification (error severity on failure)."""
        verdict = "ok" if result.ok else "FAILED"
        message = f"{result.kind.value} {result.target}: {verdict} {result.detail}".strip()
        self.log_line(Text(message, style="green" if result.ok else "bold red"))
        self.notify(message, severity="information" if result.ok else "error")

    def _require_selection(self) -> NetworkConnection | None:
        conn = self._selected()
        if conn is None:
            self.notify("Select an alert or connection first", severity="warning")
        return conn

    async def action_block(self) -> None:
        """Block the selected connection's remote IP in pf."""
        if conn := self._require_selection():
            self.report(await self.firewall.block(conn.remote_address))

    async def action_unblock(self) -> None:
        """Unblock the selected connection's remote IP in pf."""
        if conn := self._require_selection():
            self.report(await self.firewall.unblock(conn.remote_address))

    def action_suspend(self) -> None:
        """Send SIGSTOP to the selected connection's process."""
        if conn := self._require_selection():
            self.report(self.processes.suspend(conn.pid))

    def action_resume(self) -> None:
        """Send SIGCONT to the selected connection's process."""
        if conn := self._require_selection():
            self.report(self.processes.resume(conn.pid))

    def action_kill(self) -> None:
        """Send SIGKILL to the selected connection's process, after a confirmation dialog."""
        conn = self._require_selection()
        if conn is None:
            return

        def on_answer(confirmed: bool | None) -> None:
            if confirmed:
                self.report(self.processes.kill(conn.pid))

        self.push_screen(ConfirmScreen(f"Kill {conn.process_name} (pid {conn.pid})?"), on_answer)

    def action_clear_alerts(self) -> None:
        """Clear the alerts table and the alerts held by the UI."""
        self.alerts.clear()
        self.query_one("#alerts", DataTable).clear()
