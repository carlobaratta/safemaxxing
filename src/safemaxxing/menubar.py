"""macOS menu-bar companion: a status icon and quick actions over the supervisor.

Two ways to put this in the menu bar were considered:

* A minimal **Swift** `NSStatusBar` app talking to a Python daemon over a socket. It is the
  lightest at runtime and the most native, but it is a second language, a second build and a
  second release artifact, and it still needs the daemon to expose an IPC the app can read.
* **rumps** (a thin wrapper over PyObjC's `NSStatusBar`), used here. It keeps everything in
  one Python process and one release, reuses the supervisor, firewall and process controller
  directly, and costs only an optional dependency. PyObjC/rumps are macOS-only and not needed
  for the headless `watch`/`tui` paths, so the import is optional and this module loads fine
  on Linux (for the type checker and the tests) without them.

The design keeps a pure `MenuModel` -- icon state, the last few alerts, the blocked-IP list
and the auto-action toggles -- apart from the rumps rendering, so the logic is tested without
a GUI and the runner is a thin view. Whether a sensor is "active" is a recency heuristic: the
log path streams sensor *accesses*, not "sensor off", so a sensor counts as active for a short
window after its last access rather than until a kernel signal says otherwise.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from safemaxxing.models import Alert, Event, NetworkConnection, SensorType, Severity

Update = Event | NetworkConnection | Alert


class IconState(StrEnum):
    """What the status icon shows, worst-first when several could apply."""

    ALERT = "alert"  # a sensor-to-egress correlation fired recently
    SENSOR = "sensor"  # a sensor is in use, no recent correlation
    IDLE = "idle"  # nothing in use, firewall nominal


# Monochrome glyphs so no image assets are needed; the status bar renders the title text.
ICON_GLYPHS: dict[IconState, str] = {
    IconState.IDLE: "shield.idle",
    IconState.SENSOR: "shield.sensor",
    IconState.ALERT: "shield.alert",
}


@dataclass(frozen=True, slots=True)
class MenuBarConfig:
    """Timing and sizing of the menu-bar view."""

    # A sensor counts as active for this long after its last observed access.
    sensor_active_s: float = 6.0
    # The alert icon persists this long after the most recent correlation.
    alert_active_s: float = 20.0
    # How many recent alerts the drop-down lists.
    recent_alerts: int = 5
    # Cap on distinct alerts retained, pruned newest-first past it.
    max_alerts: int = 256


@dataclass(frozen=True, slots=True)
class RecentAlert:
    """A flattened alert for the menu: a label plus the targets its quick actions act on."""

    id: int
    created_at: float
    severity: Severity
    summary: str
    remote_address: str
    pid: int


class MenuModel:
    """The state behind the menu bar, fed the supervisor's updates and the firewall's table.

    Pure and clock-injected: `observe` folds in each update, `set_blocked` refreshes the
    blocked-IP list, and the read methods derive the icon, the recent-alert list and the active
    sensors. The auto-action toggles are held here but acted on by the runner, so this stays a
    display model with no side effects.
    """

    def __init__(
        self, config: MenuBarConfig | None = None, clock: Callable[[], float] = time.time
    ) -> None:
        self.config = config or MenuBarConfig()
        self._clock = clock
        self._alerts: dict[int, Alert] = {}
        self._sensor_last: dict[SensorType, float] = {}
        self._blocked: tuple[str, ...] = ()
        self.auto_block = False
        self.auto_suspend = False

    def observe(self, update: Update) -> None:
        """Fold one supervisor update into the model; connections affect nothing on their own."""
        if isinstance(update, Alert):
            self._alerts[update.id] = update
            if len(self._alerts) > self.config.max_alerts:
                newest = sorted(self._alerts.values(), key=lambda a: a.created_at, reverse=True)
                self._alerts = {a.id: a for a in newest[: self.config.max_alerts]}
        elif isinstance(update, Event):
            previous = self._sensor_last.get(update.sensor, 0.0)
            self._sensor_last[update.sensor] = max(previous, update.timestamp)

    def set_blocked(self, ips: list[str]) -> None:
        """Replace the known blocked-IP list (the runner refreshes it from the firewall)."""
        self._blocked = tuple(ips)

    def blocked_ips(self) -> tuple[str, ...]:
        """The IPs currently in the block table, as last refreshed."""
        return self._blocked

    def active_sensors(self, now: float | None = None) -> frozenset[SensorType]:
        """Sensors accessed within `sensor_active_s` of `now` (the recency heuristic)."""
        moment = self._clock() if now is None else now
        return frozenset(
            sensor
            for sensor, last in self._sensor_last.items()
            if moment - last <= self.config.sensor_active_s
        )

    def recent_alerts(self) -> list[RecentAlert]:
        """The most recent alerts, newest first, flattened for the menu."""
        newest = sorted(self._alerts.values(), key=lambda a: a.created_at, reverse=True)
        out: list[RecentAlert] = []
        for alert in newest[: self.config.recent_alerts]:
            conn = alert.finding.connection
            out.append(
                RecentAlert(
                    id=alert.id,
                    created_at=alert.created_at,
                    severity=alert.severity,
                    summary=alert.summary,
                    remote_address=conn.remote_address,
                    pid=conn.pid,
                )
            )
        return out

    def icon_state(self, now: float | None = None) -> IconState:
        """Worst state that applies now: alert, else sensor-in-use, else idle."""
        moment = self._clock() if now is None else now
        if self._alerts:
            last_alert = max(a.created_at for a in self._alerts.values())
            if moment - last_alert <= self.config.alert_active_s:
                return IconState.ALERT
        if self.active_sensors(moment):
            return IconState.SENSOR
        return IconState.IDLE

    def status_title(self, now: float | None = None) -> str:
        """The icon's glyph name for the current state."""
        return ICON_GLYPHS[self.icon_state(now)]


# --- rumps runner (macOS only; not import- or unit-testable without the dependency) ---------


def _import_rumps() -> Any:
    """Return the `rumps` module, or None when it is not installed (e.g. on CI)."""
    try:
        import rumps
    except ImportError:
        return None
    return rumps


def menubar_available() -> bool:
    """Whether the menu bar can run here: rumps is importable (so this is macOS with the extra)."""
    return _import_rumps() is not None


MENUBAR_HINT = "the menu bar needs rumps: install with  pip install 'safemaxxing[menubar]'"


def open_tui() -> None:
    """Open a Terminal window running `safemaxxing tui` (macOS `osascript`)."""
    import subprocess

    script = 'tell application "Terminal" to do script "safemaxxing tui"'
    subprocess.run(["/usr/bin/osascript", "-e", script], check=False)


def run_menubar(
    supervisor: Any,
    firewall: Any,
    processes: Any,
    config: MenuBarConfig | None = None,
) -> None:
    """Render the menu bar and drive it from `supervisor.stream()` until the app quits.

    macOS only, and requires the `menubar` extra; raises `RuntimeError` otherwise. The stream
    runs on a background asyncio thread feeding a `MenuModel`; a timer on the main thread
    rebuilds the icon and menu from that model and refreshes the blocked-IP list. Quick actions
    schedule the real firewall and process-controller calls. Not exercised in CI (no GUI).
    """
    import asyncio
    import threading
    from functools import partial

    rumps = _import_rumps()
    if rumps is None:
        raise RuntimeError(MENUBAR_HINT)

    model = MenuModel(config)
    loop = asyncio.new_event_loop()

    async def pump() -> None:
        async for update in supervisor.stream():
            model.observe(update)
            if isinstance(update, Alert) and update.severity >= Severity.HIGH:
                conn = update.finding.connection
                if model.auto_block:
                    await firewall.block(conn.remote_address)
                if model.auto_suspend:
                    processes.suspend(conn.pid)

    def run_loop() -> None:
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(pump())
        finally:
            loop.close()

    threading.Thread(target=run_loop, name="safemaxxing-menubar", daemon=True).start()

    app = rumps.App("safemaxxing", title=model.status_title(), quit_button="Quit safemaxxing")

    def block(ip: str, _sender: Any) -> None:
        asyncio.run_coroutine_threadsafe(firewall.block(ip), loop)

    def unblock(ip: str, _sender: Any) -> None:
        asyncio.run_coroutine_threadsafe(firewall.unblock(ip), loop)

    def flush(_sender: Any) -> None:
        asyncio.run_coroutine_threadsafe(firewall.flush(), loop)

    def suspend(pid: int, _sender: Any) -> None:
        processes.suspend(pid)

    def toggle_auto_block(sender: Any) -> None:
        model.auto_block = not model.auto_block
        sender.state = model.auto_block

    def toggle_auto_suspend(sender: Any) -> None:
        model.auto_suspend = not model.auto_suspend
        sender.state = model.auto_suspend

    def open_dashboard(_sender: Any) -> None:
        open_tui()

    def rebuild() -> None:
        items: list[Any] = [rumps.MenuItem(f"Status: {model.icon_state().value}", callback=None)]
        alerts = model.recent_alerts()
        items.append(rumps.separator)
        if alerts:
            for alert in alerts:
                row = rumps.MenuItem(f"[{alert.severity.label}] {alert.summary}", callback=None)
                row.add(rumps.MenuItem("Block IP", callback=partial(block, alert.remote_address)))
                row.add(rumps.MenuItem("Freeze process", callback=partial(suspend, alert.pid)))
                items.append(row)
        else:
            items.append(rumps.MenuItem("No correlations yet", callback=None))
        items.append(rumps.separator)
        auto_block_item = rumps.MenuItem("Auto-Block Mode", callback=toggle_auto_block)
        auto_block_item.state = model.auto_block
        auto_suspend_item = rumps.MenuItem("Auto-Suspend Mode", callback=toggle_auto_suspend)
        auto_suspend_item.state = model.auto_suspend
        items += [auto_block_item, auto_suspend_item, rumps.separator]
        blocked = model.blocked_ips()
        if blocked:
            for ip in blocked:
                entry = rumps.MenuItem(ip, callback=None)
                entry.add(rumps.MenuItem("Unblock", callback=partial(unblock, ip)))
                items.append(entry)
            items.append(rumps.MenuItem("Flush All", callback=flush))
        else:
            items.append(rumps.MenuItem("No blocked IPs", callback=None))
        items += [rumps.separator, rumps.MenuItem("Open TUI Dashboard", callback=open_dashboard)]
        app.menu.clear()
        app.menu.update(items)

    def refresh(_timer: Any) -> None:
        app.title = model.status_title()
        future = asyncio.run_coroutine_threadsafe(firewall.blocked(), loop)
        future.add_done_callback(lambda f: model.set_blocked(f.result()))
        rebuild()

    rebuild()
    rumps.Timer(refresh, 1.0).start()
    app.run()
