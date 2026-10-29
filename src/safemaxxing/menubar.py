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

import threading
import time
from collections import deque
from collections.abc import AsyncIterable, Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from safemaxxing.models import (
    ActionKind,
    ActionResult,
    Alert,
    Event,
    NetworkConnection,
    SensorType,
    Severity,
)

Update = Event | NetworkConnection | Alert


class IconState(StrEnum):
    """What the status icon shows, worst-first when several could apply."""

    STOPPED = "stopped"  # the supervisor stream failed or ended: nothing is being watched
    ALERT = "alert"  # a sensor-to-egress correlation fired recently
    SENSOR = "sensor"  # a sensor is in use, no recent correlation
    IDLE = "idle"  # nothing in use, firewall nominal


# Monochrome Unicode glyphs so no image assets are needed: rumps renders the title as text, so
# these are what the status bar actually shows. U+FE0E keeps the warning sign a text glyph
# rather than a colour emoji.
ICON_GLYPHS: dict[IconState, str] = {
    IconState.IDLE: "○",  # ○
    IconState.SENSOR: "●",  # ●
    IconState.ALERT: "⚠︎",  # ⚠︎
    IconState.STOPPED: "⊘",  # ⊘
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
    # How many recent action outcomes the drop-down lists.
    recent_actions: int = 3
    # Auto-Block / Auto-Suspend act on alerts at or above this severity, once per alert.
    auto_action_severity: Severity = Severity.HIGH


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

    The runner writes from its asyncio thread and reads from the main (AppKit) thread, so every
    method holds one re-entrant lock: iterating the alerts while another thread inserts one
    would otherwise raise `dictionary changed size during iteration`.
    """

    def __init__(
        self, config: MenuBarConfig | None = None, clock: Callable[[], float] = time.time
    ) -> None:
        self.config = config or MenuBarConfig()
        self._clock = clock
        self._lock = threading.RLock()
        self._alerts: dict[int, Alert] = {}
        self._sensor_last: dict[SensorType, float] = {}
        self._blocked: tuple[str, ...] = ()
        self._stopped: str | None = None
        self._enforced: set[int] = set()
        self._actions: deque[ActionResult] = deque(maxlen=self.config.recent_actions)
        self.auto_block = False
        self.auto_suspend = False

    def mark_stopped(self, reason: str) -> None:
        """Record that the update stream is gone, so the icon stops claiming all is idle."""
        with self._lock:
            self._stopped = reason

    @property
    def stopped_reason(self) -> str | None:
        """Why monitoring stopped, or None while the stream is still running."""
        with self._lock:
            return self._stopped

    def observe(self, update: Update) -> None:
        """Fold one supervisor update into the model; connections affect nothing on their own."""
        with self._lock:
            if isinstance(update, Alert):
                self._alerts[update.id] = update
                if len(self._alerts) > self.config.max_alerts:
                    newest = sorted(self._alerts.values(), key=lambda a: a.created_at, reverse=True)
                    self._alerts = {a.id: a for a in newest[: self.config.max_alerts]}
            elif isinstance(update, Event):
                previous = self._sensor_last.get(update.sensor, 0.0)
                self._sensor_last[update.sensor] = max(previous, update.timestamp)

    def claim_enforcement(self, alert: Alert) -> bool:
        """Whether the auto-actions should act on `alert` now, claiming it if so.

        True the first time an alert is at or above `auto_action_severity`, then never again for
        that id: a re-emitted alert (more sensors, higher severity) must not re-run pfctl or
        re-signal the process, matching `watch`'s act-at-most-once rule.
        """
        with self._lock:
            if alert.severity < self.config.auto_action_severity or alert.id in self._enforced:
                return False
            self._enforced.add(alert.id)
            return True

    def record_action(self, result: ActionResult) -> None:
        """Keep the outcome of a quick or automatic action, so a failure is visible."""
        with self._lock:
            self._actions.append(result)

    def recent_actions(self) -> list[ActionResult]:
        """The last few action outcomes, newest first."""
        with self._lock:
            return list(reversed(self._actions))

    def set_blocked(self, ips: list[str]) -> None:
        """Replace the known blocked-IP list (the runner refreshes it from the firewall)."""
        with self._lock:
            self._blocked = tuple(ips)

    def blocked_ips(self) -> tuple[str, ...]:
        """The IPs currently in the block table, as last refreshed."""
        with self._lock:
            return self._blocked

    def active_sensors(self, now: float | None = None) -> frozenset[SensorType]:
        """Sensors accessed within `sensor_active_s` of `now` (the recency heuristic)."""
        moment = self._clock() if now is None else now
        with self._lock:
            return frozenset(
                sensor
                for sensor, last in self._sensor_last.items()
                if moment - last <= self.config.sensor_active_s
            )

    def recent_alerts(self) -> list[RecentAlert]:
        """The most recent alerts, newest first, flattened for the menu."""
        with self._lock:
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
        """Worst state that applies now: stopped, else alert, else sensor-in-use, else idle."""
        moment = self._clock() if now is None else now
        with self._lock:
            if self._stopped is not None:
                return IconState.STOPPED
            if self._alerts:
                last_alert = max(a.created_at for a in self._alerts.values())
                if moment - last_alert <= self.config.alert_active_s:
                    return IconState.ALERT
            if self.active_sensors(moment):
                return IconState.SENSOR
            return IconState.IDLE

    def status_title(self, now: float | None = None) -> str:
        """The icon's glyph for the current state."""
        return ICON_GLYPHS[self.icon_state(now)]


def action_label(result: ActionResult) -> str:
    """One menu line for an action outcome: a tick or a cross, the action, its target, why."""
    mark = "✓" if result.ok else "✗"
    detail = f": {result.detail}" if result.detail and not result.ok else ""
    return f"{mark} {result.kind.value} {result.target}{detail}"


async def pump_updates(
    updates: AsyncIterable[Update],
    model: MenuModel,
    on_alert: Callable[[Alert], Awaitable[None]],
) -> None:
    """Fold `updates` into `model`, calling `on_alert` per alert, until the stream stops.

    The stream only ends by failing (a source died, or root is missing) or by running dry, and
    either way nothing is watched any more: the model is marked stopped so the icon shows it,
    instead of the menu bar sitting on "idle" with no supervisor behind it.
    """
    try:
        async for update in updates:
            model.observe(update)
            if isinstance(update, Alert):
                await on_alert(update)
    except Exception as exc:
        model.mark_stopped(f"monitoring stopped: {exc}")
        return
    model.mark_stopped("monitoring stopped: the supervisor stream ended")


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
    runs on a background asyncio thread feeding a `MenuModel` via `pump_updates`, which marks
    the model stopped if the stream fails or ends; a timer on the main thread rebuilds the icon
    and menu from that model, notifies once on a stop, and refreshes the blocked-IP list. Quick
    actions schedule the real firewall and process-controller calls. Not exercised in CI.
    """
    import asyncio
    import contextlib
    from collections.abc import Coroutine
    from functools import partial

    rumps = _import_rumps()
    if rumps is None:
        raise RuntimeError(MENUBAR_HINT)

    model = MenuModel(config)
    loop = asyncio.new_event_loop()

    async def act(alert: Alert) -> None:
        if not (model.auto_block or model.auto_suspend) or not model.claim_enforcement(alert):
            return
        conn = alert.finding.connection
        if model.auto_block:
            model.record_action(await firewall.block(conn.remote_address))
        if model.auto_suspend:
            model.record_action(processes.suspend(conn.pid))

    def run_loop() -> None:
        asyncio.set_event_loop(loop)
        # The loop outlives the stream, so Unblock / Flush All still work once monitoring stops.
        task = loop.create_task(pump_updates(supervisor.stream(), model, act))
        try:
            loop.run_forever()
        finally:
            task.cancel()

    threading.Thread(target=run_loop, name="safemaxxing-menubar", daemon=True).start()

    app = rumps.App("safemaxxing", title=model.status_title(), quit_button="Quit safemaxxing")

    def schedule(kind: ActionKind, target: str, action: Coroutine[Any, Any, ActionResult]) -> None:
        """Run a firewall call on the loop and record its outcome, or why it raised."""

        def done(future: Any) -> None:
            try:
                result = future.result()
            except Exception as exc:
                result = ActionResult(kind, target, False, str(exc))
            model.record_action(result)

        asyncio.run_coroutine_threadsafe(action, loop).add_done_callback(done)

    def block(ip: str, _sender: Any) -> None:
        schedule(ActionKind.BLOCK_IP, ip, firewall.block(ip))

    def unblock(ip: str, _sender: Any) -> None:
        schedule(ActionKind.UNBLOCK_IP, ip, firewall.unblock(ip))

    def flush(_sender: Any) -> None:
        schedule(ActionKind.UNBLOCK_IP, "all", firewall.flush())

    def suspend(pid: int, _sender: Any) -> None:
        model.record_action(processes.suspend(pid))

    def toggle_auto_block(sender: Any) -> None:
        model.auto_block = not model.auto_block
        sender.state = model.auto_block

    def toggle_auto_suspend(sender: Any) -> None:
        model.auto_suspend = not model.auto_suspend
        sender.state = model.auto_suspend

    def open_dashboard(_sender: Any) -> None:
        open_tui()

    def rebuild() -> None:
        status = model.stopped_reason or model.icon_state().value
        items: list[Any] = [rumps.MenuItem(f"Status: {status}", callback=None)]
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
        actions = model.recent_actions()
        if actions:
            items += [rumps.MenuItem(action_label(r), callback=None) for r in actions]
            items.append(rumps.separator)
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

    notified_stop = False

    def refresh(_timer: Any) -> None:
        nonlocal notified_stop
        app.title = model.status_title()
        if model.stopped_reason and not notified_stop:
            notified_stop = True
            # rumps refuses to notify from an interpreter without a bundle id; the icon still shows.
            with contextlib.suppress(RuntimeError):
                rumps.notification("safemaxxing", "Monitoring stopped", model.stopped_reason)
        future = asyncio.run_coroutine_threadsafe(firewall.blocked(), loop)
        future.add_done_callback(lambda f: model.set_blocked(f.result()))
        rebuild()

    rebuild()
    rumps.Timer(refresh, 1.0).start()
    app.run()
