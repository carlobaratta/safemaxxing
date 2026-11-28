"""Modal screens: the confirmation before an action you cannot take back, the timeline, the
help and FAQ, and the copy menu. Each one is driven from the keyboard alone, starts with its
focus on a visible control, and closes with Escape."""

from __future__ import annotations

from typing import ClassVar

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label, OptionList, Static
from textual.widgets.option_list import Option

from safemaxxing.models import Alert
from safemaxxing.tui.badges import SENSOR_CODE, pill, sensor_pill, severity_badge
from safemaxxing.tui.palette import current
from safemaxxing.tui.timeline import TimelineStep


def egress_pill() -> str:
    """The step that leaves the Mac: the one solid red chip on the timeline."""
    p = current()
    return f"bold {p.bg} on {p.critical}"


class ConfirmScreen(ModalScreen[bool]):
    """Modal yes/no dialog; dismisses with True only when the action is confirmed.

    `detail` says what cannot be undone, and `confirm` names the action on its button, so the
    choice is read, not guessed: "Kill process", never a bare "OK".
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("y", "confirm", "Confirm", show=False),
    ]

    def __init__(self, prompt: str, detail: str = "", confirm: str = "Confirm") -> None:
        super().__init__()
        self._prompt = prompt
        self._detail = detail
        self._confirm = confirm

    def compose(self) -> ComposeResult:
        """Lay out the question, what it changes, and the two buttons."""
        with Vertical(id="dialog"):
            yield Label(self._prompt, classes="question")
            if self._detail:
                yield Label(self._detail, classes="detail")
            with Horizontal(id="buttons"):
                yield Label("y confirms · esc cancels", classes="hint")
                yield Button("Cancel", id="no")
                yield Button(self._confirm, id="yes", variant="error")

    def on_mount(self) -> None:
        """Start on Cancel: Enter alone never runs the action."""
        self.query_one("#no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dismiss with True for the action, False for Cancel."""
        self.dismiss(event.button.id == "yes")

    def action_confirm(self) -> None:
        """Dismiss with True."""
        self.dismiss(True)

    def action_cancel(self) -> None:
        """Dismiss with False."""
        self.dismiss(False)


def render_timeline(steps: tuple[TimelineStep, ...]) -> RenderableType:
    """Steps as rows: offset from the first step, gap from the previous one, source, actor."""
    palette = current()
    strong, muted = f"bold {palette.strong}", palette.muted
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right", style=strong, no_wrap=True)
    table.add_column(justify="right", style=muted, no_wrap=True)
    table.add_column(no_wrap=True)
    table.add_column(no_wrap=True)
    table.add_column(overflow="fold")
    start = steps[0].timestamp if steps else 0.0
    previous = start
    for step in steps:
        if step.sensor is None:
            tag = pill("EGRESS", egress_pill())
        else:
            tag = pill(SENSOR_CODE[step.sensor], sensor_pill(step.sensor))
        offset = (step.timestamp - start) * 1000
        gap = (step.timestamp - previous) * 1000
        table.add_row(
            f"{offset:+.0f} ms",
            f"Δ{gap:.0f}" if step is not steps[0] else "",
            tag,
            Text(step.source.upper(), style=strong if step.egress else muted),
            Text.assemble((step.actor, strong if step.egress else ""), "  ", (step.detail, muted)),
        )
        previous = step.timestamp
    return table


class TimelineScreen(ModalScreen[None]):
    """Full-height timeline of one alert (or connection), closed with Escape, Enter or q."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "close", "Close"),
        Binding("enter", "close", "Close", show=False),
        Binding("space", "close", "Close", show=False),
        Binding("q", "close", "Close", show=False),
    ]

    def __init__(self, title: str, steps: tuple[TimelineStep, ...], alert: Alert | None) -> None:
        super().__init__()
        self._title = title
        self._steps = steps
        self._alert = alert

    def compose(self) -> ComposeResult:
        """A bordered box with the alert header above the step table."""
        header: list[RenderableType] = []
        if self._alert is not None:
            header.append(
                Text.assemble(severity_badge(self._alert.severity), "  ", self._alert.summary)
            )
        sensors = sum(1 for s in self._steps if not s.egress)
        noun = "sensor event" if sensors == 1 else "sensor events"
        header.append(Text(f"{sensors} {noun}, then the connection out", style=current().muted))
        with VerticalScroll(id="timeline"):
            yield Static(Group(*header, Text(""), render_timeline(self._steps)))

    def on_mount(self) -> None:
        """Title the box."""
        box = self.query_one("#timeline")
        box.border_title = self._title
        box.border_subtitle = "esc closes"

    def action_close(self) -> None:
        """Close the timeline."""
        self.dismiss(None)


# The answers people look for first, in the order they ask. Kept short: the README has more.
FAQ: tuple[tuple[str, str], ...] = (
    (
        "Does anything leave this Mac?",
        "No. Sensor events, connections and alerts are processed in memory, here; there is no "
        "telemetry and no third-party SDK. Host names come from the system resolver (--no-dns "
        "turns that off). The only download is `safemaxxing paranoia blocklist`, when you run it.",
    ),
    (
        "The header says read-only, or pf needs root.",
        "Blocking, pktap and Paranoia Mode need root: quit and run `sudo safemaxxing tui`.",
    ),
    (
        "No sensor events show up.",
        "Run `safemaxxing doctor`: it checks `log stream`, Full Disk Access for the terminal "
        "(System Settings › Privacy & Security) and the log predicates.",
    ),
    (
        "What does Paranoia Mode change?",
        "It loads default-deny rules in safemaxxing's own pf anchor: only apps using a sensor or "
        "granted with g reach the network. The watchdog restores the normal rules if "
        "safemaxxing stops. /etc/pf.conf and the system's rules are never touched.",
    ),
    (
        "How do I remove everything safemaxxing put here?",
        "`sudo safemaxxing purge` lists it, asks, then removes the launchd jobs, its pf rules, "
        "the saved lists and its logs.",
    ),
)


def render_help(keys: list[tuple[str, str]], issues_url: str) -> RenderableType:
    """Keys, then the FAQ, then how to report a bug without sharing what identifies you."""
    palette = current()
    strong, muted, accent = f"bold {palette.strong}", palette.muted, f"bold {palette.accent}"
    table = Table.grid(padding=(0, 2))
    table.add_column(style=accent, no_wrap=True, justify="right")
    table.add_column()
    for key, description in keys:
        table.add_row(key, description)
    parts: list[RenderableType] = [Text("Keys", style=strong), table, Text("")]
    parts.append(Text("Questions", style=strong))
    for question, answer in FAQ:
        parts += [Text(f"› {question}", style=accent), Text(f"  {answer}", style=""), Text("")]
    parts += [
        Text("Report a bug", style=strong),
        Text.assemble(
            "Attach a redacted report (no IP addresses, home paths, login or host name):\n",
            ("  safemaxxing report --redact -o report.md", accent),
            "\nand open an issue at ",
            (issues_url, accent),
            (" (nothing is sent for you).", muted),
        ),
    ]
    return Group(*parts)


class HelpScreen(ModalScreen[None]):
    """Keys, FAQ and the bug-report route; ↑/↓ and PgUp/PgDn scroll, Escape, q or ? close."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "close", "Close"),
        Binding("q", "close", "Close", show=False),
        Binding("question_mark", "close", "Close", show=False),
    ]

    def __init__(self, keys: list[tuple[str, str]], issues_url: str) -> None:
        super().__init__()
        self._keys = keys
        self._issues_url = issues_url

    def compose(self) -> ComposeResult:
        """One scrolling box."""
        with VerticalScroll(id="help"):
            yield Static(render_help(self._keys, self._issues_url))

    def on_mount(self) -> None:
        """Title the box and focus it, so the arrow keys scroll at once."""
        box = self.query_one("#help", VerticalScroll)
        box.border_title = "Help"
        box.border_subtitle = "esc closes"
        box.focus()

    def action_close(self) -> None:
        """Close the help."""
        self.dismiss(None)


class CopyScreen(ModalScreen[str | None]):
    """Pick one value of the selection to copy: ↑/↓ and Enter, or its number; Escape cancels.

    Dismisses with the value, or None.
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "cancel", "Cancel"),
        *(Binding(str(n), f"pick({n - 1})", show=False) for n in range(1, 10)),
    ]

    def __init__(self, title: str, items: list[tuple[str, str]]) -> None:
        super().__init__()
        self._title = title
        self._items = items

    def compose(self) -> ComposeResult:
        """A numbered list: label, then the value that would be copied."""
        options = [
            Option(Text.assemble((f"{n}  {label:<12}", f"bold {current().accent}"), value))
            for n, (label, value) in enumerate(self._items, 1)
        ]
        with Vertical(id="copy"):
            yield OptionList(*options, id="copy-options")

    def on_mount(self) -> None:
        """Title the box and start on its first entry."""
        box = self.query_one("#copy")
        box.border_title = self._title
        box.border_subtitle = "enter or 1-9 copies · esc cancels"
        options = self.query_one(OptionList)
        options.highlighted = 0
        options.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Dismiss with the chosen value."""
        self.dismiss(self._items[event.option_index][1])

    def action_pick(self, index: int) -> None:
        """Dismiss with entry `index` (from its number key), if there is one."""
        if 0 <= index < len(self._items):
            self.dismiss(self._items[index][1])

    def action_cancel(self) -> None:
        """Dismiss without copying."""
        self.dismiss(None)
