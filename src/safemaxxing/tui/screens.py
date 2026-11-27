"""Modal screens: the confirmation before an action you cannot take back, and the timeline."""

from __future__ import annotations

from typing import ClassVar

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

from safemaxxing.models import Alert
from safemaxxing.tui.badges import SENSOR_CODE, SENSOR_PILL, pill, severity_badge
from safemaxxing.tui.palette import BG, CRITICAL, MUTED, STRONG
from safemaxxing.tui.timeline import TimelineStep

EGRESS_PILL = f"bold {BG} on {CRITICAL}"


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
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right", style=f"bold {STRONG}", no_wrap=True)
    table.add_column(justify="right", style=MUTED, no_wrap=True)
    table.add_column(no_wrap=True)
    table.add_column(no_wrap=True)
    table.add_column(overflow="fold")
    start = steps[0].timestamp if steps else 0.0
    previous = start
    for step in steps:
        if step.sensor is None:
            tag = pill("EGRESS", EGRESS_PILL)
        else:
            tag = pill(SENSOR_CODE[step.sensor], SENSOR_PILL[step.sensor])
        offset = (step.timestamp - start) * 1000
        gap = (step.timestamp - previous) * 1000
        table.add_row(
            f"{offset:+.0f} ms",
            f"Δ{gap:.0f}" if step is not steps[0] else "",
            tag,
            Text(step.source.upper(), style=f"bold {STRONG}" if step.egress else MUTED),
            Text.assemble(
                (step.actor, f"bold {STRONG}" if step.egress else ""), "  ", (step.detail, MUTED)
            ),
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
        header.append(Text(f"{sensors} {noun}, then the connection out", style=MUTED))
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
