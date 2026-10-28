"""Modal screens: the kill confirmation and the millisecond timeline of an alert."""

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
from safemaxxing.tui.badges import MUTED, SENSOR_CODE, SENSOR_PILL, pill, severity_badge
from safemaxxing.tui.timeline import TimelineStep

EGRESS_PILL = "bold #0a0e14 on #ff2e88"


class ConfirmScreen(ModalScreen[bool]):
    """Modal yes/no dialog; dismisses with True only when Confirm is pressed."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("y", "confirm", "Confirm", show=False),
    ]

    def __init__(self, prompt: str) -> None:
        super().__init__()
        self._prompt = prompt

    def compose(self) -> ComposeResult:
        """Lay out the prompt with Cancel and Confirm buttons."""
        with Vertical(id="dialog"):
            yield Label(self._prompt)
            yield Label("y confirms · esc cancels", classes="hint")
            with Horizontal(id="buttons"):
                yield Button("Cancel", id="no")
                yield Button("Confirm", id="yes", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dismiss with True for Confirm, False for Cancel."""
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
    table.add_column(justify="right", style="bold", no_wrap=True)
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
            Text(step.source.upper(), style="bold" if step.egress else MUTED),
            Text.assemble((step.actor, "bold" if step.egress else ""), "  ", (step.detail, MUTED)),
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
                Text.assemble(severity_badge(self._alert.severity), " ", self._alert.summary)
            )
        sensors = sum(1 for s in self._steps if not s.egress)
        header.append(Text(f"{sensors} sensor events, then the egress", style=MUTED))
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
