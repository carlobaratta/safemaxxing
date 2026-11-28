"""Rich badges for the dashboard: severity, sensors and mitigations.

Every badge is plain `rich.text.Text`, so it renders the same in a DataTable cell, a Static
panel or the event log. Colours come from `palette.current()` when a badge is built, so a theme
switch recolours the next one drawn. Severity is the only thing coloured by risk; sensors share
one neutral chip, and a mitigation reads as protection, not as alarm.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from rich.text import Text

from safemaxxing.models import SensorType, Severity
from safemaxxing.tui.palette import current

SENSOR_CODE: dict[SensorType, str] = {
    SensorType.CAMERA: "CAM",
    SensorType.MICROPHONE: "MIC",
    SensorType.LOCATION: "LOC",
    SensorType.SCREEN_CAPTURE: "SCR",
    SensorType.TCC: "TCC",
}
# Display order: the sensors that matter most first, so chip rows line up.
SENSOR_ORDER = tuple(SENSOR_CODE)


def severity_pill(severity: Severity) -> str:
    """The badge style of `severity` in the current palette."""
    p = current()
    return {
        Severity.CRITICAL: f"bold {p.critical} on {p.critical_bg}",
        Severity.HIGH: f"bold {p.high} on {p.high_bg}",
        Severity.MEDIUM: f"{p.caution} on {p.caution_bg}",
        Severity.LOW: f"{p.muted} on {p.raised}",
    }[severity]


def severity_ink(severity: Severity) -> str:
    """Foreground only, for log lines and notifications that carry no badge."""
    p = current()
    return {
        Severity.CRITICAL: f"bold {p.critical}",
        Severity.HIGH: f"bold {p.high}",
        Severity.MEDIUM: p.caution,
        Severity.LOW: p.muted,
    }[severity]


def sensor_pill(sensor: SensorType) -> str:
    """A real use of a sensor is one strong chip; a TCC request is only a permission check."""
    p = current()
    if sensor is SensorType.TCC:
        return f"{p.muted} on {p.raised}"
    return f"bold {p.strong} on {p.sensor_bg}"


def blocked_pill() -> str:
    """Blocking an address protects you: it wears the accent."""
    p = current()
    return f"bold {p.accent} on {p.blocked_bg}"


def suspended_pill() -> str:
    """A paused process is waiting on you."""
    p = current()
    return f"bold {p.caution} on {p.caution_bg}"


SEVERITY_WIDTH = max(len(s.name) for s in Severity)


def pill(label: str, style: str) -> Text:
    """`label` padded by one space each side, on `style`'s background."""
    return Text(f" {label} ", style=style)


def severity_badge(severity: Severity) -> Text:
    """Fixed-width pill (`CRITICAL`, `  HIGH  `, ...) so a column of them lines up."""
    return pill(severity.name.center(SEVERITY_WIDTH), severity_pill(severity))


def sensor_pills(sensors: Iterable[SensorType]) -> Text:
    """One chip per distinct sensor (`CAM MIC`), in `SENSOR_ORDER`."""
    present = set(sensors)
    return Text(" ").join(
        pill(SENSOR_CODE[s], sensor_pill(s)) for s in SENSOR_ORDER if s in present
    )


def mitigation_badges(blocked: bool, suspended: bool, compact: bool = False) -> Text:
    """`BLOCKED` and/or `SUSPENDED` pills (`BLK` / `STOP` when `compact`, for table cells);
    empty when neither applies."""
    pills = []
    if blocked:
        pills.append(pill("BLK" if compact else "BLOCKED", blocked_pill()))
    if suspended:
        pills.append(pill("STOP" if compact else "SUSPENDED", suspended_pill()))
    return Text(" ").join(pills)


def clock(ts: float) -> str:
    """Local wall-clock time with milliseconds, e.g. `10:57:46.014`."""
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
