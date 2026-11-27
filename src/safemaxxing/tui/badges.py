"""Rich badges for the dashboard: severity, sensors and mitigations.

Every badge is plain `rich.text.Text`, so it renders the same in a DataTable cell, a Static
panel or the event log. Colours come from `palette.py`: severity is the only thing coloured by
risk; sensors share one neutral chip, and a mitigation reads as protection, not as alarm.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from rich.text import Text

from safemaxxing.models import SensorType, Severity
from safemaxxing.tui.palette import ACCENT, CAUTION, CRITICAL, HIGH, MUTED, RAISED, STRONG

SEVERITY_PILL: dict[Severity, str] = {
    Severity.CRITICAL: f"bold {CRITICAL} on #2a0a1c",
    Severity.HIGH: f"bold {HIGH} on #2a1a05",
    Severity.MEDIUM: f"{CAUTION} on #201b0d",
    Severity.LOW: f"{MUTED} on {RAISED}",
}
# Foreground only, for log lines and notifications that carry no badge.
SEVERITY_INK: dict[Severity, str] = {
    Severity.CRITICAL: f"bold {CRITICAL}",
    Severity.HIGH: f"bold {HIGH}",
    Severity.MEDIUM: CAUTION,
    Severity.LOW: MUTED,
}

SENSOR_CODE: dict[SensorType, str] = {
    SensorType.CAMERA: "CAM",
    SensorType.MICROPHONE: "MIC",
    SensorType.LOCATION: "LOC",
    SensorType.SCREEN_CAPTURE: "SCR",
    SensorType.TCC: "TCC",
}
# A real use of a sensor is one strong chip; a TCC request is only a permission check.
SENSOR_USE = f"bold {STRONG} on #243142"
SENSOR_PILL: dict[SensorType, str] = {
    sensor: SENSOR_USE if sensor is not SensorType.TCC else f"{MUTED} on {RAISED}"
    for sensor in SENSOR_CODE
}
# Display order: the sensors that matter most first, so chip rows line up.
SENSOR_ORDER = tuple(SENSOR_CODE)

# Blocking an address protects you: it wears the accent. A paused process is waiting on you.
BLOCKED_PILL = f"bold {ACCENT} on #0f2226"
SUSPENDED_PILL = f"bold {CAUTION} on #201b0d"
SEVERITY_WIDTH = max(len(s.name) for s in Severity)


def pill(label: str, style: str) -> Text:
    """`label` padded by one space each side, on `style`'s background."""
    return Text(f" {label} ", style=style)


def severity_badge(severity: Severity) -> Text:
    """Fixed-width pill (`CRITICAL`, `  HIGH  `, ...) so a column of them lines up."""
    return pill(severity.name.center(SEVERITY_WIDTH), SEVERITY_PILL[severity])


def sensor_pills(sensors: Iterable[SensorType]) -> Text:
    """One chip per distinct sensor (`CAM MIC`), in `SENSOR_ORDER`."""
    present = set(sensors)
    return Text(" ").join(
        pill(SENSOR_CODE[s], SENSOR_PILL[s]) for s in SENSOR_ORDER if s in present
    )


def mitigation_badges(blocked: bool, suspended: bool, compact: bool = False) -> Text:
    """`BLOCKED` and/or `SUSPENDED` pills (`BLK` / `STOP` when `compact`, for table cells);
    empty when neither applies."""
    pills = []
    if blocked:
        pills.append(pill("BLK" if compact else "BLOCKED", BLOCKED_PILL))
    if suspended:
        pills.append(pill("STOP" if compact else "SUSPENDED", SUSPENDED_PILL))
    return Text(" ").join(pills)


def clock(ts: float) -> str:
    """Local wall-clock time with milliseconds, e.g. `10:57:46.014`."""
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
