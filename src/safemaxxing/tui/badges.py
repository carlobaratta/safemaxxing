"""Rich pill badges for the dashboard: severity, sensors and mitigations.

Colours follow the dark palette in `safemaxxing.tcss`; every badge is plain `rich.text.Text`,
so it renders the same in a DataTable cell, a Static panel or the event log.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from rich.text import Text

from safemaxxing.models import SensorType, Severity

BG = "#0a0e14"
MUTED = "#5c6370"

SEVERITY_PILL: dict[Severity, str] = {
    Severity.CRITICAL: "bold #ff2e88 on #2a0a1c",
    Severity.HIGH: "bold #ffae42 on #2a1a05",
    Severity.MEDIUM: "#d7c46a on #1f1c0e",
    Severity.LOW: "#56b6c2 on #0e1c20",
}
# Foreground only, for log lines and notifications that carry no badge.
SEVERITY_INK: dict[Severity, str] = {
    Severity.CRITICAL: "bold #ff2e88",
    Severity.HIGH: "bold #ffae42",
    Severity.MEDIUM: "#d7c46a",
    Severity.LOW: "#56b6c2",
}

SENSOR_CODE: dict[SensorType, str] = {
    SensorType.CAMERA: "CAM",
    SensorType.MICROPHONE: "MIC",
    SensorType.LOCATION: "LOC",
    SensorType.SCREEN_CAPTURE: "SCR",
    SensorType.TCC: "TCC",
}
SENSOR_PILL: dict[SensorType, str] = {
    SensorType.CAMERA: f"bold {BG} on #c678dd",
    SensorType.MICROPHONE: f"bold {BG} on #61afef",
    SensorType.LOCATION: f"bold {BG} on #98c379",
    SensorType.SCREEN_CAPTURE: f"bold {BG} on #e5c07b",
    SensorType.TCC: f"bold {BG} on {MUTED}",
}
# Display order: the sensors that matter most first, so pill rows line up.
SENSOR_ORDER = tuple(SENSOR_CODE)

BLOCKED_PILL = f"bold {BG} on #e06c75"
SUSPENDED_PILL = f"bold {BG} on #d19a66"
SEVERITY_WIDTH = max(len(s.name) for s in Severity)


def pill(label: str, style: str) -> Text:
    """`label` padded by one space each side, on `style`'s background."""
    return Text(f" {label} ", style=style)


def severity_badge(severity: Severity) -> Text:
    """Fixed-width pill (`CRITICAL`, `  HIGH  `, ...) so a column of them lines up."""
    return pill(severity.name.center(SEVERITY_WIDTH), SEVERITY_PILL[severity])


def sensor_pills(sensors: Iterable[SensorType]) -> Text:
    """One pill per distinct sensor (`CAM MIC`), in `SENSOR_ORDER`."""
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
