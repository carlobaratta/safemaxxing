"""The dashboard's colours: three palettes (dark, high contrast, light), one in use at a time.

The Rich renderables (badges, panels, feed cells) read `current()` when they draw, and the
Textual theme built from the same palette (`app.theme_for`) feeds `safemaxxing.tcss` its
`$sm-*` variables, so switching the palette and the theme together recolours everything.

One accent marks what you can act on and what is working. Severity colours appear only where
there is risk, so a calm screen really means nothing needs you.

Every text colour is checked against the backgrounds it is drawn on (tests/test_palette.py):
WCAG AA (4.5:1) for dark and light, AAA (7:1) for high contrast. NO_COLOR=1 makes any of
them monochrome (Textual and Rich both honour it).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Palette:
    """Every colour the dashboard uses, as `#rrggbb`."""

    name: str
    label: str
    dark: bool
    # Surfaces, from the screen behind the panes to the raised chips.
    bg: str
    surface: str
    raised: str
    line: str
    # Text.
    text: str
    strong: str
    muted: str
    # Meaning.
    accent: str
    ok: str
    caution: str
    high: str
    critical: str
    danger: str
    # Badge backgrounds.
    critical_bg: str
    high_bg: str
    caution_bg: str
    blocked_bg: str
    sensor_bg: str
    # Table rows and scrollbars.
    hover: str
    cursor: str
    cursor_blurred: str
    scrollbar_hover: str
    # The Paranoia Mode button, and the frame while the mode is on.
    panic_hover: str
    lockdown_bg: str
    lockdown_bar: str
    lockdown_ink: str
    lockdown_quiet: str
    panic_fill: str
    panic_fill_hover: str
    panic_ink: str


DARK = Palette(
    name="dark",
    label="Dark",
    dark=True,
    bg="#0a0e14",
    surface="#0e131b",
    raised="#161d28",
    line="#222b38",
    text="#cfd7e2",
    strong="#eef2f6",
    muted="#8592a3",
    accent="#56b6c2",
    ok="#98c379",
    caution="#e5c07b",
    high="#ffae42",
    critical="#ff2e88",
    danger="#ff4d63",
    critical_bg="#2a0a1c",
    high_bg="#2a1a05",
    caution_bg="#201b0d",
    blocked_bg="#0f2226",
    sensor_bg="#243142",
    hover="#131a24",
    cursor="#1f2c3d",
    cursor_blurred="#18212d",
    scrollbar_hover="#2e3a4a",
    panic_hover="#2a0d14",
    lockdown_bg="#10070a",
    lockdown_bar="#5c0012",
    lockdown_ink="#ffffff",
    lockdown_quiet="#f3c6cd",
    panic_fill="#c8102e",
    panic_fill_hover="#a50d26",
    panic_ink="#ffffff",
)

HIGH_CONTRAST = Palette(
    name="high-contrast",
    label="High contrast",
    dark=True,
    bg="#000000",
    surface="#000000",
    raised="#1c1c1c",
    line="#b0b0b0",
    text="#ffffff",
    strong="#ffffff",
    muted="#d6d6d6",
    accent="#00e5ff",
    ok="#5cff5c",
    caution="#ffe94d",
    high="#ffb84d",
    critical="#ff85d6",
    danger="#ff8080",
    critical_bg="#33001f",
    high_bg="#331f00",
    caution_bg="#2b2600",
    blocked_bg="#002b33",
    sensor_bg="#2e2e2e",
    hover="#1c1c1c",
    cursor="#3a3a3a",
    cursor_blurred="#262626",
    scrollbar_hover="#808080",
    panic_hover="#3d0000",
    lockdown_bg="#000000",
    lockdown_bar="#8b0000",
    lockdown_ink="#ffffff",
    lockdown_quiet="#ffffff",
    panic_fill="#ff8080",
    panic_fill_hover="#ffa8a8",
    panic_ink="#000000",
)

LIGHT = Palette(
    name="light",
    label="Light",
    dark=False,
    bg="#f5f7fa",
    surface="#ffffff",
    raised="#e9edf2",
    line="#c3ccd6",
    text="#1d2733",
    strong="#0b1218",
    muted="#525e6c",
    accent="#0a6670",
    ok="#2d6a1e",
    caution="#765000",
    high="#934200",
    critical="#ad1260",
    danger="#be1530",
    critical_bg="#fbe3ef",
    high_bg="#fdebd7",
    caution_bg="#fbf0d2",
    blocked_bg="#ddf1f3",
    sensor_bg="#d5dde7",
    hover="#eef2f6",
    cursor="#cfe6ea",
    cursor_blurred="#e3e9ef",
    scrollbar_hover="#9aa6b3",
    panic_hover="#fbe3e7",
    lockdown_bg="#fbe9ec",
    lockdown_bar="#a3001c",
    lockdown_ink="#ffffff",
    lockdown_quiet="#ffe3e7",
    panic_fill="#be1530",
    panic_fill_hover="#9e1027",
    panic_ink="#ffffff",
)

PALETTES: dict[str, Palette] = {p.name: p for p in (DARK, HIGH_CONTRAST, LIGHT)}
# The order T cycles through.
ORDER: tuple[str, ...] = tuple(PALETTES)

_current = DARK


def current() -> Palette:
    """The palette the dashboard draws with right now."""
    return _current


def use(name: str) -> Palette:
    """Draw with palette `name` from now on (KeyError for an unknown name)."""
    global _current
    _current = PALETTES[name]
    return _current


def next_name(name: str) -> str:
    """The palette after `name` in `ORDER`, wrapping round."""
    index = ORDER.index(name) if name in ORDER else -1
    return ORDER[(index + 1) % len(ORDER)]


def _luminance(colour: str) -> float:
    channels = (int(colour.lstrip("#")[i : i + 2], 16) / 255 for i in (0, 2, 4))
    r, g, b = (c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(ink: str, background: str) -> float:
    """WCAG 2 contrast ratio of two `#rrggbb` colours, from 1 to 21."""
    hi, lo = sorted((_luminance(ink), _luminance(background)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


# (ink, background) field pairs that appear together as text on screen.
TEXT_PAIRS: tuple[tuple[str, str], ...] = (
    ("text", "bg"),
    ("text", "surface"),
    ("strong", "surface"),
    ("muted", "bg"),
    ("muted", "surface"),
    ("muted", "raised"),
    *(
        (ink, ground)
        for ink in ("accent", "ok", "caution", "high", "critical", "danger")
        for ground in ("bg", "surface")
    ),
    ("critical", "critical_bg"),
    ("high", "high_bg"),
    ("caution", "caution_bg"),
    ("accent", "blocked_bg"),
    ("strong", "sensor_bg"),
    ("strong", "cursor"),
    ("text", "cursor_blurred"),
    ("text", "hover"),
    ("danger", "raised"),
    ("danger", "panic_hover"),
    ("lockdown_ink", "lockdown_bar"),
    ("lockdown_quiet", "lockdown_bar"),
    ("panic_ink", "panic_fill"),
    ("panic_ink", "panic_fill_hover"),
    ("bg", "critical"),
)
