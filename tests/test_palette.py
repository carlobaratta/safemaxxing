from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from safemaxxing.models import Severity
from safemaxxing.tui import palette
from safemaxxing.tui.app import THEMES, css_variables, theme_name
from safemaxxing.tui.badges import severity_ink
from safemaxxing.tui.palette import (
    DARK,
    HIGH_CONTRAST,
    LIGHT,
    ORDER,
    PALETTES,
    TEXT_PAIRS,
    contrast,
)

TCSS = Path(palette.__file__).with_name("safemaxxing.tcss")
# WCAG 2: AA for normal text is 4.5:1, AAA 7:1.
MINIMUM = {DARK.name: 4.5, LIGHT.name: 4.5, HIGH_CONTRAST.name: 7.0}


@pytest.fixture(autouse=True)
def restore_palette() -> Iterator[None]:
    before = palette.current().name
    yield
    palette.use(before)


def test_contrast_ratio_matches_wcag_reference_values() -> None:
    assert contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert contrast("#ffffff", "#ffffff") == pytest.approx(1.0)
    # The order of the two colours does not matter.
    assert contrast("#767676", "#ffffff") == pytest.approx(contrast("#ffffff", "#767676"))
    assert contrast("#767676", "#ffffff") == pytest.approx(4.54, abs=0.01)


@pytest.mark.parametrize("name", list(PALETTES))
def test_every_text_colour_reads_on_its_background(name: str) -> None:
    p = PALETTES[name]
    weak = [
        (ink, ground, round(contrast(getattr(p, ink), getattr(p, ground)), 2))
        for ink, ground in TEXT_PAIRS
        if contrast(getattr(p, ink), getattr(p, ground)) < MINIMUM[name]
    ]
    assert weak == []


def test_t_cycles_through_every_palette_and_wraps() -> None:
    seen = [ORDER[0]]
    for _ in ORDER:
        seen.append(palette.next_name(seen[-1]))
    assert seen[: len(ORDER)] == list(ORDER) and seen[-1] == ORDER[0]
    assert palette.next_name("not-a-palette") == ORDER[0]


def test_badges_take_the_palette_in_use_when_drawn() -> None:
    palette.use(DARK.name)
    dark = severity_ink(Severity.CRITICAL)
    palette.use(HIGH_CONTRAST.name)
    assert severity_ink(Severity.CRITICAL) != dark
    assert HIGH_CONTRAST.critical in severity_ink(Severity.CRITICAL)
    with pytest.raises(KeyError):
        palette.use("sepia")


def test_the_stylesheet_uses_only_theme_variables() -> None:
    css = TCSS.read_text()
    # No colour of its own: every one comes from the theme, so T recolours all of it.
    declarations = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    assert re.findall(r":[^;{}]*#[0-9a-fA-F]{3,6}\b[^;{}]*;", declarations) == []
    used = set(re.findall(r"\$(sm-[a-z-]+[a-z])", css))
    assert used <= set(css_variables(DARK))
    for p in PALETTES.values():
        theme = THEMES[p.name]
        assert theme.name == theme_name(p.name) and theme.dark is p.dark
        assert used <= set(theme.variables)
