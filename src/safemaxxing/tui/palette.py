"""The dashboard's colours, in one place for the Rich renderables.

`safemaxxing.tcss` declares the same values as CSS variables; keep the two in step.

One accent (the project's teal) marks what you can act on and what is working. Severity
colours appear only where there is risk, so a calm screen really means nothing needs you.
"""

from __future__ import annotations

# Surfaces, darkest first.
BG = "#0a0e14"
SURFACE = "#0e131b"
RAISED = "#161d28"
LINE = "#222b38"

# Text.
TEXT = "#cfd7e2"
STRONG = "#eef2f6"
MUTED = "#7a8595"

# Meaning.
ACCENT = "#56b6c2"
OK = "#98c379"
CAUTION = "#e5c07b"
HIGH = "#ffae42"
CRITICAL = "#ff2e88"
DANGER = "#ff2e4d"
