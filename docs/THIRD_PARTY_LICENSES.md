# Third-party licenses

safemaxxing is released under the [MIT license](../LICENSE). Everything it installs is under a
permissive license compatible with it; `tests/test_licenses.py` reads the installed packages'
metadata and fails if a dependency (direct or not) is under GPL, AGPL, LGPL, MPL, SSPL or no
license at all. The versions below are the ones in `uv.lock`.

## Runtime

| Package | Version | License | Pulled in by |
|---------|---------|---------|--------------|
| [Textual](https://github.com/Textualize/textual) | 8.2.8 | MIT | safemaxxing (TUI) |
| [Rich](https://github.com/Textualize/rich) | 15.0.0 | MIT | safemaxxing, Textual, Typer |
| [Typer](https://github.com/fastapi/typer) | 0.28.0 | MIT | safemaxxing (CLI) |
| [psutil](https://github.com/giampaolo/psutil) | 7.2.2 | BSD-3-Clause | safemaxxing (socket table, processes) |
| markdown-it-py, mdit-py-plugins, mdurl | 4.3.0, 0.7.0, 0.1.2 | MIT | Rich, Textual |
| Pygments | 2.21.0 | BSD-2-Clause | Rich |
| platformdirs | 4.14.9 | MIT | Textual |
| typing-extensions | 4.16.0 | PSF-2.0 | Textual |
| annotated-doc | 0.0.7 | MIT | Typer |
| shellingham | 1.5.4 | ISC | Typer |

Typer 0.29 and later require pydantic and its compiled `pydantic-core`, which the CLI does not
use; `[tool.uv] constraint-dependencies` keeps the lock (and the `.pkg` build, which runs as
root) on 0.28.

## Menu bar (`--extra menubar`)

| Package | Version | License |
|---------|---------|---------|
| [rumps](https://github.com/jaredks/rumps) | 0.4.0 | BSD |
| [PyObjC](https://github.com/ronaldoussoren/pyobjc) (`pyobjc-core`, `pyobjc-framework-Cocoa`) | 13.1 | MIT |

## Build and development only

Not installed with safemaxxing: mypy (MIT), ruff (MIT), pytest (MIT), pytest-asyncio
(Apache-2.0), pytest-timeout (MIT), types-psutil (Apache-2.0), hatchling (MIT) and, for the
`.pkg`, PyInstaller (GPL-2.0 with its bootloader exception, which allows distributing the
frozen program under any license).

## Fonts

The TUI and the CLI ship no font; they draw with your terminal's. For the box-drawing lines,
the status symbols (● ○ ▲ ◆ ■ ◌) and the `→` in the help to line up, use a monospaced font
that covers them:

| Font | License | Notes |
|------|---------|-------|
| SF Mono, Menlo | Apple, bundled with macOS | Terminal's defaults; nothing to install |
| [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) | SIL Open Font License 1.1 | Clear `0`/`O` and `1`/`l`, useful for addresses and pids |

The project website (`site/`) uses Host Grotesk and JetBrains Mono, both under the SIL Open
Font License 1.1, loaded from Google Fonts; [PRIVACY.md](../PRIVACY.md#the-project-website)
explains what that request reveals and how to self-host them.
