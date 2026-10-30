"""Dead-man switch: if safemaxxing stops beating while Paranoia Mode is on, put pf back.

A root LaunchDaemon (KeepAlive) runs a `/bin/sh` loop and `/sbin/pfctl` only, never this
package, for the reason `boot.py` gives. It is idle unless `/var/run/safemaxxing/lockdown`
exists. While it does, the loop reads a counter safemaxxing rewrites every second; after
`MISSED_BEATS` iterations without a change it reloads the v0.2 ruleset (block table kept),
flushes the grants and removes the flag.

It counts its own iterations rather than comparing timestamps: no clock jump can blind or
trip it, and during system sleep neither side runs, so waking up is not a missed beat.
`/var/run` is emptied at boot, so a lockdown never survives a restart either.
"""

from __future__ import annotations

import asyncio
import os
import plistlib
import shlex
import tempfile
from collections.abc import Callable
from pathlib import Path

from safemaxxing.boot import LaunchdJob
from safemaxxing.firewall import ANCHOR, PFCTL, Runner, anchor_rules, run_command
from safemaxxing.lockdown.rules import GRANTS_ANCHOR

LABEL = "io.github.carlobaratta.safemaxxing.watchdog"
PLIST = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
LOG = Path("/var/log/safemaxxing-watchdog.log")
# Root-owned and emptied at boot: an unprivileged process can neither fake a beat (keeping a
# dead lockdown up) nor arm it.
RUN_DIR = Path("/var/run/safemaxxing")
HEARTBEAT = RUN_DIR / "heartbeat"
ARMED = RUN_DIR / "lockdown"
MISSED_BEATS = 5
TICK_S = "1"


def watchdog_script(
    heartbeat: Path = HEARTBEAT,
    armed: Path = ARMED,
    anchor: str = ANCHOR,
    grants_anchor: str = GRANTS_ANCHOR,
    pfctl: str = PFCTL,
    missed: int = MISSED_BEATS,
    tick: str = TICK_S,
) -> str:
    """The POSIX sh loop the job runs. `read` is a builtin: an idle tick forks only `sleep`."""
    q = shlex.quote
    return "\n".join(
        (
            f"hb={q(str(heartbeat))}",
            f"armed={q(str(armed))}",
            "last=",
            "stale=0",
            "while :; do",
            '  if [ -e "$armed" ]; then',
            "    beat=",
            '    read -r beat 2>/dev/null < "$hb"',
            '    if [ -n "$beat" ] && [ "$beat" != "$last" ]; then',
            "      last=$beat",
            "      stale=0",
            "    else",
            "      stale=$((stale + 1))",
            "    fi",
            f'    if [ "$stale" -ge {missed} ]; then',
            f'      echo "$(/bin/date) no heartbeat for {missed} ticks: leaving lockdown"',
            f"      printf %s {q(anchor_rules())} | {q(pfctl)} -a {q(anchor)} -f -",
            f"      {q(pfctl)} -a {q(grants_anchor)} -F rules",
            '      /bin/rm -f "$armed"',
            "      stale=0",
            "      last=",
            "    fi",
            "  else",
            "    stale=0",
            "    last=",
            "  fi",
            f"  /bin/sleep {q(tick)}",
            "done",
            "",
        )
    )


def watchdog_plist(script: str) -> bytes:
    """The job's property list: start at load, restart whenever it exits, log to LOG."""
    return plistlib.dumps(
        {
            "Label": LABEL,
            "ProgramArguments": ["/bin/sh", "-c", script],
            "RunAtLoad": True,
            "KeepAlive": True,
            "StandardOutPath": str(LOG),
            "StandardErrorPath": str(LOG),
        }
    )


class WatchdogJob(LaunchdJob):
    """The watchdog in launchd's system domain. Installing it changes nothing until armed."""

    def __init__(self, runner: Runner = run_command, plist: Path = PLIST) -> None:
        super().__init__(LABEL, plist, runner)

    async def install(self, script: str | None = None) -> str:
        """Write the plist and (re)load it; return a problem or ''."""
        return await self.load(watchdog_plist(script or watchdog_script()))


class Heartbeat:
    """Writes the counter the watchdog watches, and arms or disarms it.

    `healthy` gates every beat: the loop being alive is not enough, the learn loop and its
    capture must be too, or a lockdown that stopped learning would hold the user offline.
    """

    def __init__(
        self,
        run_dir: Path = RUN_DIR,
        interval_s: float = 1.0,
        healthy: Callable[[], bool] = lambda: True,
    ) -> None:
        self.run_dir = run_dir
        self.heartbeat = run_dir / HEARTBEAT.name
        self.armed_flag = run_dir / ARMED.name
        self.interval_s = interval_s
        self.healthy = healthy
        self.count = 0

    def _write(self, path: Path, text: str) -> None:
        self.run_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.run_dir, prefix=f".{path.name}-")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(text)
            os.chmod(tmp, 0o644)
            # Atomic, so the shell's `read` never sees half a line.
            os.replace(tmp, path)
        except BaseException:
            os.unlink(tmp)
            raise

    def beat(self) -> None:
        """Write the next counter value."""
        self.count += 1
        self._write(self.heartbeat, f"{self.count}\n")

    def arm(self) -> None:
        """Beat, then create the flag: from now on silence means restore."""
        self.beat()
        self._write(self.armed_flag, "armed\n")

    def disarm(self) -> None:
        """Remove the flag; the watchdog goes idle."""
        self.armed_flag.unlink(missing_ok=True)

    @property
    def armed(self) -> bool:
        """False after the watchdog tripped (it removes the flag), or before `arm`."""
        return self.armed_flag.exists()

    async def run(self, on_tripped: Callable[[], None]) -> None:
        """Beat every `interval_s` while healthy; call `on_tripped` once the flag is gone."""
        while True:
            if not self.armed:
                on_tripped()
                return
            if self.healthy():
                self.beat()
            await asyncio.sleep(self.interval_s)
