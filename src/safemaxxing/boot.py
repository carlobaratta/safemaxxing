"""launchd job that reapplies saved blocks at boot, since pf forgets its tables on reboot.

The job runs `/bin/sh` and `/sbin/pfctl` only, never this package: a root job pointing into a
user-writable virtualenv would let anything running as that user execute code as root.
"""

from __future__ import annotations

import os
import plistlib
import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path

from safemaxxing.firewall import (
    ANCHOR,
    BLOCKLIST,
    PARENT_ANCHOR_RULE,
    PFCTL,
    TABLE,
    Runner,
    anchor_rules,
    run_command,
)

LABEL = "io.github.carlobaratta.safemaxxing.restore"
PLIST = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
LOG = Path("/var/log/safemaxxing-boot.log")
LAUNCHCTL = "/bin/launchctl"
# com.apple.pfctl loads /etc/pf.conf at boot in no fixed order with us; wait for it this long.
PARENT_WAIT_S = 60


def boot_script(
    blocklist: Path = BLOCKLIST,
    anchor: str = ANCHOR,
    table: str = TABLE,
    pfctl: str = PFCTL,
    wait_s: int = PARENT_WAIT_S,
) -> str:
    """Return the POSIX sh script the job runs: wait for pf.conf, load the anchor, add, enable.

    Exits 0 without touching pf when the list is empty or missing, so an unused install never
    enables pf. Uses `-T add`, not `replace`, so running it on a live system only adds.
    """
    q = shlex.quote
    table_cmd = f'{q(pfctl)} -a {q(anchor)} -t {q(table)} -T add -f "$list"'
    has_parent = f"/usr/bin/grep -qF {q(PARENT_ANCHOR_RULE)}"
    missing = q(f"main pf ruleset still lacks {PARENT_ANCHOR_RULE} after {wait_s} s")
    return "\n".join(
        (
            f"list={q(str(blocklist))}",
            '[ -s "$list" ] || exit 0',
            "i=0",
            f"until {q(pfctl)} -s rules 2>/dev/null | {has_parent}; do",
            f'  i=$((i + 1)); [ "$i" -ge {wait_s} ] && echo {missing} >&2 && exit 1',
            "  /bin/sleep 1",
            "done",
            f"printf %s {q(anchor_rules(table))} | {q(pfctl)} -a {q(anchor)} -f - || exit 1",
            f"{table_cmd} || exit 1",
            f"exec {q(pfctl)} -E",
            "",
        )
    )


def launchd_plist(script: str) -> bytes:
    """Return the job's property list: run `script` once at load, log to LOG."""
    return plistlib.dumps(
        {
            "Label": LABEL,
            "ProgramArguments": ["/bin/sh", "-c", script],
            "RunAtLoad": True,
            "StandardOutPath": str(LOG),
            "StandardErrorPath": str(LOG),
        }
    )


@dataclass(frozen=True, slots=True)
class BootStatus:
    """Whether the job's plist is on disk and whether launchd has it loaded."""

    installed: bool
    loaded: bool


def write_root_file(path: Path, data: bytes) -> None:
    """Atomically write `path` with mode 0644 (launchd ignores a group/world-writable plist)."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


class LaunchdJob:
    """A job in launchd's system domain: load, unload, inspect (load and unload need root)."""

    def __init__(self, label: str, plist: Path, runner: Runner = run_command) -> None:
        self.label = label
        self.plist = plist
        self._run = runner

    async def load(self, plist: bytes) -> str:
        """Write `plist` and (re)load it into the system domain; return a problem or ''."""
        write_root_file(self.plist, plist)
        # bootstrap refuses a label that is already loaded, so drop any older copy first.
        await self._run([LAUNCHCTL, "bootout", f"system/{self.label}"])
        res = await self._run([LAUNCHCTL, "bootstrap", "system", str(self.plist)])
        return "" if res.returncode == 0 else (res.stderr.strip() or f"exit {res.returncode}")

    async def uninstall(self) -> None:
        """Unload the job and delete its plist."""
        await self._run([LAUNCHCTL, "bootout", f"system/{self.label}"])
        self.plist.unlink(missing_ok=True)

    async def print(self) -> str | None:
        """`launchctl print` of the job, or None when launchd does not have it loaded."""
        res = await self._run([LAUNCHCTL, "print", f"system/{self.label}"])
        return res.stdout if res.returncode == 0 else None

    async def status(self) -> BootStatus:
        """Report whether the plist exists and `launchctl print` finds the job."""
        return BootStatus(self.plist.exists(), await self.print() is not None)


class BootJob(LaunchdJob):
    """The boot-time restore job; uninstalling it leaves the saved list and live blocks alone."""

    def __init__(self, runner: Runner = run_command, plist: Path = PLIST) -> None:
        super().__init__(LABEL, plist, runner)

    async def install(self, script: str | None = None) -> str:
        """Write the plist and (re)load it into launchd's system domain; return a problem or ''.

        Loading runs the script once, which only adds the saved addresses to the live table.
        """
        return await self.load(launchd_plist(script or boot_script()))
