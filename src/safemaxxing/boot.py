"""launchd job that reapplies saved blocks at boot, since pf forgets its tables on reboot.

The job runs `/bin/sh`, `/sbin/pfctl` and base system tools only, never this package: a root
job pointing into a user-writable virtualenv would let anything running as that user execute
code as root.
"""

from __future__ import annotations

import errno
import os
import plistlib
import shlex
import stat as stat_mod
from dataclasses import dataclass
from pathlib import Path

from safemaxxing.firewall import (
    ANCHOR,
    BLOCKLIST,
    PARENT_ANCHOR_RULE,
    PF_REFERENCE,
    PFCTL,
    TABLE,
    FirewallError,
    PfReference,
    Runner,
    anchor_rules,
    run_command,
)
from safemaxxing.secure_fs import UntrustedPathError, write_atomic

LABEL = "io.github.carlobaratta.safemaxxing.restore"
PLIST = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
LOG = Path("/var/log/safemaxxing-boot.log")
LAUNCHCTL = "/bin/launchctl"
SYSCTL = "/usr/sbin/sysctl"
STAT = "/usr/bin/stat"
# com.apple.pfctl loads /etc/pf.conf at boot in no fixed order with us; wait for it this long.
PARENT_WAIT_S = 60
# Files launchd creates for a job (its logs) are private to root: the watch daemon's log is a
# record of which app used which sensor and where it connected.
JOB_UMASK = 0o077


def boot_script(
    blocklist: Path = BLOCKLIST,
    anchor: str = ANCHOR,
    table: str = TABLE,
    pfctl: str = PFCTL,
    wait_s: int = PARENT_WAIT_S,
    reference: Path = PF_REFERENCE,
    sysctl: str = SYSCTL,
    stat: str = STAT,
    owner_uid: int = 0,
) -> str:
    """Return the POSIX sh script the job runs: wait for pf.conf, load the anchor, add, enable.

    Exits 0 without touching pf when the list is empty or missing, so an unused install never
    enables pf. A list that `owner_uid` (root) does not own, that its group or others can
    write, or that holds anything but addresses and `#` comments is refused before pf is
    touched: pfctl's table files also take host names, networks and `!` negations, and the
    list is the only input the job reads. Uses `-T add`, not `replace`, so running it on a
    live system only adds. The
    `pfctl -E` token is saved in PfReference's format (root-only, 0600), so a later `flush`
    can release it. A record written since this boot, while pf is on, is kept and no new
    reference is taken: that is `boot install` loading the job on a live system, and taking a
    second reference there would leak the first. A record from before the reboot is deleted.
    """
    q = shlex.quote
    table_cmd = f'{q(pfctl)} -a {q(anchor)} -t {q(table)} -T add -f "$list"'
    has_parent = f"/usr/bin/grep -qF {q(PARENT_ANCHOR_RULE)}"
    missing = q(f"main pf ruleset still lacks {PARENT_ANCHOR_RULE} after {wait_s} s")
    pf_on = f"{q(pfctl)} -s info 2>/dev/null | /usr/bin/grep -q '^Status: Enabled'"
    not_private = q("refusing the block list: not root-owned, or writable by others")
    not_addresses = q("refusing the block list: a line is not an IP address")
    return "\n".join(
        (
            f"list={q(str(blocklist))}",
            '[ -s "$list" ] || exit 0',
            # Owner uid, then the permission bits: no write bit (2) for the group or others.
            f'case $({q(stat)} -f "%u %Lp" "$list" 2>/dev/null) in',
            f'  "{owner_uid} "?[0145][0145]) ;;',
            f"  *) echo {not_private} >&2; exit 1 ;;",
            "esac",
            "if /usr/bin/grep -qvE '^([0-9A-Fa-f:.]*|#.*)$' \"$list\"; then",
            f"  echo {not_addresses} >&2; exit 1",
            "fi",
            "i=0",
            f"until {q(pfctl)} -s rules 2>/dev/null | {has_parent}; do",
            f'  i=$((i + 1)); [ "$i" -ge {wait_s} ] && echo {missing} >&2 && exit 1',
            "  /bin/sleep 1",
            "done",
            f"printf %s {q(anchor_rules(table))} | {q(pfctl)} -a {q(anchor)} -f - || exit 1",
            f"{table_cmd} || exit 1",
            f"ref={q(str(reference))}",
            f'if [ -f "$ref" ] && {pf_on}; then',
            # kern.boottime: "{ sec = 1762678800, usec = 0 } Sun Nov  9 ..."
            f"  boot=$({q(sysctl)} -n kern.boottime 2>/dev/null)",
            '  boot=${boot#*"sec = "}; boot=${boot%%,*}',
            f'  mtime=$({q(stat)} -f %m "$ref" 2>/dev/null)',
            '  case "$boot:$mtime" in *[!0-9:]*|:*|*:) ;; *)',
            '    if [ "$mtime" -ge "$boot" ]; then',
            "      echo 'pf reference kept: recorded since this boot'; exit 0",
            "    fi ;;",
            "  esac",
            "fi",
            '/bin/rm -f "$ref"',
            f"out=$({q(pfctl)} -E 2>&1) || exit 1",
            "token=",
            "while IFS= read -r line; do",
            '  case $line in "Token : "*) token=${line#"Token : "} ;; esac',
            "done <<EOF",
            "$out",
            "EOF",
            "case $token in ''|*[!0-9]*) exit 0 ;; esac",
            f"status=$({q(pfctl)} -s info 2>/dev/null |",
            "  /usr/bin/grep '^Status: Enabled') || exit 0",
            "umask 077",
            'printf \'token=%s\\nstatus=%s\\n\' "$token" "$status" > "$ref.tmp" &&',
            '  /bin/mv -f "$ref.tmp" "$ref"',
            "",
        )
    )


def launchd_plist(script: str) -> bytes:
    """Return the job's property list: run `script` once at load, log to LOG (root only)."""
    return plistlib.dumps(
        {
            "Label": LABEL,
            "ProgramArguments": ["/bin/sh", "-c", script],
            "RunAtLoad": True,
            "Umask": JOB_UMASK,
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
    write_atomic(path, data, mode=0o644)


def prepare_private_log(path: Path) -> None:
    """Create `path` empty with mode 0600, or make an existing log 0600; never via a symlink.

    launchd opens a job's log files itself and keeps the mode of one that exists, so a log an
    older install left readable by everyone stays that way unless it is tightened here.
    """
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UntrustedPathError(f"{path}: a symlink, refusing to follow it") from None
        raise
    try:
        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode) or st.st_nlink > 1:
            raise UntrustedPathError(f"{path}: not a plain file, refusing to use it as a log")
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def plist_logs(plist: bytes) -> list[Path]:
    """The distinct StandardOutPath / StandardErrorPath of a job's property list."""
    job = plistlib.loads(plist)
    paths = (job.get("StandardOutPath"), job.get("StandardErrorPath"))
    return [Path(p) for p in dict.fromkeys(paths) if isinstance(p, str)]


class LaunchdJob:
    """A job in launchd's system domain: load, unload, inspect (load and unload need root)."""

    def __init__(self, label: str, plist: Path, runner: Runner = run_command) -> None:
        self.label = label
        self.plist = plist
        self._run = runner

    async def load(self, plist: bytes) -> str:
        """Write `plist` and (re)load it into the system domain; return a problem or ''.

        As root, the job's log files are made private (0600) first, so what it writes is
        readable by root only, whatever an older install left behind.
        """
        if os.geteuid() == 0:
            for log in plist_logs(plist):
                try:
                    prepare_private_log(log)
                except OSError as exc:
                    return f"log {log}: {exc}"
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


async def install_holding_reference(
    job: BootJob, reference: PfReference, saved: bool, run: Runner = run_command
) -> tuple[str, str]:
    """Take safemaxxing's pf reference, then load `job`; return (launchctl problem, note).

    The script runs at load and keeps a record written since this boot, so taking the
    reference first (when the list is not empty, as the script would) means the script finds a
    live record and takes no second one. Both happen under the reference's lock, so a `flush`
    cannot release in between. A pf that stays off is reported in the note; the job is still
    loaded, since it is what reapplies the list at the next boot.
    """
    async with reference.locked():
        note = ""
        if saved:
            try:
                note = await reference.acquire(run)
            except FirewallError as exc:
                note = str(exc)
        return await job.install(), note
