"""pf table management and process control (SIGSTOP / SIGCONT / SIGKILL)."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import ipaddress
import os
import re
import signal
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from safemaxxing.models import ActionKind, ActionResult

PFCTL = "/sbin/pfctl"
TABLE = "safemaxxing_block"
# The stock /etc/pf.conf evaluates `anchor "com.apple/*"`, so rules here apply without editing it.
ANCHOR = "com.apple/safemaxxing"
# Root-owned, so only root can change what the boot job feeds to pfctl.
STATE_DIR = Path("/Library/Application Support/safemaxxing")
BLOCKLIST = STATE_DIR / "blocklist"


def anchor_rules(table: str = TABLE) -> str:
    """Return the pf rule text loaded into the anchor: drop all outbound traffic to `table`."""
    # No `table` definition: reloading a ruleset that defines a table resets its contents.
    return f"block drop out quick from any to <{table}>\n"


class FirewallError(RuntimeError):
    """Raised when pf cannot be prepared: unreachable anchor, rejected rules, or pf stays off."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Exit status and decoded output of one finished subprocess."""

    returncode: int
    stdout: str
    stderr: str


class Runner(Protocol):
    """Async callable that runs an argv (optionally feeding stdin); swapped out in tests."""

    async def __call__(self, argv: Sequence[str], stdin: str | None = None) -> CommandResult: ...


async def run_command(argv: Sequence[str], stdin: str | None = None) -> CommandResult:
    """Run `argv` directly (no shell) and capture its output; never raises on a non-zero exit.

    Output is decoded leniently. A missing executable still raises OSError from the spawn.
    """
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate(stdin.encode() if stdin is not None else None)
    return CommandResult(
        proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")
    )


def validate_ip(raw: str) -> str:
    """Normalise an address and refuse ones whose blocking would break the host."""
    ip = ipaddress.ip_address(raw.strip())
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        raise ValueError(f"refusing to block {ip}")
    return str(ip)


def is_root() -> bool:
    """True if the process runs as root, which pfctl and signalling other users' processes need."""
    return os.geteuid() == 0


_STATUS_RE = re.compile(r"^Status:\s+(Enabled|Disabled)", re.MULTILINE)
# pfctl chatter on Darwin that is not an error.
_BENIGN_STDERR = (
    "No ALTQ support in kernel",
    "ALTQ related functions disabled",
    "pf enabled",
    "pf already enabled",
    "Token :",
    "rules cleared",
    # Printed by Darwin's pfctl on every `-f`, even when scoped to an anchor with `-a`.
    "Use of -f option, could result in flushing of rules",
    "present in the main ruleset added by the system at startup",
    "See /etc/pf.conf for further details",
)
PARENT_ANCHOR_RULE = 'anchor "com.apple/*"'


# How Darwin's pfctl answers a query for an anchor that has never been created.
_ANCHOR_MISSING = ("DIOCGETRULES: Invalid argument", "Anchor does not exist")


def anchor_missing(stderr: str) -> bool:
    """True if pfctl's stderr says the anchor has never been created."""
    return any(marker in stderr for marker in _ANCHOR_MISSING)


def table_missing(stderr: str) -> bool:
    """pf creates the table on the first `-T add`; before that, queries report it missing."""
    return "Table does not exist" in stderr


def parse_pf_status(info: str) -> bool | None:
    """Parse `pfctl -s info`: True if Enabled, False if Disabled, None if unrecognised."""
    match = _STATUS_RE.search(info)
    return None if match is None else match.group(1) == "Enabled"


def meaningful_stderr(stderr: str) -> list[str]:
    """Return stripped stderr lines that are real errors, dropping benign Darwin pfctl chatter."""
    return [
        line.strip()
        for line in stderr.splitlines()
        if line.strip() and not any(b in line for b in _BENIGN_STDERR)
    ]


class BlockList:
    """Blocked addresses saved on disk, one per line, for the boot job to reapply.

    pf forgets its tables at reboot; `safemaxxing boot install` adds a launchd job that feeds
    this file to `pfctl -T add -f`. The file is replaced atomically and kept mode 0644.
    """

    def __init__(self, path: Path = BLOCKLIST) -> None:
        self.path = path

    def load(self) -> list[str]:
        """Return the saved addresses in insertion order; a missing file means none."""
        try:
            text = self.path.read_text()
        except FileNotFoundError:
            return []
        return [line.strip() for line in text.splitlines() if line.strip() and line[0] != "#"]

    def _save(self, ips: list[str]) -> None:
        self.path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".blocklist-")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write("".join(f"{ip}\n" for ip in ips))
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise

    def add(self, ip: str) -> None:
        """Save `ip` unless it is already listed."""
        ips = self.load()
        if ip not in ips:
            self._save([*ips, ip])

    def remove(self, ip: str) -> None:
        """Drop `ip` from the file; an address that was never saved is not an error."""
        ips = self.load()
        if ip in ips:
            self._save([i for i in ips if i != ip])

    def clear(self) -> None:
        """Empty the file (it stays in place, so the boot job finds nothing to do)."""
        if self.path.exists():
            self._save([])


class PfFirewall:
    """Blocks IPs through a pf table inside a dedicated anchor, driven by `pfctl` (needs root).

    The table and its anchor rule live in the kernel, so blocks outlive this process and
    `flush` empties the table without unloading the rule or disabling pf. With a `store`,
    every successful change is also saved there so the boot job can reapply it.
    """

    def __init__(
        self,
        runner: Runner = run_command,
        anchor: str = ANCHOR,
        table: str = TABLE,
        store: BlockList | None = None,
    ) -> None:
        self._run = runner
        self.anchor = anchor
        self.table = table
        self.store = store
        self._ready = False

    def _persist(self, result: ActionResult, save: Callable[[BlockList], None]) -> ActionResult:
        # The kernel change already happened; a failed save is reported, not turned into a failure.
        if not result.ok or self.store is None:
            return result
        try:
            save(self.store)
        except OSError as exc:
            detail = "; ".join(filter(None, (result.detail, f"not saved for reboot: {exc}")))
            return dataclasses.replace(result, detail=detail)
        return result

    def _table_cmd(self, *args: str) -> list[str]:
        return [PFCTL, "-a", self.anchor, "-t", self.table, "-T", *args]

    async def is_enabled(self) -> bool | None:
        """Run `pfctl -s info`: True if pf is enabled, False if disabled, None if unrecognised."""
        return parse_pf_status((await self._run([PFCTL, "-s", "info"])).stdout)

    async def anchor_reachable(self) -> bool:
        """True if the main ruleset evaluates `com.apple/*`, the parent of our anchor."""
        res = await self._run([PFCTL, "-s", "rules"])
        return PARENT_ANCHOR_RULE in res.stdout

    async def anchor_loaded(self) -> bool:
        """True if our anchor already holds the rule referencing the block table."""
        res = await self._run([PFCTL, "-a", self.anchor, "-s", "rules"])
        return f"<{self.table}>" in res.stdout

    async def _load_anchor(self) -> None:
        rules = anchor_rules(self.table)
        for argv in (
            [PFCTL, "-a", self.anchor, "-n", "-f", "-"],
            [PFCTL, "-a", self.anchor, "-f", "-"],
        ):
            res = await self._run(argv, stdin=rules)
            problems = meaningful_stderr(res.stderr)
            if res.returncode != 0 or problems:
                detail = "; ".join(problems) or f"exit {res.returncode}"
                raise FirewallError(f"pfctl rejected anchor rules: {detail}")
        if not await self.anchor_loaded():
            raise FirewallError(f"anchor {self.anchor} did not retain its rules after loading")

    async def _enable(self) -> None:
        if await self.is_enabled():
            return
        # -E takes a reference (safe alongside other pf users); -e is the plain fallback.
        for flag in ("-E", "-e"):
            await self._run([PFCTL, flag])
            if await self.is_enabled():
                return
        raise FirewallError("pf is still disabled after `pfctl -E` / `pfctl -e`")

    async def setup(self) -> None:
        """Load the anchor rules and enable pf. Blocks deliberately outlive this process.

        Runs once per instance (guarded by `_ready`). Loads the rules only if the anchor lacks
        them, then enables pf with `pfctl -E`, falling back to `-e`; pf stays enabled afterwards.
        Raises FirewallError if the main ruleset skips `com.apple/*`, pfctl rejects the rules,
        or pf stays disabled.
        """
        if self._ready:
            return
        if not await self.anchor_reachable():
            raise FirewallError(
                f"the main pf ruleset does not evaluate {PARENT_ANCHOR_RULE}, so rules in "
                f"{self.anchor} would be ignored; restore the default with: "
                "sudo pfctl -f /etc/pf.conf"
            )
        if not await self.anchor_loaded():
            await self._load_anchor()
        await self._enable()
        self._ready = True

    async def _table_op(
        self, kind: ActionKind, op: str, raw_ip: str, needs_setup: bool = True
    ) -> ActionResult:
        try:
            ip = validate_ip(raw_ip)
            if needs_setup:
                await self.setup()
        except (ValueError, FirewallError) as exc:
            return ActionResult(kind, raw_ip, False, str(exc))
        res = await self._run(self._table_cmd(op, ip))
        return ActionResult(kind, ip, res.returncode == 0, "; ".join(meaningful_stderr(res.stderr)))

    async def block(self, ip: str) -> ActionResult:
        """Add `ip` to the block table (`pfctl -T add`), running `setup` first.

        Loopback, unspecified and multicast addresses are refused. Invalid input and setup
        failures come back as a failed ActionResult rather than raising. On success `pfctl -k`
        also kills existing states between the address and anywhere, so open sockets die too.
        """
        result = await self._table_op(ActionKind.BLOCK_IP, "add", ip)
        if result.ok:
            # Table rules only see new flows; drop existing state so open sockets die too.
            any_net = "::/0" if ":" in result.target else "0.0.0.0/0"
            await self._run([PFCTL, "-k", any_net, "-k", result.target])
        return self._persist(result, lambda store: store.add(result.target))

    async def unblock(self, ip: str) -> ActionResult:
        """Remove `ip` from the block table (`pfctl -T delete`) without running `setup`.

        Invalid input comes back as a failed ActionResult rather than raising.
        """
        # Removing must never depend on (re)loading rules, or a failed setup could strand a block.
        result = await self._table_op(ActionKind.UNBLOCK_IP, "delete", ip, needs_setup=False)
        return self._persist(result, lambda store: store.remove(result.target))

    async def blocked(self) -> list[str]:
        """List the addresses in the block table (`pfctl -T show`); empty if there are none.

        Errors are not raised, so a missing table or anchor also yields an empty list.
        """
        res = await self._run(self._table_cmd("show"))
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]

    async def flush(self) -> ActionResult:
        """Remove every address from the block table (`pfctl -T flush`).

        The anchor rule stays loaded and pf stays enabled. A table that was never created
        counts as success. Existing states are not touched.
        """
        res = await self._run(self._table_cmd("flush"))
        if table_missing(res.stderr):
            result = ActionResult(ActionKind.UNBLOCK_IP, self.table, True, "table already empty")
        else:
            detail = "; ".join(meaningful_stderr(res.stderr))
            result = ActionResult(ActionKind.UNBLOCK_IP, self.table, res.returncode == 0, detail)
        return self._persist(result, BlockList.clear)


_SIGNALS: dict[ActionKind, signal.Signals] = {
    ActionKind.SUSPEND: signal.SIGSTOP,
    ActionKind.RESUME: signal.SIGCONT,
    ActionKind.KILL: signal.SIGKILL,
}


class ProcessController:
    """Suspends, resumes or kills processes by pid with SIGSTOP, SIGCONT and SIGKILL."""

    def __init__(self, kill: Callable[[int, int], None] = os.kill) -> None:
        self._kill = kill
        self._protected = {0, 1, os.getpid(), os.getppid()}

    def signal(self, kind: ActionKind, pid: int) -> ActionResult:
        """Send the signal for `kind` (SUSPEND, RESUME or KILL) to `pid`.

        Refuses pids 0 and 1, this process, its parent and negative pids (process groups).
        A missing process or insufficient privilege is reported in the ActionResult, not raised.
        """
        sig = _SIGNALS[kind]
        if pid in self._protected or pid < 0:
            return ActionResult(kind, str(pid), False, "protected process")
        try:
            self._kill(pid, sig)
        except ProcessLookupError:
            return ActionResult(kind, str(pid), False, "no such process")
        except PermissionError:
            return ActionResult(kind, str(pid), False, "permission denied (run as root)")
        return ActionResult(kind, str(pid), True, sig.name)

    def suspend(self, pid: int) -> ActionResult:
        """Stop a process with SIGSTOP; it cannot catch or ignore this."""
        return self.signal(ActionKind.SUSPEND, pid)

    def resume(self, pid: int) -> ActionResult:
        """Continue a stopped process with SIGCONT."""
        return self.signal(ActionKind.RESUME, pid)

    def kill(self, pid: int) -> ActionResult:
        """Terminate a process with SIGKILL; it cannot catch or ignore this."""
        return self.signal(ActionKind.KILL, pid)
