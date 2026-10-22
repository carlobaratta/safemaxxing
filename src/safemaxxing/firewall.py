"""pf table management and process control (SIGSTOP / SIGCONT / SIGKILL)."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import signal
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from safemaxxing.models import ActionKind, ActionResult

PFCTL = "/sbin/pfctl"
TABLE = "safemaxxing_block"
# The stock /etc/pf.conf evaluates `anchor "com.apple/*"`, so rules here apply without editing it.
ANCHOR = "com.apple/safemaxxing"


def anchor_rules(table: str = TABLE) -> str:
    # No `table` definition: reloading a ruleset that defines a table resets its contents.
    return f"block drop out quick from any to <{table}>\n"


class FirewallError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class Runner(Protocol):
    async def __call__(self, argv: Sequence[str], stdin: str | None = None) -> CommandResult: ...


async def run_command(argv: Sequence[str], stdin: str | None = None) -> CommandResult:
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
)
PARENT_ANCHOR_RULE = 'anchor "com.apple/*"'


# How Darwin's pfctl answers a query for an anchor that has never been created.
_ANCHOR_MISSING = ("DIOCGETRULES: Invalid argument", "Anchor does not exist")


def anchor_missing(stderr: str) -> bool:
    return any(marker in stderr for marker in _ANCHOR_MISSING)


def parse_pf_status(info: str) -> bool | None:
    """Parse `pfctl -s info`: True if Enabled, False if Disabled, None if unrecognised."""
    match = _STATUS_RE.search(info)
    return None if match is None else match.group(1) == "Enabled"


def meaningful_stderr(stderr: str) -> list[str]:
    return [
        line.strip()
        for line in stderr.splitlines()
        if line.strip() and not any(b in line for b in _BENIGN_STDERR)
    ]


class PfFirewall:
    def __init__(
        self, runner: Runner = run_command, anchor: str = ANCHOR, table: str = TABLE
    ) -> None:
        self._run = runner
        self.anchor = anchor
        self.table = table
        self._ready = False

    def _table_cmd(self, *args: str) -> list[str]:
        return [PFCTL, "-a", self.anchor, "-t", self.table, "-T", *args]

    async def is_enabled(self) -> bool | None:
        return parse_pf_status((await self._run([PFCTL, "-s", "info"])).stdout)

    async def anchor_reachable(self) -> bool:
        """True if the main ruleset evaluates `com.apple/*`, the parent of our anchor."""
        res = await self._run([PFCTL, "-s", "rules"])
        return PARENT_ANCHOR_RULE in res.stdout

    async def anchor_loaded(self) -> bool:
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
        """Load the anchor rules and enable pf. Blocks deliberately outlive this process."""
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

    async def _table_op(self, kind: ActionKind, op: str, raw_ip: str) -> ActionResult:
        try:
            ip = validate_ip(raw_ip)
            await self.setup()
        except (ValueError, FirewallError) as exc:
            return ActionResult(kind, raw_ip, False, str(exc))
        res = await self._run(self._table_cmd(op, ip))
        return ActionResult(kind, ip, res.returncode == 0, "; ".join(meaningful_stderr(res.stderr)))

    async def block(self, ip: str) -> ActionResult:
        result = await self._table_op(ActionKind.BLOCK_IP, "add", ip)
        if result.ok:
            # Table rules only see new flows; drop existing state so open sockets die too.
            any_net = "::/0" if ":" in result.target else "0.0.0.0/0"
            await self._run([PFCTL, "-k", any_net, "-k", result.target])
        return result

    async def unblock(self, ip: str) -> ActionResult:
        return await self._table_op(ActionKind.UNBLOCK_IP, "delete", ip)

    async def blocked(self) -> list[str]:
        res = await self._run(self._table_cmd("show"))
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]

    async def flush(self) -> ActionResult:
        res = await self._run(self._table_cmd("flush"))
        detail = "; ".join(meaningful_stderr(res.stderr))
        return ActionResult(ActionKind.UNBLOCK_IP, self.table, res.returncode == 0, detail)


_SIGNALS: dict[ActionKind, signal.Signals] = {
    ActionKind.SUSPEND: signal.SIGSTOP,
    ActionKind.RESUME: signal.SIGCONT,
    ActionKind.KILL: signal.SIGKILL,
}


class ProcessController:
    def __init__(self, kill: Callable[[int, int], None] = os.kill) -> None:
        self._kill = kill
        self._protected = {0, 1, os.getpid(), os.getppid()}

    def signal(self, kind: ActionKind, pid: int) -> ActionResult:
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
        return self.signal(ActionKind.SUSPEND, pid)

    def resume(self, pid: int) -> ActionResult:
        return self.signal(ActionKind.RESUME, pid)

    def kill(self, pid: int) -> ActionResult:
        return self.signal(ActionKind.KILL, pid)
