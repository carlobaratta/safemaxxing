"""pf table management and process control (SIGSTOP / SIGCONT / SIGKILL)."""

from __future__ import annotations

import asyncio
import ipaddress
import os
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
    return CommandResult(proc.returncode or 0, out.decode(errors="replace"), err.decode("replace"))


def validate_ip(raw: str) -> str:
    """Normalise an address and refuse ones whose blocking would break the host."""
    ip = ipaddress.ip_address(raw.strip())
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        raise ValueError(f"refusing to block {ip}")
    return str(ip)


def is_root() -> bool:
    return os.geteuid() == 0


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

    async def setup(self) -> None:
        """Load the anchor rules and enable pf. Blocks deliberately outlive this process."""
        if self._ready:
            return
        current = await self._run([PFCTL, "-a", self.anchor, "-s", "rules"])
        if f"<{self.table}>" not in current.stdout:
            loaded = await self._run(
                [PFCTL, "-a", self.anchor, "-f", "-"], stdin=anchor_rules(self.table)
            )
            if loaded.returncode != 0:
                raise FirewallError(f"pfctl could not load anchor: {loaded.stderr.strip()}")
        enabled = await self._run([PFCTL, "-E"])
        if enabled.returncode != 0 and "already enabled" not in enabled.stderr:
            raise FirewallError(f"pfctl could not enable pf: {enabled.stderr.strip()}")
        self._ready = True

    async def _table_op(self, kind: ActionKind, op: str, raw_ip: str) -> ActionResult:
        try:
            ip = validate_ip(raw_ip)
            await self.setup()
        except (ValueError, FirewallError) as exc:
            return ActionResult(kind, raw_ip, False, str(exc))
        res = await self._run(self._table_cmd(op, ip))
        return ActionResult(kind, ip, res.returncode == 0, res.stderr.strip())

    async def block(self, ip: str) -> ActionResult:
        return await self._table_op(ActionKind.BLOCK_IP, "add", ip)

    async def unblock(self, ip: str) -> ActionResult:
        return await self._table_op(ActionKind.UNBLOCK_IP, "delete", ip)

    async def blocked(self) -> list[str]:
        res = await self._run(self._table_cmd("show"))
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]

    async def flush(self) -> ActionResult:
        res = await self._run(self._table_cmd("flush"))
        return ActionResult(ActionKind.UNBLOCK_IP, self.table, res.returncode == 0, res.stderr)


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
