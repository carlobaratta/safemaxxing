"""pf table management and process control (SIGSTOP / SIGCONT / SIGKILL)."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import fcntl
import ipaddress
import os
import re
import signal
import stat
import tempfile
import time
from collections.abc import AsyncIterator, Callable, Sequence
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
# The `pfctl -E` token safemaxxing holds, written by this module and by the boot job.
PF_REFERENCE = STATE_DIR / "pf-reference"


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
# The summary pfctl prints after every `-T` command that succeeds ("1 table created.",
# "2/3 addresses added.", "no changes."): an exit code of 0 already says it worked.
_TABLE_SUMMARY_RE = re.compile(
    r"^(?:no changes|\d+(?:/\d+)? (?:tables?|addresses) "
    r"(?:created|added|deleted|changed|zeroed|expired))\.?$"
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


_RUNTIME_RE = re.compile(r"^Status: Enabled for (\d+) days (\d+):(\d\d):(\d\d)", re.MULTILINE)
_TOKEN_RE = re.compile(r"^Token : (\d{1,20})\s*$", re.MULTILINE)


def parse_pf_runtime(info: str) -> int | None:
    """Seconds pf has been running, from `pfctl -s info`'s "Enabled for D days HH:MM:SS"."""
    match = _RUNTIME_RE.search(info)
    if match is None:
        return None
    days, hours, minutes, seconds = (int(g) for g in match.groups())
    return ((days * 24 + hours) * 60 + minutes) * 60 + seconds


def parse_pf_token(output: str) -> str | None:
    """The reference token `pfctl -E` prints ("Token : N"), or None. 0 means none was issued."""
    match = _TOKEN_RE.search(output)
    if match is None:
        return None
    value = int(match.group(1))
    return str(value) if 0 < value < 2**64 else None


@dataclass(frozen=True, slots=True)
class PfRecord:
    """A saved `pfctl -E` token and the wall-clock instant pf's current run began."""

    token: str
    started: float


class PfReference:
    """The one pf enable reference safemaxxing holds, saved so a later process can release it.

    pf on macOS counts references: `pfctl -E` enables it and returns a token, and
    `pfctl -X <token>` drops that reference, so pf stops only when no holder is left. A token
    lives only for one run of pf: a reboot or a `pfctl -d` by anyone invalidates every token,
    and the kernel may hand the same value to another holder later. So the record also keeps
    when pf's run began (from "Enabled for ..."), and a token is used only while pf is still in
    that same run; otherwise it is forgotten, never released. A restart within TOLERANCE_S of
    the moment the record was taken cannot be told apart from no restart.

    The record is `token=N` and `status=<pfctl -s info status line>`, root-owned and 0600; the
    status line is read against the file's mtime. The boot job writes the same format.
    """

    # pfctl prints the runtime to the second; allow for that and the time to write the file.
    TOLERANCE_S = 5.0
    LOCK_TIMEOUT_S = 10.0

    def __init__(
        self,
        path: Path = PF_REFERENCE,
        owner_uid: int = 0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = path
        self.lock_path = path.with_name(path.name + ".lock")
        self.owner_uid = owner_uid
        self._clock = clock

    @contextlib.asynccontextmanager
    async def locked(self) -> AsyncIterator[None]:
        """Hold an exclusive lock so a block and a flush in two processes cannot interleave.

        Not reentrant. Raises FirewallError after LOCK_TIMEOUT_S.
        """
        self.lock_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(self.lock_path, flags, 0o600)
        try:
            deadline = time.monotonic() + self.LOCK_TIMEOUT_S
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() > deadline:
                        raise FirewallError(
                            f"another safemaxxing process holds {self.lock_path}"
                        ) from None
                    await asyncio.sleep(0.02)
            yield
        finally:
            os.close(fd)  # also releases the flock

    def load(self) -> PfRecord | None:
        """The saved record, or None if missing, malformed or not root-owned and private."""
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return None
        with os.fdopen(fd) as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid != self.owner_uid or st.st_mode & 0o077:
                return None
            fields = dict(line.split("=", 1) for line in fh.read(4096).splitlines() if "=" in line)
        token = parse_pf_token(f"Token : {fields.get('token', '')}")
        runtime = parse_pf_runtime(fields.get("status", ""))
        if token is None or runtime is None:
            return None
        return PfRecord(token, st.st_mtime - runtime)

    def _save(self, token: str, info: str) -> None:
        status = next(line for line in info.splitlines() if line.startswith("Status: Enabled"))
        self.path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".pf-reference-")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(f"token={token}\nstatus={status.strip()}\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise

    def forget(self) -> None:
        """Delete the record; a missing one is not an error."""
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()

    def _live(self, info: str) -> PfRecord | None:
        """The record, if pf is still in the run it was taken in (so the token is ours)."""
        record = self.load()
        runtime = parse_pf_runtime(info)
        if record is None or runtime is None:
            return None
        started = self._clock() - runtime
        return record if abs(started - record.started) <= self.TOLERANCE_S else None

    async def acquire(self, run: Runner) -> str:
        """Make sure pf is enabled and safemaxxing holds a reference to it.

        With a live record, nothing runs but `pfctl -s info`. Otherwise `pfctl -E` takes a new
        reference, even when pf is already on, so another holder's `pfctl -X` cannot turn it
        off under our rules; its token is saved. Falls back to `pfctl -e` (no token, so nothing
        to release later). Returns a note for the user ("" when all went to plan); raises
        FirewallError if pf stays disabled.
        """
        info = (await run([PFCTL, "-s", "info"])).stdout
        if parse_pf_status(info) and self._live(info) is not None:
            return ""
        res = await run([PFCTL, "-E"])
        token = parse_pf_token(f"{res.stdout}\n{res.stderr}")
        info = (await run([PFCTL, "-s", "info"])).stdout
        if parse_pf_status(info):
            if token is None or parse_pf_runtime(info) is None:
                return "pf enabled, but no pfctl -E token was recorded: flush cannot release it"
            try:
                self._save(token, info)
            except OSError as exc:
                return f"pf enabled, but its reference was not saved: {exc}"
            return ""
        await run([PFCTL, "-e"])
        if parse_pf_status((await run([PFCTL, "-s", "info"])).stdout):
            return "pf enabled with pfctl -e (no reference): flush cannot release it"
        raise FirewallError("pf is still disabled after `pfctl -E` / `pfctl -e`")

    async def release(self, run: Runner) -> str:
        """Drop safemaxxing's reference with `pfctl -X`; never `pfctl -d`.

        pf stops only if no other program holds a reference. A token from an earlier run of pf
        is forgotten without being released. Returns what happened, for the user.
        """
        info = (await run([PFCTL, "-s", "info"])).stdout
        if self.load() is None:
            return "pf left as is: safemaxxing holds no recorded reference"
        if parse_pf_status(info) is False:
            self.forget()
            return "pf already disabled"
        record = self._live(info)
        if record is None:
            if parse_pf_runtime(info) is None:
                return "pf left as is: its status could not be read"
            self.forget()
            return "pf left as is: it was restarted since safemaxxing enabled it"
        res = await run([PFCTL, "-X", record.token])
        if res.returncode != 0:
            detail = "; ".join(meaningful_stderr(res.stderr)) or f"exit {res.returncode}"
            return f"pf left as is: pfctl -X failed: {detail}"
        self.forget()
        if parse_pf_status((await run([PFCTL, "-s", "info"])).stdout) is False:
            return "released safemaxxing's pf reference; pf disabled (no other holder)"
        return "released safemaxxing's pf reference; pf stays enabled for its other holders"


def meaningful_stderr(stderr: str) -> list[str]:
    """Return stripped stderr lines that are real errors, dropping benign Darwin pfctl chatter."""
    return [
        line.strip()
        for line in stderr.splitlines()
        if line.strip()
        and not any(b in line for b in _BENIGN_STDERR)
        and not _TABLE_SUMMARY_RE.match(line.strip())
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
    `flush` empties the table without unloading the rule. With a `store`, every successful
    change is also saved there so the boot job can reapply it. With a `reference`, pf is
    enabled through a saved `pfctl -E` token that `flush` gives back once nothing of
    safemaxxing needs pf; without one, pf is enabled and never released.
    """

    def __init__(
        self,
        runner: Runner = run_command,
        anchor: str = ANCHOR,
        table: str = TABLE,
        store: BlockList | None = None,
        reference: PfReference | None = None,
    ) -> None:
        self._run = runner
        self.anchor = anchor
        self.table = table
        self.store = store
        self.reference = reference
        self._anchor_ready = False

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

    async def _enable(self) -> str:
        if self.reference is not None:
            return await self.reference.acquire(self._run)
        if await self.is_enabled():
            return ""
        # -E takes a reference (safe alongside other pf users); -e is the plain fallback.
        for flag in ("-E", "-e"):
            await self._run([PFCTL, flag])
            if await self.is_enabled():
                return ""
        raise FirewallError("pf is still disabled after `pfctl -E` / `pfctl -e`")

    async def setup(self) -> str:
        """Load the anchor rules and enable pf. Blocks deliberately outlive this process.

        Loads the rules only if the anchor lacks them (checked once per instance). pf is
        checked on every call, because another process may have turned it off since: a
        long-running TUI or daemon must not add blocks to a pf that is off. Returns a note for
        the user, "" when there is none. Raises FirewallError if the main ruleset skips
        `com.apple/*`, pfctl rejects the rules, or pf stays disabled.
        """
        if not self._anchor_ready:
            if not await self.anchor_reachable():
                raise FirewallError(
                    f"the main pf ruleset does not evaluate {PARENT_ANCHOR_RULE}, so rules in "
                    f"{self.anchor} would be ignored; restore the default with: "
                    "sudo pfctl -f /etc/pf.conf"
                )
            if not await self.anchor_loaded():
                await self._load_anchor()
            self._anchor_ready = True
        return await self._enable()

    async def _table_op(
        self, kind: ActionKind, op: str, raw_ip: str, needs_setup: bool = True
    ) -> ActionResult:
        note = ""
        try:
            ip = validate_ip(raw_ip)
            if needs_setup:
                note = await self.setup()
        except (ValueError, FirewallError) as exc:
            return ActionResult(kind, raw_ip, False, str(exc))
        res = await self._run(self._table_cmd(op, ip))
        detail = "; ".join([*meaningful_stderr(res.stderr), *filter(None, [note])])
        return ActionResult(kind, ip, res.returncode == 0, detail)

    async def block(self, ip: str) -> ActionResult:
        """Add `ip` to the block table (`pfctl -T add`), running `setup` first.

        Loopback, unspecified and multicast addresses are refused. Invalid input and setup
        failures come back as a failed ActionResult rather than raising. On success `pfctl -k`
        also kills existing states between the address and anywhere, so open sockets die too.
        With a `reference`, runs under its lock, so a `flush` elsewhere cannot release pf
        between enabling it and adding the address.
        """
        if self.reference is None:
            return await self._block(ip)
        try:
            async with self.reference.locked():
                return await self._block(ip)
        except (OSError, FirewallError) as exc:
            return ActionResult(ActionKind.BLOCK_IP, ip, False, str(exc))

    async def _block(self, ip: str) -> ActionResult:
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

        The anchor rule stays loaded. A table that was never created counts as success.
        Existing states are not touched. With a `reference`, safemaxxing's pf reference is then
        released (`pfctl -X`, never `pfctl -d`) if the table is empty and the anchor holds only
        the block rule, not Paranoia Mode's ruleset; pf stops only if nobody else holds it.
        The release never turns a flush into a failure: what happened is in `detail`.
        """
        if self.reference is None:
            return await self._flush()
        try:
            async with self.reference.locked():
                result = await self._flush()
                if not result.ok:
                    return result
                note = await self._release_if_unused(self.reference)
        except (OSError, FirewallError) as exc:
            return ActionResult(ActionKind.UNBLOCK_IP, self.table, False, str(exc))
        detail = "; ".join(filter(None, (result.detail, note)))
        return dataclasses.replace(result, detail=detail)

    async def _release_if_unused(self, reference: PfReference) -> str:
        if await self.blocked():
            return "pf reference kept: the block table is not empty"
        res = await self._run([PFCTL, "-a", self.anchor, "-s", "rules"])
        rules = [line for line in res.stdout.splitlines() if line.strip()]
        if res.returncode != 0 and not anchor_missing(res.stderr):
            return "pf reference kept: the anchor's rules could not be read"
        if len(rules) > 1:
            return "pf reference kept: Paranoia Mode's rules are loaded"
        return await reference.release(self._run)

    async def _flush(self) -> ActionResult:
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
