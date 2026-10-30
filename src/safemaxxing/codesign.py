"""Code-signing identity of a binary (`codesign -dv`, for the TUI's inspector) and, for
Paranoia Mode, of a *running process*, read from the kernel with `csops(2)`.

What the kernel knows about a live process is what matters before granting it the network:
the CDHash of the code it actually mapped, whether every page it ran so far validated
(`CS_VALID`), whether it runs with the hardened runtime and whether a debugger got in. These
come from `csops`, a stable libsystem call (used by `codesign` itself) whose constants live in
xnu's `bsd/sys/codesign.h`, not in the public SDK. Measured on macOS 27.0.1 as a normal user:
it answers for other users' processes and root daemons alike; the Team ID comes back behind an
8-byte header; the entitlements blob has magic 0xfade7171 and ends with a NUL; and errno is
stale whenever the call succeeds, so it is read only on failure.
"""

from __future__ import annotations

import asyncio
import ctypes
import errno
import os
import plistlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

import psutil

from safemaxxing.firewall import Runner, run_command
from safemaxxing.network import enclosing_apps

CODESIGN = "/usr/bin/codesign"


def signing_target(exe_path: str) -> str:
    """What to ask codesign about: the outermost .app holding `exe_path`, else the binary.

    A browser helper's own signature is the vendor's too, but the outer app names the product.
    """
    apps = enclosing_apps(exe_path)
    return apps[0] if apps else exe_path


def parse_codesign(stderr: str, returncode: int) -> str:
    """One-line identity from `codesign -dv --verbose=2` output (it writes to stderr).

    The leaf `Authority=` line wins (e.g. `Developer ID Application: Brave Software, Inc.
    (KL8N8XSYF4)`, or `Software Signing` for Apple's binaries); then `ad-hoc`, `unsigned`,
    or `unknown` when codesign failed for another reason.
    """
    if "not signed at all" in stderr:
        return "unsigned"
    lines = [line.strip() for line in stderr.splitlines()]
    for line in lines:
        if line.startswith("Authority="):
            return line.removeprefix("Authority=")
    if "Signature=adhoc" in lines:
        return "ad-hoc"
    return "unknown" if returncode != 0 else "signed, no authority"


async def signing_identity(
    exe_path: str, runner: Runner = run_command, timeout_s: float = 3.0
) -> str:
    """The signing identity of `exe_path`'s app (see `parse_codesign`); `unknown` if codesign
    is missing or does not answer within `timeout_s`."""
    argv = [CODESIGN, "-dv", "--verbose=2", signing_target(exe_path)]
    try:
        result = await asyncio.wait_for(runner(argv), timeout_s)
    except (TimeoutError, OSError):
        return "unknown"
    return parse_codesign(result.stderr, result.returncode)


# csops(2) operations and code-signing flags, from xnu's bsd/sys/codesign.h.
CS_OPS_STATUS = 0
CS_OPS_CDHASH = 5
CS_OPS_ENTITLEMENTS_BLOB = 7
CS_OPS_TEAMID = 14
CS_VALID = 0x00000001
CS_ADHOC = 0x00000002
CS_GET_TASK_ALLOW = 0x00000004
CS_HARD = 0x00000100
CS_KILL = 0x00000200
CS_RUNTIME = 0x00010000
CS_PLATFORM_BINARY = 0x04000000
CS_DEBUGGED = 0x10000000
CS_SIGNED = 0x20000000
CS_CDHASH_LEN = 20
_ENTITLEMENTS_MAGIC = 0xFADE7171

type Csops = Callable[[int, int, ctypes.Array[ctypes.c_char], int], tuple[int, int]]


def _load_csops() -> Csops | None:
    """Bind libsystem's `csops`, or None off macOS. Returns (rc, errno) per call."""
    try:
        fn = ctypes.CDLL(None, use_errno=True).csops
    except (OSError, AttributeError):
        return None
    fn.restype = ctypes.c_int
    fn.argtypes = (ctypes.c_int, ctypes.c_uint, ctypes.c_void_p, ctypes.c_size_t)

    def call(pid: int, op: int, buf: ctypes.Array[ctypes.c_char], size: int) -> tuple[int, int]:
        rc = int(fn(pid, op, buf, size))
        return rc, ctypes.get_errno() if rc == -1 else 0

    return call


_CSOPS = _load_csops()


@dataclass(frozen=True, slots=True)
class CodeStatus:
    """What the kernel holds about a running process's code signature."""

    pid: int
    flags: int
    cdhash: str | None
    team_id: str | None
    # Entitlement keys whose value is true (the only kind the policy below looks at).
    entitlements: frozenset[str]

    def has(self, flag: int) -> bool:
        """Whether every bit of `flag` is set."""
        return self.flags & flag == flag

    @property
    def platform(self) -> bool:
        """An Apple platform binary: no Team ID, trusted by the OS itself."""
        return self.has(CS_PLATFORM_BINARY)


def _entitlements(pid: int, csops: Csops) -> frozenset[str] | None:
    probe = ctypes.create_string_buffer(8)
    rc, err = csops(pid, CS_OPS_ENTITLEMENTS_BLOB, probe, 8)
    if rc == 0:
        return frozenset()  # fits in 8 bytes: no entitlements at all
    if err != errno.ERANGE:
        return None
    size = int.from_bytes(probe.raw[4:8], "big")
    blob = ctypes.create_string_buffer(size)
    rc, _ = csops(pid, CS_OPS_ENTITLEMENTS_BLOB, blob, size)
    if rc != 0 or int.from_bytes(blob.raw[:4], "big") != _ENTITLEMENTS_MAGIC:
        return None
    length = int.from_bytes(blob.raw[4:8], "big")
    try:
        data = plistlib.loads(blob.raw[8:length].rstrip(b"\x00"))
    except (plistlib.InvalidFileException, ValueError):
        return None
    return frozenset(k for k, v in data.items() if v is True) if isinstance(data, dict) else None


def kernel_code_status(pid: int, csops: Csops | None = _CSOPS) -> CodeStatus | None:
    """The kernel's view of `pid`'s code; None if it is gone, unreadable or off macOS."""
    if csops is None:
        return None
    status = ctypes.create_string_buffer(4)
    rc, _ = csops(pid, CS_OPS_STATUS, status, 4)
    if rc != 0:
        return None
    flags = int.from_bytes(status.raw, "little")
    cd = ctypes.create_string_buffer(CS_CDHASH_LEN)
    rc, _ = csops(pid, CS_OPS_CDHASH, cd, CS_CDHASH_LEN)
    cdhash = cd.raw.hex() if rc == 0 else None
    team = ctypes.create_string_buffer(8 + 64)
    rc, _ = csops(pid, CS_OPS_TEAMID, team, len(team))
    # Behind an 8-byte header, NUL-terminated; ENOENT for platform binaries, which have none.
    team_id = team.raw[8:].split(b"\x00", 1)[0].decode("ascii", "replace") if rc == 0 else None
    entitlements = _entitlements(pid, csops)
    if entitlements is None:
        return None
    return CodeStatus(pid, flags, cdhash, team_id or None, entitlements)


class Strictness(StrEnum):
    """How much injection surface a leased process may carry."""

    STANDARD = "standard"
    STRICT = "strict"


# Entitlements that open a process to code that is not its own: each maps to whether it is
# refused under STANDARD (STRICT refuses them all). Brave's network helper carries
# disable-library-validation (macOS 27.0.1), so refusing it by default would break the very
# calls Paranoia Mode is meant to keep working.
INJECTION_ENTITLEMENTS: dict[str, bool] = {
    "com.apple.security.get-task-allow": True,
    "com.apple.security.cs.allow-dyld-environment-variables": True,
    "com.apple.security.cs.disable-library-validation": False,
    "com.apple.security.cs.allow-unsigned-executable-memory": False,
    "com.apple.security.cs.disable-executable-page-protection": False,
}
_TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")


@dataclass(frozen=True, slots=True)
class Verdict:
    """Whether a process may be granted the network, why not, and what to flag anyway."""

    ok: bool
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    status: CodeStatus | None = None


def assess(
    status: CodeStatus, pinned_team: str | None, strictness: Strictness = Strictness.STANDARD
) -> Verdict:
    """Judge a process's kernel code status against the policy and its app's pinned Team ID.

    Required: valid pages so far, signed, not ad-hoc, hardened runtime, no debugger, not
    debuggable, and (for third-party code) the pinned Team ID.
    """
    reasons: list[str] = []
    warnings: list[str] = []
    checks = (
        (status.has(CS_VALID), "code signature no longer valid (CS_VALID cleared)"),
        (status.has(CS_SIGNED), "not signed"),
        (not status.has(CS_ADHOC), "ad-hoc signature"),
        (status.has(CS_RUNTIME) or status.platform, "no hardened runtime"),
        (not status.has(CS_DEBUGGED), "a debugger is or was attached (CS_DEBUGGED)"),
        (not status.has(CS_GET_TASK_ALLOW), "debuggable (CS_GET_TASK_ALLOW)"),
    )
    reasons += [why for passed, why in checks if not passed]
    if not status.has(CS_KILL):
        warnings.append("an invalid page would not kill it (no CS_KILL): re-verified on a timer")
    if not status.platform:
        if status.team_id is None:
            reasons.append("no Team ID")
        elif pinned_team is not None and status.team_id != pinned_team:
            reasons.append(f"Team ID {status.team_id} does not match the pinned {pinned_team}")
    for key, refused_in_standard in INJECTION_ENTITLEMENTS.items():
        if key in status.entitlements:
            short = key.rsplit(".", 1)[-1]
            if refused_in_standard or strictness is Strictness.STRICT:
                reasons.append(f"entitlement {short}")
            else:
                warnings.append(f"entitlement {short}")
    return Verdict(not reasons, tuple(reasons), tuple(warnings), status)


def team_requirement(team_id: str) -> str:
    """A code requirement satisfied only by Apple-anchored code of `team_id`."""
    if not _TEAM_ID_RE.match(team_id):
        raise ValueError(f"not a Team ID: {team_id!r}")
    return f'anchor apple generic and certificate leaf[subject.OU] = "{team_id}"'


async def satisfies(
    target: str, requirement: str, runner: Runner = run_command, timeout_s: float = 3.0
) -> bool:
    """`codesign --verify -R=<requirement> <target>`: a pid checks the running code against
    its file on disk (the kernel CDHash included), a path checks the bundle's seal. 30-50 ms.

    No `--strict`: it rejects a stock Brave install for a Finder xattr (macOS 27.0.1).
    """
    argv = [CODESIGN, "--verify", f"-R={requirement}", target]
    try:
        result = await asyncio.wait_for(runner(argv), timeout_s)
    except (TimeoutError, OSError):
        return False
    return result.returncode == 0


def start_time(pid: int) -> float | None:
    """When `pid` started, to notice a pid reused while it was being checked."""
    try:
        return psutil.Process(pid).create_time()
    except psutil.Error:
        return None


class CodeVerifier:
    """Verifies a process before it is granted the network: kernel status and policy first
    (no subprocess), then `codesign` on the running pid and on its app's seal (cached until
    the bundle's signature file changes)."""

    def __init__(
        self,
        strictness: Strictness = Strictness.STANDARD,
        status: Callable[[int], CodeStatus | None] = kernel_code_status,
        runner: Runner = run_command,
        started: Callable[[int], float | None] = start_time,
    ) -> None:
        self.strictness = strictness
        self._status = status
        self._run = runner
        self._started = started
        self._seals: dict[str, tuple[float, bool]] = {}

    async def _sealed(self, app_path: str, requirement: str) -> bool:
        try:
            stamp = os.stat(f"{app_path}/Contents/_CodeSignature/CodeResources").st_mtime
        except OSError:
            return False
        cached = self._seals.get(app_path)
        if cached is not None and cached[0] == stamp:
            return cached[1]
        ok = await satisfies(app_path, requirement, self._run)
        self._seals[app_path] = (stamp, ok)
        return ok

    async def verify(self, pid: int, pinned_team: str | None, app_path: str | None) -> Verdict:
        """Verdict for `pid`; a pid that exits or is reused during the check is refused."""
        before = self._started(pid)
        status = self._status(pid)
        if before is None or status is None:
            return Verdict(False, ("process gone or unreadable",))
        verdict = assess(status, pinned_team, self.strictness)
        if verdict.ok and not status.platform and status.team_id is not None:
            requirement = team_requirement(pinned_team or status.team_id)
            problems = list(verdict.reasons)
            if not await satisfies(str(pid), requirement, self._run):
                problems.append("running code fails codesign --verify against its Team ID")
            if app_path is not None and not await self._sealed(app_path, requirement):
                problems.append(f"bundle seal broken: {app_path}")
            if problems:
                verdict = Verdict(False, tuple(problems), verdict.warnings, status)
        if self._started(pid) != before:
            return Verdict(False, ("pid reused during verification",), status=status)
        return verdict
