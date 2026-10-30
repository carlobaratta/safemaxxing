from __future__ import annotations

import ctypes
import errno
import os
import plistlib
import sys
from collections.abc import Sequence

import pytest

from safemaxxing.codesign import (
    CS_ADHOC,
    CS_DEBUGGED,
    CS_GET_TASK_ALLOW,
    CS_HARD,
    CS_KILL,
    CS_OPS_CDHASH,
    CS_OPS_ENTITLEMENTS_BLOB,
    CS_OPS_STATUS,
    CS_OPS_TEAMID,
    CS_PLATFORM_BINARY,
    CS_RUNTIME,
    CS_SIGNED,
    CS_VALID,
    CodeStatus,
    CodeVerifier,
    Strictness,
    assess,
    kernel_code_status,
    team_requirement,
)
from safemaxxing.firewall import CommandResult

GOOD = CS_VALID | CS_SIGNED | CS_RUNTIME | CS_HARD | CS_KILL
DLV = "com.apple.security.cs.disable-library-validation"


def status(
    flags: int = GOOD, team: str | None = "KL8N8XSYF4", ents: Sequence[str] = ()
) -> CodeStatus:
    return CodeStatus(
        4242, flags, "5aba0c03d96072bd582b1b678eab59ddbe220c18", team, frozenset(ents)
    )


def test_hardened_signed_app_with_its_pinned_team_passes() -> None:
    verdict = assess(status(), "KL8N8XSYF4")
    assert verdict.ok and not verdict.warnings


@pytest.mark.parametrize(
    "flags, reason",
    [
        (GOOD & ~CS_VALID, "CS_VALID"),
        (GOOD | CS_DEBUGGED, "debugger"),
        (GOOD | CS_GET_TASK_ALLOW, "debuggable"),
        (GOOD | CS_ADHOC, "ad-hoc"),
        (GOOD & ~CS_RUNTIME, "hardened runtime"),
    ],
)
def test_injection_and_tampering_signals_are_refused(flags: int, reason: str) -> None:
    verdict = assess(status(flags), "KL8N8XSYF4")
    assert not verdict.ok and any(reason in r for r in verdict.reasons)


def test_spoofed_bundle_with_another_team_is_refused() -> None:
    verdict = assess(status(team="EVILTEAM00"), "KL8N8XSYF4")
    assert not verdict.ok and "does not match the pinned" in verdict.reasons[0]


def test_library_validation_off_warns_in_standard_and_refuses_in_strict() -> None:
    # Measured: Brave's network helper carries it (macOS 27.0.1).
    assert assess(status(ents=[DLV]), "KL8N8XSYF4").warnings == (
        "entitlement disable-library-validation",
    )
    assert not assess(status(ents=[DLV]), "KL8N8XSYF4", Strictness.STRICT).ok
    dyld = "com.apple.security.cs.allow-dyld-environment-variables"
    assert not assess(status(ents=[dyld]), "KL8N8XSYF4").ok


def test_platform_binaries_need_no_team() -> None:
    assert assess(status(GOOD | CS_PLATFORM_BINARY, team=None), "").ok
    assert not assess(status(team=None), None).ok


def test_team_requirement_refuses_injection() -> None:
    assert team_requirement("KL8N8XSYF4").endswith('= "KL8N8XSYF4"')
    with pytest.raises(ValueError):
        team_requirement('X" or anchor apple')


class FakeKernel:
    """csops answering like macOS 27.0.1 did for Brave's helper (pid 937)."""

    def __init__(self) -> None:
        xml = plistlib.dumps({DLV: True, "com.apple.security.device.camera": True})
        body = xml + b"\x00"
        self.blob = (0xFADE7171).to_bytes(4, "big") + (len(body) + 8).to_bytes(4, "big") + body

    def __call__(
        self, pid: int, op: int, buf: ctypes.Array[ctypes.c_char], size: int
    ) -> tuple[int, int]:
        if op == CS_OPS_STATUS:
            ctypes.memmove(buf, (GOOD).to_bytes(4, "little"), 4)
        elif op == CS_OPS_CDHASH:
            ctypes.memmove(buf, bytes.fromhex("872d9200b706" + "00" * 14), 20)
        elif op == CS_OPS_TEAMID:
            raw = b"\x00\x00\x00\x00\x00\x00\x00\x13KL8N8XSYF4\x00"
            ctypes.memmove(buf, raw, len(raw))
        elif op == CS_OPS_ENTITLEMENTS_BLOB:
            if size < len(self.blob):
                ctypes.memmove(buf, b"\x00" * 4 + len(self.blob).to_bytes(4, "big"), 8)
                return -1, errno.ERANGE
            ctypes.memmove(buf, self.blob, len(self.blob))
        return 0, 0


def test_kernel_status_decodes_team_header_and_entitlement_blob() -> None:
    got = kernel_code_status(937, FakeKernel())
    assert got is not None
    assert got.team_id == "KL8N8XSYF4" and got.cdhash is not None and got.cdhash.startswith("872d")
    assert got.entitlements == {DLV, "com.apple.security.device.camera"}


@pytest.mark.skipif(sys.platform != "darwin", reason="csops is macOS-only")
def test_kernel_status_of_this_process_on_macos() -> None:
    got = kernel_code_status(os.getpid())
    assert got is not None and got.has(CS_VALID) and got.cdhash is not None


async def test_verifier_runs_codesign_on_the_pid_and_detects_pid_reuse() -> None:
    argvs: list[list[str]] = []

    async def runner(argv: Sequence[str], stdin: str | None = None) -> CommandResult:
        argvs.append(list(argv))
        return CommandResult(0, "", "")

    starts = iter([100.0, 100.0])
    verifier = CodeVerifier(
        status=lambda pid: status(), runner=runner, started=lambda p: next(starts)
    )
    assert (await verifier.verify(4242, "KL8N8XSYF4", None)).ok
    assert argvs[0][-1] == "4242" and argvs[0][2].startswith("-R=anchor apple generic")
    reused = iter([100.0, 200.0])
    verifier = CodeVerifier(
        status=lambda pid: status(), runner=runner, started=lambda p: next(reused)
    )
    assert (await verifier.verify(4242, "KL8N8XSYF4", None)).reasons == (
        "pid reused during verification",
    )
