"""Code-signing identity of a binary, read with `codesign -dv` for the TUI's inspector."""

from __future__ import annotations

import asyncio

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
