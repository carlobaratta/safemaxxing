from __future__ import annotations

import os
import signal
from collections.abc import Sequence

import pytest

from safemaxxing.firewall import (
    ANCHOR,
    PFCTL,
    TABLE,
    CommandResult,
    PfFirewall,
    ProcessController,
    validate_ip,
)
from safemaxxing.models import ActionKind


class FakeRunner:
    def __init__(self, rules: str = "", fail: set[str] | None = None) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.rules = rules
        self.fail = fail or set()

    async def __call__(self, argv: Sequence[str], stdin: str | None = None) -> CommandResult:
        argv = list(argv)
        self.calls.append((argv, stdin))
        if any(a in self.fail for a in argv):
            return CommandResult(1, "", "boom")
        if "-s" in argv:
            return CommandResult(0, self.rules, "")
        if argv[-1] == "show":
            return CommandResult(0, "   203.0.113.9\n   2001:db8::1\n", "")
        return CommandResult(0, "", "")


async def test_block_loads_anchor_once_and_adds_ip() -> None:
    runner = FakeRunner()
    fw = PfFirewall(runner=runner)
    assert (await fw.block("203.0.113.9")).ok
    assert (await fw.block("198.51.100.1")).ok
    argvs = [c[0] for c in runner.calls]
    assert argvs[0] == [PFCTL, "-a", ANCHOR, "-s", "rules"]
    assert argvs[1] == [PFCTL, "-a", ANCHOR, "-f", "-"]
    assert f"<{TABLE}>" in (runner.calls[1][1] or "")
    assert "table <" not in (runner.calls[1][1] or "")
    assert argvs[2] == [PFCTL, "-E"]
    assert argvs[3] == [PFCTL, "-a", ANCHOR, "-t", TABLE, "-T", "add", "203.0.113.9"]
    assert argvs[4][-1] == "198.51.100.1"
    assert len(argvs) == 5


async def test_existing_anchor_not_reloaded() -> None:
    runner = FakeRunner(rules=f"block drop out quick from any to <{TABLE}>")
    await PfFirewall(runner=runner).block("203.0.113.9")
    assert not any("-f" in c[0] for c in runner.calls)


async def test_setup_failure_reported() -> None:
    result = await PfFirewall(runner=FakeRunner(fail={"-E"})).block("203.0.113.9")
    assert not result.ok and "enable" in result.detail


async def test_block_rejects_invalid_and_loopback() -> None:
    runner = FakeRunner()
    fw = PfFirewall(runner=runner)
    assert not (await fw.block("127.0.0.1")).ok
    assert not (await fw.block("1.2.3.4; rm -rf /")).ok
    assert runner.calls == []


async def test_unblock_and_show() -> None:
    runner = FakeRunner()
    fw = PfFirewall(runner=runner)
    result = await fw.unblock("2001:DB8::1")
    assert result.ok and result.kind is ActionKind.UNBLOCK_IP and result.target == "2001:db8::1"
    assert runner.calls[-1][0][-2:] == ["delete", "2001:db8::1"]
    assert await fw.blocked() == ["203.0.113.9", "2001:db8::1"]


def test_validate_ip_normalises() -> None:
    assert validate_ip(" 2001:DB8::0001 ") == "2001:db8::1"
    with pytest.raises(ValueError):
        validate_ip("0.0.0.0")


def test_process_controller_signals() -> None:
    sent: list[tuple[int, int]] = []
    ctl = ProcessController(kill=lambda pid, sig: sent.append((pid, sig)))
    assert ctl.suspend(4242).ok
    assert ctl.resume(4242).ok
    assert ctl.kill(4242).ok
    assert sent == [(4242, signal.SIGSTOP), (4242, signal.SIGCONT), (4242, signal.SIGKILL)]


def test_process_controller_protects_critical_pids() -> None:
    sent: list[tuple[int, int]] = []
    ctl = ProcessController(kill=lambda pid, sig: sent.append((pid, sig)))
    for pid in (0, 1, -1, os.getpid()):
        assert not ctl.suspend(pid).ok
    assert sent == []


def test_process_controller_errors() -> None:
    def missing(pid: int, sig: int) -> None:
        raise ProcessLookupError

    def denied(pid: int, sig: int) -> None:
        raise PermissionError

    assert ProcessController(kill=missing).kill(4242).detail == "no such process"
    assert "permission" in ProcessController(kill=denied).kill(4242).detail
