from __future__ import annotations

import os
import signal
import sys
from collections.abc import Sequence

import pytest

from safemaxxing.firewall import (
    ANCHOR,
    PFCTL,
    TABLE,
    CommandResult,
    PfFirewall,
    ProcessController,
    anchor_missing,
    meaningful_stderr,
    parse_pf_status,
    run_command,
    validate_ip,
)
from safemaxxing.models import ActionKind

ALTQ = "No ALTQ support in kernel\nALTQ related functions disabled\n"
DEFAULT_MAIN_RULES = (
    'scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all\n'
)


class FakePf:
    """Simulates Darwin pfctl, including its benign ALTQ chatter on stderr."""

    def __init__(
        self,
        enabled: bool = False,
        main_rules: str = DEFAULT_MAIN_RULES,
        honour_big_e: bool = True,
        reject_rules: bool = False,
    ) -> None:
        self.enabled = enabled
        self.main_rules = main_rules
        self.honour_big_e = honour_big_e
        self.reject_rules = reject_rules
        self.anchor_rules = ""
        self.table: set[str] = set()
        self.calls: list[list[str]] = []

    async def __call__(self, argv: Sequence[str], stdin: str | None = None) -> CommandResult:
        args = list(argv)
        self.calls.append(args)
        assert args[0] == PFCTL
        rest = args[1:]
        anchored = rest[:2] == ["-a", ANCHOR]
        if anchored:
            rest = rest[2:]
        if rest == ["-s", "info"]:
            status = "Enabled" if self.enabled else "Disabled"
            return CommandResult(0, f"Status: {status}       Debug: Urgent\n", ALTQ)
        if rest == ["-s", "rules"]:
            return CommandResult(0, self.anchor_rules if anchored else self.main_rules, ALTQ)
        if rest in (["-n", "-f", "-"], ["-f", "-"]):
            if self.reject_rules:
                return CommandResult(1, "", ALTQ + "stdin:1: syntax error\n")
            if rest[0] == "-f":
                self.anchor_rules = (stdin or "").replace("from any to", "all to")
            return CommandResult(0, "", ALTQ)
        if rest == ["-E"]:
            self.enabled = self.enabled or self.honour_big_e
            return CommandResult(0, "", ALTQ + "pf enabled\nToken : 1234\n")
        if rest == ["-e"]:
            if self.enabled:
                return CommandResult(1, "", "pfctl: pf already enabled\n")
            self.enabled = True
            return CommandResult(0, "", ALTQ + "pf enabled\n")
        if rest[:4] == ["-t", TABLE, "-T", "add"]:
            self.table.add(rest[4])
            return CommandResult(0, "", "1/1 addresses added.\n")
        if rest[:4] == ["-t", TABLE, "-T", "delete"]:
            self.table.discard(rest[4])
            return CommandResult(0, "", "1/1 addresses deleted.\n")
        if rest == ["-t", TABLE, "-T", "show"]:
            return CommandResult(0, "".join(f"   {ip}\n" for ip in sorted(self.table)), ALTQ)
        if rest[0] == "-k":
            return CommandResult(0, "", "killed 1 states from 1 sources and 0 destinations\n")
        raise AssertionError(f"unexpected pfctl call: {args}")


def test_parse_pf_status() -> None:
    assert parse_pf_status("Status: Enabled for 0 days 00:01:02           Debug: Urgent") is True
    assert parse_pf_status("Status: Disabled                              Debug: Urgent") is False
    assert parse_pf_status("pfctl: /dev/pf: Permission denied") is None


def test_meaningful_stderr_ignores_darwin_chatter() -> None:
    assert meaningful_stderr(ALTQ + "pf enabled\nToken : 99\n") == []
    assert meaningful_stderr(ALTQ + "stdin:1: syntax error\n") == ["stdin:1: syntax error"]


async def test_block_enables_disabled_pf_and_loads_anchor() -> None:
    pf = FakePf(enabled=False)
    fw = PfFirewall(runner=pf)
    result = await fw.block("203.0.113.9")
    assert result.ok, result.detail
    assert pf.enabled
    assert pf.table == {"203.0.113.9"}
    assert [PFCTL, "-a", ANCHOR, "-n", "-f", "-"] in pf.calls  # dry-run parse first
    assert [PFCTL, "-E"] in pf.calls
    assert pf.calls[-1] == [PFCTL, "-k", "0.0.0.0/0", "-k", "203.0.113.9"]


async def test_block_falls_back_to_lowercase_e() -> None:
    pf = FakePf(enabled=False, honour_big_e=False)
    assert (await PfFirewall(runner=pf).block("203.0.113.9")).ok
    assert [PFCTL, "-e"] in pf.calls and pf.enabled


async def test_setup_is_idempotent_and_skips_enable_when_on() -> None:
    pf = FakePf(enabled=True)
    fw = PfFirewall(runner=pf)
    await fw.block("203.0.113.9")
    calls_after_first = len(pf.calls)
    await fw.block("198.51.100.1")
    assert [PFCTL, "-E"] not in pf.calls
    assert len(pf.calls) - calls_after_first == 2  # add + kill states, no re-setup


async def test_existing_anchor_not_reloaded() -> None:
    pf = FakePf(enabled=True)
    pf.anchor_rules = f"block drop out quick all to <{TABLE}>\n"
    await PfFirewall(runner=pf).block("203.0.113.9")
    assert not any("-f" in c for c in pf.calls)


async def test_missing_parent_anchor_is_refused() -> None:
    pf = FakePf(main_rules="")
    result = await PfFirewall(runner=pf).block("203.0.113.9")
    assert not result.ok and "pfctl -f /etc/pf.conf" in result.detail
    assert pf.table == set()


async def test_rule_syntax_error_reported() -> None:
    result = await PfFirewall(runner=FakePf(reject_rules=True)).block("203.0.113.9")
    assert not result.ok and "syntax error" in result.detail


async def test_ipv6_block_kills_v6_states() -> None:
    pf = FakePf(enabled=True)
    assert (await PfFirewall(runner=pf).block("2001:DB8::1")).target == "2001:db8::1"
    assert pf.calls[-1] == [PFCTL, "-k", "::/0", "-k", "2001:db8::1"]


async def test_block_rejects_invalid_and_loopback() -> None:
    pf = FakePf()
    fw = PfFirewall(runner=pf)
    assert not (await fw.block("127.0.0.1")).ok
    assert not (await fw.block("1.2.3.4; rm -rf /")).ok
    assert pf.calls == []


async def test_unblock_and_show() -> None:
    pf = FakePf(enabled=True)
    fw = PfFirewall(runner=pf)
    await fw.block("203.0.113.9")
    await fw.block("2001:db8::1")
    result = await fw.unblock("203.0.113.9")
    assert result.ok and result.kind is ActionKind.UNBLOCK_IP
    assert await fw.blocked() == ["2001:db8::1"]


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


async def test_run_command_real_subprocess_decodes_both_streams() -> None:
    script = (
        "import sys; d = sys.stdin.read(); print(d.upper()); "
        "sys.stderr.write('\\xe9rr'); sys.exit(3)"
    )
    res = await run_command([sys.executable, "-c", script], stdin="rules")
    assert res.returncode == 3
    assert res.stdout.strip() == "RULES"
    assert res.stderr == "érr"


def test_anchor_missing_matches_darwin_reply() -> None:
    assert anchor_missing("pfctl: DIOCGETRULES: Invalid argument\n")
    assert not anchor_missing(ALTQ)
