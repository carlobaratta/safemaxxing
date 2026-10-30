from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Sequence

import pytest

from safemaxxing.firewall import CommandResult, FirewallError
from safemaxxing.lockdown.pf import LockdownFirewall
from safemaxxing.lockdown.rules import (
    GRANTS_ANCHOR,
    Grant,
    LockdownConfig,
    grant_rules,
    lockdown_rules,
)
from safemaxxing.models import Protocol

# Darwin's pfctl parses (-n) without root; anywhere else these checks are skipped.
darwin_pfctl = pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("pfctl", path="/sbin") is None,
    reason="needs Darwin's /sbin/pfctl",
)


def pf_parses(text: str) -> tuple[int, str]:
    res = subprocess.run(
        ["/sbin/pfctl", "-n", "-f", "-"], input=text, capture_output=True, text=True
    )
    return res.returncode, res.stderr


@darwin_pfctl
@pytest.mark.parametrize(
    "config",
    [LockdownConfig(), LockdownConfig(sinkhole=False), LockdownConfig(apple_443=True)],
)
def test_lockdown_ruleset_parses_on_darwin(config: LockdownConfig) -> None:
    code, stderr = pf_parses(lockdown_rules(config))
    assert code == 0, stderr


@darwin_pfctl
def test_grant_rules_parse_on_darwin() -> None:
    grants = [Grant(Protocol.TCP, "203.0.113.9", 443), Grant(Protocol.UDP, "2001:db8::1", 8801)]
    code, stderr = pf_parses(grant_rules(grants))
    assert code == 0, stderr


def test_ruleset_order_block_table_first_default_deny_last() -> None:
    lines = lockdown_rules().splitlines()
    filters = [line for line in lines if not line.startswith("rdr")]
    assert filters[0] == "block drop out quick from any to <safemaxxing_block>"
    assert lines[-1] == "block drop out log quick all"
    assert lines[-2] == 'anchor "grants"'
    # Translation rules must precede filter rules in a pf ruleset.
    assert all(line.startswith("rdr") for line in lines[:2])


def test_without_sinkhole_dns_goes_only_to_the_resolver_table() -> None:
    text = lockdown_rules(LockdownConfig(sinkhole=False))
    assert "rdr" not in text and "route-to" not in text
    assert "to <safemaxxing_dns> port 53" in text


def test_apple_443_is_opt_in() -> None:
    assert "port { 5223 2197 }" in lockdown_rules()
    assert "port { 5223 2197 443 }" in lockdown_rules(LockdownConfig(apple_443=True))


def test_grants_are_validated_normalised_and_deduplicated() -> None:
    a = Grant(Protocol.UDP, "2001:DB8:0::1", 8801)
    b = Grant(Protocol.UDP, "2001:db8::1", 8801)
    assert a == b and a.address == "2001:db8::1"
    assert grant_rules([a, b]).count("\n") == 1
    assert grant_rules([]) == ""
    # psutil's scoped spelling and pflog's bare one are one grant; nothing after % reaches pf.
    assert Grant(Protocol.TCP, "fe80::1%en0", 80) == Grant(Protocol.TCP, "fe80::1", 80)
    assert "pass" not in Grant(Protocol.TCP, "fe80::1%x port 1 pass", 80).address
    for bad in ("1.2.3.4 port 1 pass", "127.0.0.1", "0.0.0.0", "224.0.0.1", "any"):
        with pytest.raises(ValueError):
            Grant(Protocol.TCP, bad, 443)
    with pytest.raises(ValueError):
        Grant(Protocol.TCP, "203.0.113.9", 0)


class RecordingPf:
    def __init__(self, reject: str | None = None) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.reject = reject

    async def __call__(self, argv: Sequence[str], stdin: str | None = None) -> CommandResult:
        self.calls.append((list(argv), stdin))
        if self.reject and stdin and self.reject in stdin:
            return CommandResult(1, "", "stdin:1: syntax error\n")
        return CommandResult(0, "", "No ALTQ support in kernel\n")


async def test_load_checks_before_loading_and_restore_is_two_steps() -> None:
    pf = RecordingPf()
    fw = LockdownFirewall(pf)
    await fw.load(lockdown_rules())
    assert [c[0][3] for c in pf.calls] == ["-n", "-f"]
    pf.calls.clear()
    await fw.restore_normal()
    assert pf.calls[-1][0] == ["/sbin/pfctl", "-a", GRANTS_ANCHOR, "-F", "rules"]
    assert pf.calls[1][1] == "block drop out quick from any to <safemaxxing_block>\n"


async def test_rejected_rules_are_never_loaded() -> None:
    pf = RecordingPf(reject="anchor")
    with pytest.raises(FirewallError, match="syntax error"):
        await LockdownFirewall(pf).load(lockdown_rules())
    assert all("-n" in argv for argv, _ in pf.calls)


async def test_replace_table_flushes_when_empty() -> None:
    pf = RecordingPf()
    fw = LockdownFirewall(pf)
    await fw.replace_table("safemaxxing_ntp", ["17.253.4.125", "17.253.4.125"])
    await fw.replace_table("safemaxxing_user", [])
    assert pf.calls[0][0][-3:] == ["-T", "replace", "17.253.4.125"]
    assert pf.calls[1][0][-2:] == ["-T", "flush"]
