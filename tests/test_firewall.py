from __future__ import annotations

import os
import signal
import stat
import sys
import time
from collections.abc import Sequence
from pathlib import Path

import pytest

from safemaxxing.firewall import (
    ANCHOR,
    PFCTL,
    TABLE,
    BlockList,
    CommandResult,
    PfFirewall,
    PfReference,
    ProcessController,
    anchor_missing,
    meaningful_stderr,
    parse_pf_runtime,
    parse_pf_status,
    parse_pf_token,
    run_command,
    validate_ip,
)
from safemaxxing.models import ActionKind

ALTQ = "No ALTQ support in kernel\nALTQ related functions disabled\n"
# Verbatim from pfctl on macOS 27.0.1 for any `-f`, including `-a <anchor> -f -`.
F_FLAG_WARNING = (
    "pfctl: Use of -f option, could result in flushing of rules\n"
    "present in the main ruleset added by the system at startup.\n"
    "See /etc/pf.conf for further details.\n"
)
DEFAULT_MAIN_RULES = (
    'scrub-anchor "com.apple/*" all fragment reassemble\nanchor "com.apple/*" all\n'
)


class FakePf:
    """Simulates Darwin pfctl, including its benign ALTQ chatter on stderr.

    pf's references are modelled as in xnu: `-E` adds a token, `-X` drops one, and pf stops
    when no token and no other holder (`others`) is left. `pfctl -d` is never expected.
    """

    def __init__(
        self,
        enabled: bool = False,
        main_rules: str = DEFAULT_MAIN_RULES,
        honour_big_e: bool = True,
        reject_rules: bool = False,
        others: int | None = None,
    ) -> None:
        self.enabled = enabled
        # A pf already on is held by someone else, unless the test says otherwise.
        self.others = (1 if enabled else 0) if others is None else others
        self.since = time.time() - 3600
        self.tokens: set[str] = set()
        self._next_token = 1234
        self.main_rules = main_rules
        self.honour_big_e = honour_big_e
        self.reject_rules = reject_rules
        self.anchor_rules = ""
        self.table: set[str] = set()
        self.calls: list[list[str]] = []

    def restart(self) -> None:
        """Someone ran `pfctl -d` (every token invalidated), then enabled pf again."""
        self.tokens.clear()
        self._next_token = 1234  # the kernel may reuse a token value
        self.since = time.time()
        self.enabled, self.others = True, 1

    def _info(self) -> str:
        if not self.enabled:
            return "Status: Disabled                              Debug: Urgent\n"
        runtime = int(time.time() - self.since)
        hours, rest = divmod(runtime, 3600)
        clock = f"{hours:02d}:{rest // 60:02d}:{rest % 60:02d}"
        return f"Status: Enabled for 0 days {clock}           Debug: Urgent\n"

    async def __call__(self, argv: Sequence[str], stdin: str | None = None) -> CommandResult:
        args = list(argv)
        self.calls.append(args)
        assert args[0] == PFCTL
        rest = args[1:]
        anchored = rest[:2] == ["-a", ANCHOR]
        if anchored:
            rest = rest[2:]
        if rest == ["-s", "info"]:
            return CommandResult(0, self._info(), ALTQ)
        if rest == ["-s", "rules"]:
            return CommandResult(0, self.anchor_rules if anchored else self.main_rules, ALTQ)
        if rest in (["-n", "-f", "-"], ["-f", "-"]):
            if self.reject_rules:
                return CommandResult(1, "", F_FLAG_WARNING + ALTQ + "stdin:1: syntax error\n")
            if rest[0] == "-f":
                self.anchor_rules = (stdin or "").replace("from any to", "all to")
            return CommandResult(0, "", F_FLAG_WARNING + ALTQ)
        if rest == ["-E"]:
            if not self.honour_big_e:
                return CommandResult(0, "", ALTQ + "pf enabled\nToken : 0\n")
            token = str(self._next_token)
            self._next_token += 1
            self.tokens.add(token)
            if not self.enabled:
                self.enabled, self.since = True, time.time()
            return CommandResult(0, "", ALTQ + f"pf enabled\nToken : {token}\n")
        if rest[:1] == ["-X"]:
            if rest[1] not in self.tokens:
                return CommandResult(1, "", "pfctl: DIOCSTOPREF: No such file or directory\n")
            self.tokens.discard(rest[1])
            if not self.tokens and not self.others:
                self.enabled = False
            return CommandResult(0, "", "pf: 0 references remaining\n")
        if rest == ["-e"]:
            if self.enabled:
                return CommandResult(1, "", "pfctl: pf already enabled\n")
            self.enabled, self.since, self.others = True, time.time(), self.others + 1
            return CommandResult(0, "", ALTQ + "pf enabled\n")
        if rest[:4] == ["-t", TABLE, "-T", "add"]:
            self.table.add(rest[4])
            return CommandResult(0, "", "1/1 addresses added.\n")
        if rest[:4] == ["-t", TABLE, "-T", "delete"]:
            self.table.discard(rest[4])
            return CommandResult(0, "", "1/1 addresses deleted.\n")
        if rest == ["-t", TABLE, "-T", "flush"]:
            if not self.table:
                return CommandResult(255, "", ALTQ + "pfctl: Table does not exist.\n")
            self.table.clear()
            return CommandResult(0, "", "1 addresses deleted.\n")
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
    assert meaningful_stderr("1 table created.\n1/2 addresses added.\nno changes.\n") == []
    assert meaningful_stderr("1 addresses added.\npfctl: Invalid argument.\n") == [
        "pfctl: Invalid argument."
    ]


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


async def test_setup_loads_the_anchor_once_and_skips_enable_when_on() -> None:
    pf = FakePf(enabled=True)
    fw = PfFirewall(runner=pf)
    await fw.block("203.0.113.9")
    calls_after_first = len(pf.calls)
    await fw.block("198.51.100.1")
    assert [PFCTL, "-E"] not in pf.calls
    assert len(pf.calls) - calls_after_first == 3  # pf status + add + kill states


async def test_a_long_lived_firewall_re_enables_pf_turned_off_elsewhere() -> None:
    pf = FakePf(enabled=False)
    fw = PfFirewall(runner=pf)
    assert (await fw.block("203.0.113.9")).ok
    pf.enabled, pf.tokens = False, set()  # another process's flush released the last holder
    assert (await fw.block("198.51.100.1")).ok
    assert pf.enabled


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


def test_darwin_f_flag_warning_is_benign() -> None:
    assert meaningful_stderr(F_FLAG_WARNING + ALTQ) == []


async def test_unblock_works_even_when_setup_would_fail() -> None:
    pf = FakePf(main_rules="")
    pf.table.add("203.0.113.9")
    result = await PfFirewall(runner=pf).unblock("203.0.113.9")
    assert result.ok
    assert pf.table == set()
    assert not any("-f" in c or "-E" in c for c in pf.calls)


async def test_flush_of_never_created_table_is_ok() -> None:
    pf = FakePf(enabled=True)
    result = await PfFirewall(runner=pf).flush()
    assert result.ok and result.detail == "table already empty"
    pf.table.add("203.0.113.9")
    assert (await PfFirewall(runner=pf).flush()).ok and pf.table == set()


def test_blocklist_keeps_order_skips_duplicates_and_comments(tmp_path: Path) -> None:
    store = BlockList(tmp_path / "state" / "blocklist")
    assert store.load() == []
    store.add("203.0.113.9")
    store.add("2001:db8::1")
    store.add("203.0.113.9")
    assert store.load() == ["203.0.113.9", "2001:db8::1"]
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o644
    store.path.write_text("# kept by hand\n\n198.51.100.1\n")
    assert store.load() == ["198.51.100.1"]


def test_blocklist_remove_and_clear(tmp_path: Path) -> None:
    store = BlockList(tmp_path / "blocklist")
    store.clear()  # nothing saved yet: no file is created
    assert not store.path.exists()
    for ip in ("203.0.113.9", "198.51.100.1"):
        store.add(ip)
    store.remove("192.0.2.7")  # never saved: not an error
    store.remove("203.0.113.9")
    assert store.load() == ["198.51.100.1"]
    store.clear()
    assert store.path.read_text() == ""
    assert [p.name for p in tmp_path.iterdir()] == ["blocklist"]  # no temp files left


async def test_store_follows_block_unblock_and_flush(tmp_path: Path) -> None:
    store = BlockList(tmp_path / "blocklist")
    fw = PfFirewall(runner=FakePf(enabled=True), store=store)
    await fw.block("203.0.113.9")
    await fw.block("2001:DB8::1")
    assert store.load() == ["203.0.113.9", "2001:db8::1"]  # saved normalised
    await fw.unblock("203.0.113.9")
    assert store.load() == ["2001:db8::1"]
    assert (await fw.flush()).ok
    assert store.load() == []


async def test_failed_block_is_not_saved(tmp_path: Path) -> None:
    store = BlockList(tmp_path / "blocklist")
    fw = PfFirewall(runner=FakePf(main_rules="pass all\n"), store=store)
    assert not (await fw.block("203.0.113.9")).ok
    assert not (await fw.block("127.0.0.1")).ok
    assert store.load() == []


async def test_unwritable_store_keeps_the_block_and_says_so(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    pf = FakePf(enabled=True)
    result = await PfFirewall(runner=pf, store=BlockList(blocker / "blocklist")).block(
        "203.0.113.9"
    )
    assert result.ok
    assert pf.table == {"203.0.113.9"}
    assert "not saved for reboot: [Errno 20]" in result.detail


def own_reference(tmp_path: Path) -> PfReference:
    return PfReference(tmp_path / "state" / "pf-reference", owner_uid=os.getuid())


def test_parse_pf_runtime_and_token() -> None:
    info = "Status: Enabled for 2 days 03:04:05           Debug: Urgent\n"
    assert parse_pf_runtime(info) == ((2 * 24 + 3) * 60 + 4) * 60 + 5
    assert parse_pf_runtime("Status: Disabled              Debug: Urgent\n") is None
    assert parse_pf_token(ALTQ + "pf enabled\nToken : 18446742974214806528\n") == (
        "18446742974214806528"
    )
    assert parse_pf_token("Token : 0\n") is None  # the kernel's "no token"
    assert parse_pf_token(f"Token : {2**64}\n") is None
    assert parse_pf_token("Token : 12; rm -rf /\n") is None


async def test_flush_releases_the_reference_and_pf_stops_without_other_holders(
    tmp_path: Path,
) -> None:
    pf, reference = FakePf(enabled=False), own_reference(tmp_path)
    fw = PfFirewall(runner=pf, reference=reference)
    assert (await fw.block("203.0.113.9")).ok
    record = reference.load()
    assert record is not None and record.token in pf.tokens
    assert stat.S_IMODE(reference.path.stat().st_mode) == 0o600
    result = await fw.flush()
    assert result.ok, result.detail
    assert [PFCTL, "-X", record.token] in pf.calls
    assert not pf.enabled and "pf disabled (no other holder)" in result.detail
    assert reference.load() is None
    assert not any(c[1:] == ["-d"] for c in pf.calls)


async def test_flush_leaves_pf_on_for_its_other_holders(tmp_path: Path) -> None:
    pf = FakePf(enabled=True)  # e.g. Internet Sharing already holds pf
    fw = PfFirewall(runner=pf, reference=own_reference(tmp_path))
    assert (await fw.block("203.0.113.9")).ok
    assert [PFCTL, "-E"] in pf.calls  # our own reference, even though pf was on
    result = await fw.flush()
    assert result.ok and pf.enabled and pf.tokens == set()
    assert "stays enabled for its other holders" in result.detail


async def test_our_reference_keeps_pf_on_when_another_holder_leaves(tmp_path: Path) -> None:
    pf = FakePf(enabled=True)
    assert (await PfFirewall(runner=pf, reference=own_reference(tmp_path)).block("192.0.2.7")).ok
    pf.others = 0  # the VPN that had enabled pf releases its reference
    assert pf.tokens and pf.enabled


async def test_flush_keeps_the_reference_while_paranoia_rules_are_loaded(tmp_path: Path) -> None:
    pf, reference = FakePf(enabled=False), own_reference(tmp_path)
    fw = PfFirewall(runner=pf, reference=reference)
    assert (await fw.block("203.0.113.9")).ok
    pf.anchor_rules += "block drop out log quick all\npass out quick proto udp to <dns>\n"
    result = await fw.flush()
    assert result.ok and pf.table == set()
    assert "Paranoia Mode's rules are loaded" in result.detail
    assert pf.enabled and reference.load() is not None
    assert not any(c[1:2] == ["-X"] for c in pf.calls)


async def test_a_token_from_an_earlier_run_of_pf_is_forgotten_not_released(
    tmp_path: Path,
) -> None:
    pf, reference = FakePf(enabled=True), own_reference(tmp_path)  # pf on for an hour
    fw = PfFirewall(runner=pf, reference=reference)
    assert (await fw.block("203.0.113.9")).ok
    pf.restart()
    vpn = PfFirewall(runner=pf)  # a stand-in for another program taking a reference
    await vpn._run([PFCTL, "-E"])
    assert pf.tokens == {"1234"}  # the value our stale record also holds
    result = await fw.flush()
    assert result.ok and "restarted since safemaxxing enabled it" in result.detail
    assert pf.tokens == {"1234"} and pf.enabled
    assert not any(c[1:2] == ["-X"] for c in pf.calls)
    assert reference.load() is None


async def test_a_record_others_can_write_is_ignored(tmp_path: Path) -> None:
    pf, reference = FakePf(enabled=False), own_reference(tmp_path)
    fw = PfFirewall(runner=pf, reference=reference)
    assert (await fw.block("203.0.113.9")).ok
    reference.path.chmod(0o666)
    result = await fw.flush()
    assert result.ok and "no recorded reference" in result.detail
    assert pf.enabled and not any(c[1:2] == ["-X"] for c in pf.calls)


async def test_lowercase_e_fallback_has_nothing_to_release(tmp_path: Path) -> None:
    pf = FakePf(enabled=False, honour_big_e=False)
    fw = PfFirewall(runner=pf, reference=own_reference(tmp_path))
    result = await fw.block("203.0.113.9")
    assert result.ok and "flush cannot release it" in result.detail
    flushed = await fw.flush()
    assert flushed.ok and "no recorded reference" in flushed.detail and pf.enabled


async def test_block_waits_for_a_flush_holding_the_lock(tmp_path: Path) -> None:
    pf = FakePf(enabled=True)
    held, waiting = own_reference(tmp_path), own_reference(tmp_path)
    waiting.LOCK_TIMEOUT_S = 0.05
    async with held.locked():
        result = await PfFirewall(runner=pf, reference=waiting).block("203.0.113.9")
    assert not result.ok and "holds" in result.detail
    assert pf.table == set()
    assert (await PfFirewall(runner=pf, reference=waiting).block("203.0.113.9")).ok
