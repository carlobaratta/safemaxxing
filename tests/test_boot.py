from __future__ import annotations

import os
import plistlib
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from safemaxxing.boot import (
    LABEL,
    LAUNCHCTL,
    LOG,
    BootJob,
    boot_script,
    install_holding_reference,
    launchd_plist,
)
from safemaxxing.firewall import ANCHOR, TABLE, CommandResult, PfReference, anchor_rules

# Stands in for /sbin/pfctl: logs argv, prints the main ruleset from $RULES, saves `-f -` stdin.
FAKE_PFCTL = """#!/bin/sh
echo "$*" >> "$CALLS"
case "$*" in
  "-s rules") [ -f "$RULES" ] && cat "$RULES" ;;
  *" -f -") cat > "$STDIN" ;;
  "-E") printf 'No ALTQ support in kernel\npf enabled\nToken : %s\n' "${TOKEN-42}" >&2 ;;
  "-s info")
    if [ -n "$PF_OFF" ]; then echo "Status: Disabled                              Debug: Urgent"
    else echo "Status: Enabled for 0 days 00:00:03           Debug: Urgent"; fi ;;
esac
exit 0
"""
# Stand in for sysctl and BSD stat, so the boot-time check runs the same on any OS.
FAKE_SYSCTL = """#!/bin/sh
echo "$*" >> "$CALLS"
printf '%s\\n' "${BOOT_OUT-{ sec = 4000000000, usec = 0 \\} Sun Nov  9 10:00:00 2096}"
"""
FAKE_STAT = """#!/bin/sh
echo "${MTIME-1000}"
"""


def run_script(
    tmp_path: Path,
    ips: str | None,
    main_rules: str | None,
    token: str = "42",
    extra_env: dict[str, str] | None = None,
    real_tools: bool = False,
) -> tuple[int, list[str]]:
    bindir = tmp_path / "bin dir"  # a space, to prove every path is quoted
    bindir.mkdir()
    for name, text in (("pfctl", FAKE_PFCTL), ("sysctl", FAKE_SYSCTL), ("stat", FAKE_STAT)):
        (bindir / name).write_text(text)
        (bindir / name).chmod(0o755)
    pfctl = bindir / "pfctl"
    tools = {} if real_tools else {"sysctl": str(bindir / "sysctl"), "stat": str(bindir / "stat")}
    blocklist = tmp_path / "Application Support" / "blocklist"
    blocklist.parent.mkdir(exist_ok=True)
    if ips is not None:
        blocklist.write_text(ips)
    env = {
        **os.environ,
        "CALLS": str(tmp_path / "calls"),
        "STDIN": str(tmp_path / "stdin"),
        "TOKEN": token,
        **(extra_env or {}),
    }
    if main_rules is not None:
        (tmp_path / "rules").write_text(main_rules)
        env["RULES"] = str(tmp_path / "rules")
    reference = blocklist.parent / "pf-reference"
    script = boot_script(
        blocklist=blocklist, pfctl=str(pfctl), wait_s=1, reference=reference, **tools
    )
    proc = subprocess.run(["/bin/sh", "-c", script], env=env, capture_output=True, timeout=10)
    calls = tmp_path / "calls"
    return proc.returncode, calls.read_text().splitlines() if calls.exists() else []


def test_boot_script_reapplies_saved_list(tmp_path: Path) -> None:
    code, calls = run_script(tmp_path, "203.0.113.9\n", 'anchor "com.apple/*" all\n')
    blocklist = tmp_path / "Application Support" / "blocklist"
    assert code == 0
    assert calls == [
        "-s rules",
        f"-a {ANCHOR} -f -",
        f"-a {ANCHOR} -t {TABLE} -T add -f {blocklist}",
        "-E",
        "-s info",
    ]
    assert (tmp_path / "stdin").read_text() == anchor_rules()
    reference = PfReference(blocklist.parent / "pf-reference", owner_uid=os.getuid())
    assert stat.S_IMODE(reference.path.stat().st_mode) == 0o600
    record = reference.load()
    assert record is not None and record.token == "42"
    assert abs(record.started - (reference.path.stat().st_mtime - 3)) < 1e-6


def test_boot_script_drops_a_stale_record_and_saves_no_bad_token(tmp_path: Path) -> None:
    for i, token in enumerate(("0x1", "1; touch pwned", "")):
        case = tmp_path / str(i)
        (case / "Application Support").mkdir(parents=True)
        stale = case / "Application Support" / "pf-reference"
        stale.write_text("token=7\nstatus=Status: Enabled for 9 days 00:00:00\n")
        code, calls = run_script(case, "203.0.113.9\n", 'anchor "com.apple/*" all\n', token)
        assert code == 0 and calls[-1] == "-E"  # pf enabled, nothing recorded
        assert not stale.exists()
        assert not (case / "pwned").exists()


LIVE_RECORD = "token=7\nstatus=Status: Enabled for 0 days 00:10:00\n"


def write_record(case: Path) -> Path:
    (case / "Application Support").mkdir(parents=True)
    record = case / "Application Support" / "pf-reference"
    record.write_text(LIVE_RECORD)
    return record


def test_boot_script_keeps_a_record_taken_since_this_boot(tmp_path: Path) -> None:
    # `boot install` loading the job on a live system: a second `pfctl -E` would leak the first.
    record = write_record(tmp_path)
    env = {"BOOT_OUT": "{ sec = 1000, usec = 5 } Sun Nov  9 10:00:00 2026", "MTIME": "1000"}
    code, calls = run_script(tmp_path, "203.0.113.9\n", 'anchor "com.apple/*" all\n', "9", env)
    blocklist = tmp_path / "Application Support" / "blocklist"
    assert code == 0
    assert calls[-3:] == [
        f"-a {ANCHOR} -t {TABLE} -T add -f {blocklist}",
        "-s info",
        "-n kern.boottime",
    ]
    assert record.read_text() == LIVE_RECORD


def test_boot_script_replaces_a_record_it_cannot_trust(tmp_path: Path) -> None:
    cases = {
        "before boot": {"MTIME": "999", "BOOT_OUT": "{ sec = 1000, usec = 0 }"},
        "pf off": {"MTIME": "2000", "BOOT_OUT": "{ sec = 1000, usec = 0 }", "PF_OFF": "1"},
        "no boot time": {"MTIME": "2000", "BOOT_OUT": "sysctl: unknown oid"},
        "no mtime": {"MTIME": "", "BOOT_OUT": "{ sec = 1000, usec = 0 }"},
        "odd mtime": {"MTIME": "2000 x", "BOOT_OUT": "{ sec = 1000, usec = 0 }"},
    }
    for name, env in cases.items():
        record = write_record(tmp_path / name)
        code, calls = run_script(
            tmp_path / name, "203.0.113.9\n", 'anchor "com.apple/*" all\n', "9", env
        )
        assert code == 0 and "-E" in calls, name
        if "PF_OFF" in env:
            assert not record.exists(), name  # pf stays off for the fake: nothing to record
        else:
            assert record.read_text().startswith("token=9\n"), name


@pytest.mark.skipif(sys.platform != "darwin", reason="real sysctl kern.boottime and BSD stat")
def test_boot_script_reads_the_real_boot_time_and_mtime(tmp_path: Path) -> None:
    record = write_record(tmp_path)
    code, calls = run_script(
        tmp_path, "203.0.113.9\n", 'anchor "com.apple/*" all\n', "9", real_tools=True
    )
    assert code == 0 and "-E" not in calls
    assert record.read_text() == LIVE_RECORD


class FakePf:
    """pfctl and launchctl together, logging the order of calls."""

    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled
        self.calls: list[str] = []

    async def __call__(self, argv: Sequence[str], stdin: str | None = None) -> CommandResult:
        args = list(argv)
        if args[0] == LAUNCHCTL:
            self.calls.append(args[1])
            return CommandResult(0, "", "")
        self.calls.append(" ".join(args[1:]))
        if args[1:] == ["-s", "info"]:
            line = "Enabled for 0 days 00:00:01" if self.enabled else "Disabled"
            return CommandResult(0, f"Status: {line}           Debug: Urgent\n", "")
        if args[1:] == ["-E"]:
            self.enabled = True
            return CommandResult(0, "", "pf enabled\nToken : 77\n")
        raise AssertionError(f"unexpected call: {args}")


async def test_install_takes_the_reference_before_the_job_runs(tmp_path: Path) -> None:
    run = FakePf()
    reference = PfReference(tmp_path / "pf-reference", owner_uid=os.getuid())
    job = BootJob(runner=run, plist=tmp_path / f"{LABEL}.plist")
    assert await install_holding_reference(job, reference, True, run) == ("", "")
    assert run.calls == ["-s info", "-E", "-s info", "bootout", "bootstrap"]
    record = reference.load()
    assert record is not None and record.token == "77"
    async with reference.locked():  # released again
        pass


async def test_install_leaves_pf_alone_without_saved_blocks(tmp_path: Path) -> None:
    run = FakePf()
    reference = PfReference(tmp_path / "pf-reference", owner_uid=os.getuid())
    job = BootJob(runner=run, plist=tmp_path / f"{LABEL}.plist")
    assert await install_holding_reference(job, reference, False, run) == ("", "")
    assert run.calls == ["bootout", "bootstrap"]
    assert reference.load() is None


def test_boot_script_leaves_pf_alone_without_saved_blocks(tmp_path: Path) -> None:
    for name, ips in (("missing", None), ("empty", "")):
        (tmp_path / name).mkdir()
        assert run_script(tmp_path / name, ips, 'anchor "com.apple/*" all\n') == (0, [])


def test_boot_script_gives_up_when_pf_conf_never_loads(tmp_path: Path) -> None:
    code, calls = run_script(tmp_path, "203.0.113.9\n", "")
    assert code == 1
    assert set(calls) == {"-s rules"}  # never loads rules or enables pf


def test_launchd_plist_runs_the_script_once_at_load() -> None:
    job = plistlib.loads(launchd_plist("echo hi"))
    assert job["Label"] == LABEL
    assert job["ProgramArguments"] == ["/bin/sh", "-c", "echo hi"]
    assert job["RunAtLoad"] is True
    assert "KeepAlive" not in job
    assert job["StandardErrorPath"] == str(LOG)


class FakeLaunchctl:
    def __init__(self, bootstrap_rc: int = 0, loaded: bool = False) -> None:
        self.bootstrap_rc = bootstrap_rc
        self.loaded = loaded
        self.calls: list[list[str]] = []

    async def __call__(self, argv: Sequence[str], stdin: str | None = None) -> CommandResult:
        args = list(argv)
        self.calls.append(args)
        assert args[0] == LAUNCHCTL
        if args[1] == "bootstrap":
            self.loaded = self.bootstrap_rc == 0
            return CommandResult(self.bootstrap_rc, "", "Bootstrap failed: 5: I/O error\n")
        if args[1] == "bootout":
            was, self.loaded = self.loaded, False
            return CommandResult(0 if was else 3, "", "" if was else "No such process\n")
        if args[1] == "print":
            return CommandResult(0 if self.loaded else 113, "", "")
        raise AssertionError(f"unexpected launchctl call: {args}")


async def test_install_writes_plist_and_reloads_job(tmp_path: Path) -> None:
    launchctl = FakeLaunchctl(loaded=True)
    job = BootJob(runner=launchctl, plist=tmp_path / f"{LABEL}.plist")
    assert await job.install("echo hi") == ""
    assert stat.S_IMODE(job.plist.stat().st_mode) == 0o644
    assert plistlib.loads(job.plist.read_bytes())["ProgramArguments"][-1] == "echo hi"
    assert [c[1] for c in launchctl.calls] == ["bootout", "bootstrap"]
    assert (await job.status()).loaded


async def test_install_reports_bootstrap_failure(tmp_path: Path) -> None:
    job = BootJob(runner=FakeLaunchctl(bootstrap_rc=5), plist=tmp_path / f"{LABEL}.plist")
    assert await job.install() == "Bootstrap failed: 5: I/O error"


async def test_uninstall_unloads_and_deletes(tmp_path: Path) -> None:
    launchctl = FakeLaunchctl()
    job = BootJob(runner=launchctl, plist=tmp_path / f"{LABEL}.plist")
    await job.install("echo hi")
    await job.uninstall()
    status = await job.status()
    assert not status.installed and not status.loaded
    await job.uninstall()  # twice is fine
