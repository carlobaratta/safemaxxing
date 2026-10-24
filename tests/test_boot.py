from __future__ import annotations

import os
import plistlib
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path

from safemaxxing.boot import LABEL, LAUNCHCTL, LOG, BootJob, boot_script, launchd_plist
from safemaxxing.firewall import ANCHOR, TABLE, CommandResult, anchor_rules

# Stands in for /sbin/pfctl: logs argv, prints the main ruleset from $RULES, saves `-f -` stdin.
FAKE_PFCTL = """#!/bin/sh
echo "$*" >> "$CALLS"
case "$*" in
  "-s rules") [ -f "$RULES" ] && cat "$RULES" ;;
  *" -f -") cat > "$STDIN" ;;
esac
exit 0
"""


def run_script(tmp_path: Path, ips: str | None, main_rules: str | None) -> tuple[int, list[str]]:
    pfctl = tmp_path / "bin dir" / "pfctl"  # a space, to prove every path is quoted
    pfctl.parent.mkdir()
    pfctl.write_text(FAKE_PFCTL)
    pfctl.chmod(0o755)
    blocklist = tmp_path / "Application Support" / "blocklist"
    blocklist.parent.mkdir()
    if ips is not None:
        blocklist.write_text(ips)
    env = {**os.environ, "CALLS": str(tmp_path / "calls"), "STDIN": str(tmp_path / "stdin")}
    if main_rules is not None:
        (tmp_path / "rules").write_text(main_rules)
        env["RULES"] = str(tmp_path / "rules")
    script = boot_script(blocklist=blocklist, pfctl=str(pfctl), wait_s=1)
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
    ]
    assert (tmp_path / "stdin").read_text() == anchor_rules()


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
