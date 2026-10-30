from __future__ import annotations

import plistlib
import subprocess
import time
from pathlib import Path

from safemaxxing.lockdown.watchdog import Heartbeat, watchdog_plist, watchdog_script


def fake_pfctl(tmp_path: Path) -> Path:
    calls = tmp_path / "calls"
    script = tmp_path / "pfctl"
    script.write_text(f'#!/bin/sh\necho "pfctl $*" >> {calls}\ncat > /dev/null\n')
    script.chmod(0o755)
    return script


def calls(tmp_path: Path) -> list[str]:
    path = tmp_path / "calls"
    return path.read_text().splitlines() if path.exists() else []


def run_watchdog(tmp_path: Path, hb: Heartbeat) -> subprocess.Popen[bytes]:
    script = watchdog_script(
        heartbeat=hb.heartbeat, armed=hb.armed_flag, pfctl=str(fake_pfctl(tmp_path)), tick="0.05"
    )
    return subprocess.Popen(["/bin/sh", "-c", script], stdout=subprocess.DEVNULL)


def test_idle_until_armed_and_quiet_while_beating(tmp_path: Path) -> None:
    hb = Heartbeat(run_dir=tmp_path / "run")
    proc = run_watchdog(tmp_path, hb)
    try:
        time.sleep(0.4)
        assert calls(tmp_path) == []
        hb.arm()
        for _ in range(20):
            hb.beat()
            time.sleep(0.03)
        assert calls(tmp_path) == [] and hb.armed
    finally:
        proc.terminate()
        proc.wait()


def test_restores_v02_rules_when_beats_stop(tmp_path: Path) -> None:
    hb = Heartbeat(run_dir=tmp_path / "run")
    proc = run_watchdog(tmp_path, hb)
    try:
        hb.arm()
        deadline = time.monotonic() + 5
        while hb.armed and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not hb.armed
        assert calls(tmp_path) == [
            "pfctl -a com.apple/safemaxxing -f -",
            "pfctl -a com.apple/safemaxxing/grants -F rules",
        ]
    finally:
        proc.terminate()
        proc.wait()


async def test_heartbeat_reports_a_trip(tmp_path: Path) -> None:
    hb = Heartbeat(run_dir=tmp_path, interval_s=0.01)
    tripped: list[bool] = []
    hb.arm()
    hb.armed_flag.unlink()
    await hb.run(lambda: tripped.append(True))
    assert tripped == [True]


def test_heartbeat_skips_beats_while_unhealthy(tmp_path: Path) -> None:
    hb = Heartbeat(run_dir=tmp_path, healthy=lambda: False)
    hb.arm()
    assert hb.heartbeat.read_text() == "1\n"


def test_plist_runs_only_sh_and_keeps_alive() -> None:
    plist = plistlib.loads(watchdog_plist(watchdog_script()))
    assert plist["ProgramArguments"][:2] == ["/bin/sh", "-c"]
    assert plist["KeepAlive"] is True and plist["RunAtLoad"] is True
    # Never this package: a root job running a user-writable interpreter is a root shell.
    script = plist["ProgramArguments"][2]
    assert "python" not in script and ".venv" not in script and " -m " not in script
