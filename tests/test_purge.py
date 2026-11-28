from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from test_boot import FakeLaunchctl
from test_firewall import FakePf

from safemaxxing.boot import LaunchdJob
from safemaxxing.firewall import (
    ANCHOR,
    PFCTL,
    TABLE,
    CommandResult,
    PfReference,
    check_pfctl_argv,
)
from safemaxxing.lockdown.rules import GRANTS_ANCHOR
from safemaxxing.purge import (
    TABLES,
    PurgeTargets,
    blocker,
    planned,
    purge,
    running_instances,
)


class PurgePf(FakePf):
    """FakePf plus the calls only a purge makes: the lockdown tables and the grants anchor."""

    def __init__(self, enabled: bool = True) -> None:
        super().__init__(enabled=enabled)
        self.flushed: list[str] = []
        self.grants_flushed = False

    async def __call__(self, argv: Sequence[str], stdin: str | None = None) -> CommandResult:
        args = list(argv)
        if args[1:4] == ["-a", ANCHOR, "-t"] and args[4] != TABLE and args[5:] == ["-T", "flush"]:
            self.calls.append(args)
            self.flushed.append(args[4])
            return CommandResult(255, "", "pfctl: Table does not exist.\n")
        if args[1:] == ["-a", GRANTS_ANCHOR, "-F", "rules"]:
            self.calls.append(args)
            self.grants_flushed = True
            return CommandResult(0, "", "rules cleared\n")
        return await super().__call__(argv, stdin)


def targets(tmp_path: Path, launchctl: FakeLaunchctl) -> PurgeTargets:
    state, run, logs = tmp_path / "state", tmp_path / "run", tmp_path / "log"
    for directory in (state, run, logs):
        directory.mkdir(mode=0o755)
    plist = tmp_path / "job.plist"
    plist.write_bytes(b"<plist/>")
    return PurgeTargets(
        jobs=(LaunchdJob("com.example.job", plist, launchctl),),
        reference=PfReference(path=state / "pf-reference.json"),
        state_dir=state,
        state_files=(
            state / "blocklist.txt",
            state / "pf-reference.json",
            state / "pf-reference.json.lock",
            state / "pins.json",
        ),
        run_dir=run,
        run_files=(run / "heartbeat", run / "lock"),
        armed_flag=run / "armed",
        logs=(logs / "boot.log", logs / "watch.log"),
    )


async def test_purge_removes_only_what_safemaxxing_created(tmp_path: Path) -> None:
    launchctl = FakeLaunchctl(loaded=True)
    t = targets(tmp_path, launchctl)
    pf = PurgePf()
    pf.table = {"203.0.113.9"}
    pf.anchor_rules = "block drop out quick all to <safemaxxing_block>\n"
    (t.state_dir / "blocklist.txt").write_text("203.0.113.9\n")
    (t.state_dir / ".blocklist.txt-abc123").write_text("half-written")  # our temp file
    (t.state_dir / "notes.txt").write_text("not ours")
    (t.run_dir / "heartbeat").write_text("1")
    target = tmp_path / "precious"
    target.write_text("keep me")
    os.symlink(target, t.run_dir / "lock")  # a planted link: the link goes, not its target
    t.logs[0].write_text("log\n")

    plan = await planned(t)
    assert any("com.example.job" in line for line in plan)
    assert str(t.state_dir / "blocklist.txt") in plan and str(t.logs[0]) in plan
    assert str(t.state_dir / "notes.txt") not in plan

    steps = await purge(t, pf)
    failed = [s for s in steps if not s.ok]
    assert failed == []
    # launchd: unloaded and its plist gone.
    assert not launchctl.loaded and not t.jobs[0].plist.exists()
    # pf: every table flushed, the anchor emptied, the grants flushed; never `pfctl -d`.
    assert pf.table == set() and pf.anchor_rules == ""
    assert sorted(pf.flushed) == sorted(set(TABLES) - {TABLE}) and pf.grants_flushed
    assert all(call[0] == PFCTL and "-d" not in call for call in pf.calls)
    for call in pf.calls:
        check_pfctl_argv(call)  # raises for anything outside safemaxxing's anchor
    changes = [call for call in pf.calls if call[1:] != ["-s", "info"]]
    assert all(call[1:3] in (["-a", ANCHOR], ["-a", GRANTS_ANCHOR]) for call in changes)
    # Files: ours gone, someone else's kept with its directory, the link's target untouched.
    assert sorted(os.listdir(t.state_dir)) == ["notes.txt"]
    assert not t.run_dir.exists() and target.read_text() == "keep me"
    assert not t.logs[0].exists()
    assert any("kept: not created by safemaxxing: notes.txt" in s.detail for s in steps)


async def test_purge_twice_is_harmless(tmp_path: Path) -> None:
    t = targets(tmp_path, FakeLaunchctl(loaded=False))
    t.jobs[0].plist.unlink()
    pf = PurgePf(enabled=False)
    first = await purge(t, pf)
    assert all(s.ok for s in first)
    second = await purge(t, pf)
    assert all(s.ok for s in second)
    assert not t.state_dir.exists() and not t.run_dir.exists()


def test_purge_refuses_during_paranoia_mode_or_beside_another_instance(tmp_path: Path) -> None:
    t = targets(tmp_path, FakeLaunchctl())
    assert blocker(t, instances=lambda: []) == ""
    assert "pid 77" in blocker(t, instances=lambda: [(77, "safemaxxing watch")])
    t.armed_flag.write_text("")
    assert "Paranoia Mode is on" in blocker(t, instances=lambda: [])


def test_running_instances_never_lists_this_process() -> None:
    assert os.getpid() not in {pid for pid, _ in running_instances()}
