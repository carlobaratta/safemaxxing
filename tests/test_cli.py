"""The CLI commands this audit added or hardened, driven through Typer with fakes for pf,
launchd and signals: nothing here touches the real firewall, jobs or processes."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest
from test_boot import FakeLaunchctl
from test_purge import PurgePf, targets
from typer.testing import CliRunner

from safemaxxing import cli
from safemaxxing.firewall import ProcessController
from safemaxxing.purge import PurgeTargets, blocker, purge
from safemaxxing.report import SecurityReport

LOGINWINDOW = "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"
ENV = {"COLUMNS": "200", "NO_COLOR": "1"}


def invoke(*args: str, stdin: str | None = None) -> Any:
    return CliRunner().invoke(cli.app, list(args), input=stdin, env=ENV)


@pytest.fixture
def purge_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[PurgeTargets, PurgePf]:
    t = targets(tmp_path, FakeLaunchctl(loaded=True))
    (t.state_dir / "blocklist.txt").write_text("203.0.113.9\n")
    pf = PurgePf()

    async def run_purge(found: PurgeTargets) -> Any:
        return await purge(found, pf)

    monkeypatch.setattr(cli, "purge_targets", lambda: t)
    monkeypatch.setattr(cli, "run_purge", run_purge)
    monkeypatch.setattr(cli, "purge_blocker", lambda found: blocker(found, instances=lambda: []))
    return t, pf


def test_purge_dry_run_lists_and_removes_nothing(purge_setup: Any) -> None:
    t, _ = purge_setup
    result = invoke("purge", "--dry-run")
    assert result.exit_code == 0, result.output
    assert "com.example.job" in result.output and "blocklist.txt" in result.output
    assert (t.state_dir / "blocklist.txt").exists()


def test_purge_needs_root_and_a_yes(purge_setup: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    t, _ = purge_setup
    monkeypatch.setattr(cli, "is_root", lambda: False)
    assert "needs root" in invoke("purge").output
    monkeypatch.setattr(cli, "is_root", lambda: True)
    result = invoke("purge", stdin="n\n")
    assert result.exit_code == 1 and "nothing removed" in result.output
    assert (t.state_dir / "blocklist.txt").exists() and t.jobs[0].plist.exists()


def test_purge_yes_removes_everything(purge_setup: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    t, pf = purge_setup
    monkeypatch.setattr(cli, "is_root", lambda: True)
    result = invoke("purge", "--yes")
    assert result.exit_code == 0, result.output
    assert not t.state_dir.exists() and not t.jobs[0].plist.exists()
    assert pf.anchor_rules == "" and "✘" not in result.output


def test_purge_refuses_while_paranoia_mode_is_on(
    purge_setup: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    t, _ = purge_setup
    monkeypatch.setattr(cli, "is_root", lambda: True)
    t.armed_flag.write_text("")
    result = invoke("purge", "--yes")
    assert result.exit_code == 1 and "Paranoia Mode is on" in result.output
    assert (t.state_dir / "blocklist.txt").exists()


REPORT = SecurityReport(
    generated="2026-11-27 10:00:00 +0100",
    version="0.0.0",
    macos="26.1 (arm64)",
    root=True,
    pf_enabled=True,
    anchor_rules=("block drop out quick all to <safemaxxing_block>",),
    blocked_live=("203.0.113.9",),
    blocked_saved=("203.0.113.9",),
    jobs=(),
    paranoia_armed=False,
    pf_reference_held=True,
)


@pytest.fixture
def fixed_report(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def collect(**kwargs: Any) -> SecurityReport:
        calls.append(kwargs)
        return REPORT

    monkeypatch.setattr(cli, "collect_report", collect)
    return calls


def test_report_writes_a_private_file(fixed_report: Any, tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = invoke("report", "--format", "json", "--no-checks", "--out", str(out))
    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert json.loads(out.read_text())["blocked_live"] == ["203.0.113.9"]
    assert fixed_report[0]["checks"] is False


def test_report_refuses_to_write_through_a_symlink(fixed_report: Any, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("keep")
    link = tmp_path / "report.md"
    link.symlink_to(target)
    result = invoke("report", "--out", str(link))
    assert result.exit_code == 1 and target.read_text() == "keep"


def test_report_redact_prints_no_address(fixed_report: Any) -> None:
    result = invoke("report", "--redact", "--format", "text")
    assert result.exit_code == 0
    assert "203.0.113.9" not in result.stdout and "<ip-1>" in result.stdout


def fake_processes(monkeypatch: pytest.MonkeyPatch, exe: str | None) -> list[tuple[int, int]]:
    sent: list[tuple[int, int]] = []
    controller = ProcessController(
        kill=lambda pid, sig: sent.append((pid, sig)), exe_of=lambda p: exe
    )
    monkeypatch.setattr(cli, "ProcessController", lambda: controller)
    return sent


def test_freezing_a_system_process_asks_first(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = fake_processes(monkeypatch, LOGINWINDOW)
    result = invoke("freeze", "4242", stdin="n\n")
    assert result.exit_code == 1 and sent == []
    assert "macOS system process" in result.output
    assert invoke("freeze", "4242", "--yes").exit_code == 0 and len(sent) == 1


def test_killing_an_ordinary_process_does_not_ask(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = fake_processes(monkeypatch, "/Applications/Spy.app/Contents/MacOS/spy")
    result = invoke("kill", "4242")
    assert result.exit_code == 0 and len(sent) == 1 and "system process" not in result.output
