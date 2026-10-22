from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest
from test_firewall import ALTQ, DEFAULT_MAIN_RULES

from safemaxxing.diagnostics import (
    Status,
    check_full_disk_access,
    check_log_predicate,
    check_pf_anchor,
    check_pf_status,
    check_root,
    check_snapshot_latency,
    check_socket_visibility,
    collect_log_sample,
    parse_lsof_owners,
    summarize_sample,
)
from safemaxxing.firewall import ANCHOR, TABLE, CommandResult


def fixed(mapping: dict[tuple[str, ...], CommandResult]):  # type: ignore[no-untyped-def]
    def run(argv: Sequence[str], timeout_s: float) -> CommandResult:
        return mapping[tuple(argv[1:])]

    return run


def test_root_check() -> None:
    assert check_root(0).status is Status.OK
    assert check_root(501).status is Status.FAIL


def test_pf_status_states() -> None:
    enabled = fixed({("-s", "info"): CommandResult(0, "Status: Enabled for 1 days", ALTQ)})
    disabled = fixed({("-s", "info"): CommandResult(0, "Status: Disabled   Debug: Urgent", ALTQ)})
    denied = fixed({("-s", "info"): CommandResult(1, "", "pfctl: /dev/pf: Permission denied")})
    assert check_pf_status(enabled).status is Status.OK
    assert check_pf_status(disabled).status is Status.WARN
    result = check_pf_status(denied)
    assert result.status is Status.WARN and "needs root" in result.detail


def test_pf_anchor_without_root_is_not_reported_as_missing() -> None:
    # Real macOS 27.0.1 output of `safemaxxing doctor` without sudo.
    denied = CommandResult(1, "", "pfctl: /dev/pf: Permission denied")
    run = fixed({("-s", "rules"): denied, ("-a", ANCHOR, "-s", "rules"): denied})
    checks = check_pf_anchor(run)
    assert [c.status for c in checks] == [Status.WARN, Status.WARN]
    assert all("needs root" in c.detail and "/etc/pf.conf" not in c.detail for c in checks)


def test_pf_anchor_checks() -> None:
    good = fixed(
        {
            ("-s", "rules"): CommandResult(0, DEFAULT_MAIN_RULES, ALTQ),
            ("-a", ANCHOR, "-s", "rules"): CommandResult(
                0, f"block drop out quick all to <{TABLE}>", ALTQ
            ),
        }
    )
    parent, ours = check_pf_anchor(good)
    assert parent.status is Status.OK and ours.status is Status.OK
    broken = fixed(
        {
            ("-s", "rules"): CommandResult(0, "", ALTQ),
            ("-a", ANCHOR, "-s", "rules"): CommandResult(
                1, "", ALTQ + "pfctl: Anchor does not exist."
            ),
        }
    )
    parent, ours = check_pf_anchor(broken)
    assert parent.status is Status.FAIL and "/etc/pf.conf" in parent.detail
    assert ours.status is Status.OK and "not created yet" in ours.detail


def test_pf_anchor_reports_real_errors() -> None:
    run = fixed(
        {
            ("-s", "rules"): CommandResult(0, DEFAULT_MAIN_RULES, ALTQ),
            ("-a", ANCHOR, "-s", "rules"): CommandResult(
                1, "", "pfctl: /dev/pf: Permission denied"
            ),
        }
    )
    _, ours = check_pf_anchor(run)
    assert ours.status is Status.FAIL and "Permission denied" in ours.detail


LSOF_OWNERS = "p1\nLroot\nf5\np222\nL_mdnsresponder\np4242\nLcarlo\n"


def test_socket_visibility() -> None:
    assert parse_lsof_owners(LSOF_OWNERS) == {1: "root", 222: "_mdnsresponder", 4242: "carlo"}
    run = fixed({("-nP", "-iTCP", "-iUDP", "-FpL"): CommandResult(0, LSOF_OWNERS, "")})
    assert check_socket_visibility(run, user="root").status is Status.OK
    own_only = fixed({("-nP", "-iTCP", "-iUDP", "-FpL"): CommandResult(0, "p4242\nLcarlo\n", "")})
    assert check_socket_visibility(own_only, user="carlo").status is Status.WARN


def test_socket_visibility_distinguishes_daemons_and_lsof_failure() -> None:
    argv = ("-nP", "-iTCP", "-iUDP", "-FpL")
    # lsof exits 1 on partially unreadable fds; what it did print still counts.
    partial = fixed({argv: CommandResult(1, LSOF_OWNERS, "lsof: WARNING: can't stat()")})
    check = check_socket_visibility(partial, user="carlo")
    assert check.status is Status.OK and "_mdnsresponder" in check.detail
    users_only = fixed({argv: CommandResult(0, "p1\nLalice\np2\nLcarlo\n", "")})
    assert check_socket_visibility(users_only, user="carlo").status is Status.WARN
    missing = fixed({argv: CommandResult(127, "", "/usr/sbin/lsof: not found")})
    check = check_socket_visibility(missing, user="carlo")
    assert check.status is Status.FAIL and "not found" in check.detail


def test_full_disk_access(tmp_path: Path) -> None:
    readable = tmp_path / "TCC.db"
    readable.write_bytes(b"SQLite format 3\x00")
    assert check_full_disk_access(str(readable)).status is Status.OK
    locked = tmp_path / "locked.db"
    locked.write_bytes(b"x")
    locked.chmod(0)
    expected = Status.OK if __import__("os").geteuid() == 0 else Status.WARN
    assert check_full_disk_access(str(locked)).status is expected


def test_snapshot_latency_threshold() -> None:
    assert check_snapshot_latency(0.2, snapshot=lambda now: []).status is Status.OK
    slow = check_snapshot_latency(0.0, snapshot=lambda now: [])
    assert slow.status is Status.WARN


def test_log_predicate_check() -> None:
    streaming = lambda argv, t: CommandResult(-1, "", "timeout")  # noqa: E731
    rejected = lambda argv, t: CommandResult(65, "", "log: Invalid predicate")  # noqa: E731
    assert check_log_predicate(streaming).status is Status.OK
    result = check_log_predicate(rejected)
    assert result.status is Status.FAIL and "Invalid predicate" in result.detail


def test_summarize_sample_reports_redaction_and_coverage() -> None:
    entries: list[dict[str, object]] = [
        {
            "subsystem": "com.apple.TCC",
            "processID": 180,
            "processImagePath": "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
            "eventMessage": "AUTHREQ_CTX: sender_pid=4242, service=kTCCServiceCamera",
            "timestamp": "2026-10-22 10:00:00.000000+0000",
        },
        {
            "subsystem": "com.apple.TCC",
            "processID": 180,
            "processImagePath": "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
            "eventMessage": "AUTHREQ_SUBJECT: subject=<private>, service=kTCCServiceCamera",
        },
        {
            "subsystem": "com.apple.cmio.Device",
            "processImagePath": "<private>",
            "eventMessage": "x",
        },
    ]
    stats = summarize_sample(entries)
    tcc, cmio = stats["com.apple.TCC"], stats["com.apple.cmio"]
    assert (tcc.entries, tcc.parsed, tcc.with_pid, tcc.redacted_message) == (2, 1, 1, 1)
    assert tcc.processes["tccd"] == 2
    assert tcc.unparsed_examples == [
        "AUTHREQ_SUBJECT: subject=<private>, service=kTCCServiceCamera"
    ]
    assert (cmio.redacted_image_path, cmio.missing_pid) == (1, 1)


async def test_collect_log_sample_stops_after_timeout(tmp_path: Path) -> None:
    script = (
        "import sys, time, json\n"
        "sys.stdout.write('[' + json.dumps({'subsystem': 'com.apple.TCC'}) + ',')\n"
        "sys.stdout.flush(); time.sleep(30)\n"
    )
    import sys

    entries = await collect_log_sample(0.5, command=[sys.executable, "-c", script])
    assert entries == [{"subsystem": "com.apple.TCC"}]
    json.dumps(entries)


def test_doctor_cli_renders_every_status(monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from safemaxxing import cli
    from safemaxxing.diagnostics import Check

    checks = [
        Check("a", Status.OK, "fine"),
        Check("b", Status.WARN, "[2001:db8::1] looks like markup"),
        Check("c", Status.FAIL, "broken"),
    ]
    monkeypatch.setattr(cli, "run_doctor", lambda poll_interval_s: checks)
    result = CliRunner().invoke(cli.app, ["doctor"])
    assert result.exit_code == 1
    assert "[2001:db8::1] looks like markup" in result.output


def test_summary_shows_category_and_parsed_examples() -> None:
    entries: list[dict[str, object]] = [
        {"subsystem": "com.apple.controlcenter", "category": "sensor", "eventMessage": "Cameras"},
        {
            "subsystem": "com.apple.TCC",
            "processImagePath": "/usr/libexec/tccd",
            "eventMessage": "sender_pid=42, service=kTCCServiceCamera",
        },
    ]
    stats = summarize_sample(entries)
    assert stats["com.apple.controlcenter"].unparsed_examples == ["[sensor] Cameras"]
    assert stats["com.apple.TCC"].parsed_examples == [
        "camera pid:42 pid=42 [?] sender_pid=42, service=kTCCServiceCamera"
    ]


def test_summary_counts_sensors_and_log_levels() -> None:
    entries: list[dict[str, object]] = [
        {
            "subsystem": "com.apple.cmio",
            "messageType": "Debug",
            "processID": 34654,
            "processImagePath": "/System/Applications/Photo Booth.app/Contents/MacOS/Photo Booth",
            "eventMessage": "CMIODevice startStream",
        }
    ]
    s = summarize_sample(entries)["com.apple.cmio"]
    assert s.sensors == {"camera": 1} and s.levels == {"Debug": 1}
    assert "[Debug] CMIODevice startStream" in s.parsed_examples[0]
