from __future__ import annotations

import json
from pathlib import Path

from test_boot import FakeLaunchctl
from test_firewall import FakePf

from safemaxxing.boot import LaunchdJob
from safemaxxing.diagnostics import Check, Status
from safemaxxing.firewall import ANCHOR, BlockList, PfReference
from safemaxxing.report import (
    ISSUES_URL,
    RENDERERS,
    ReportFormat,
    SecurityReport,
    collect_report,
    redact,
    render_json,
    render_markdown,
    render_text,
)

CHECKS = [Check("root", Status.OK, "uid 0"), Check("full disk access", Status.WARN, "a | b")]


async def collect(tmp_path: Path, root: bool, pf: FakePf | None = None) -> SecurityReport:
    plist = tmp_path / "job.plist"
    plist.write_bytes(b"<plist/>")
    store = BlockList(tmp_path / "blocklist.txt")
    store.add("198.51.100.7")
    return await collect_report(
        run=pf or FakePf(),
        doctor=lambda: CHECKS,
        root=lambda: root,
        jobs=[("watch daemon", LaunchdJob("com.example.watch", plist, FakeLaunchctl(loaded=True)))],
        clock=lambda: 0.0,
        store=store,
        reference=PfReference(path=tmp_path / "pf-reference.json"),
        armed_flag=tmp_path / "armed",
        alerts=lambda: ("ALERT #1 com.example.spy used camera",),
    )


async def test_report_without_root_says_what_needs_it(tmp_path: Path) -> None:
    report = await collect(tmp_path, root=False)
    assert report.pf_enabled is None and report.anchor_rules is None
    assert report.blocked_live is None and report.recent_alerts is None
    assert report.blocked_saved == ("198.51.100.7",)
    assert report.jobs[0].installed and report.jobs[0].loaded
    assert not report.paranoia_armed and report.checks == tuple(CHECKS)
    markdown = render_markdown(report)
    assert "| pf | needs root |" in markdown and "_Needs root._" in markdown


async def test_report_as_root_reads_pf_and_the_alerts(tmp_path: Path) -> None:
    pf = FakePf(enabled=True)
    pf.anchor_rules = "block drop out quick all to <safemaxxing_block>\n"
    pf.table = {"203.0.113.9"}
    report = await collect(tmp_path, root=True, pf=pf)
    assert report.pf_enabled is True and report.blocked_live == ("203.0.113.9",)
    assert report.anchor_rules == ("block drop out quick all to <safemaxxing_block>",)
    assert report.recent_alerts == ("ALERT #1 com.example.spy used camera",)
    # Reading the report changes nothing in pf.
    assert all(
        call[1:] in (["-s", "info"], ["-a", ANCHOR, "-s", "rules"]) or "show" in call
        for call in pf.calls
    )


async def test_every_format_renders_the_same_facts(tmp_path: Path) -> None:
    report = await collect(tmp_path, root=False)
    markdown, text = render_markdown(report), render_text(report)
    data = json.loads(render_json(report))
    assert data["blocked_saved"] == ["198.51.100.7"]
    assert data["checks"][1] == {"name": "full disk access", "status": "warn", "detail": "a | b"}
    assert "198.51.100.7" in markdown and "198.51.100.7" in text
    assert "| full disk access | warn | a / b |" in markdown  # a pipe would break the table
    assert "[warn] full disk access" in text
    assert ISSUES_URL in markdown and "nothing was sent anywhere" in markdown
    assert set(RENDERERS) == set(ReportFormat)


def test_redact_hides_addresses_paths_and_names_but_keeps_their_shape() -> None:
    text = (
        "blocked 203.0.113.9 and 2001:db8::1; again 203.0.113.9; loopback 127.0.0.1 and ::1\n"
        "log /Users/alice/Library/Logs/x.log on alice-mbp.local as alice\n"
        "version 1.2.3.4-not-an-ip? port 10.0.0.300\n"
    )
    out = redact(text, identities=["alice", "alice-mbp.local", "alice-mbp"])
    assert "203.0.113.9" not in out and "2001:db8::1" not in out
    assert out.count("<ip-1>") == 2 and "<ip-2>" in out  # the same address, the same mark
    assert "127.0.0.1" in out and " ::1" in out
    assert "/Users/<user>/Library/Logs/x.log" in out
    assert "alice" not in out and "<redacted>" in out
    assert "10.0.0.300" in out  # not an address: left alone
