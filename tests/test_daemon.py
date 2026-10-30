from __future__ import annotations

import json
import os
import plistlib
import stat
from collections.abc import Sequence
from pathlib import Path

import pytest

from safemaxxing.daemon import (
    ERR_LOG,
    LABEL,
    LOG,
    THROTTLE_S,
    WatchDaemon,
    WatchOptions,
    daemon_plist,
    parse_print,
    recent_alerts,
    unsafe_reason,
)
from safemaxxing.firewall import CommandResult

LAUNCHCTL_PRINT = """system/io.github.carlobaratta.safemaxxing.watch = {
\tactive count = 1
\tpath = /Library/LaunchDaemons/io.github.carlobaratta.safemaxxing.watch.plist
\tstate = running

\tprogram = /usr/local/libexec/safemaxxing/safemaxxing
\tpid = 4242
\tlast exit code = 1

\tendpoints = {
\t\t"com.example" = {
\t\t\tstate = active
\t\t}
\t}
}
"""


def test_default_options_spell_out_every_value() -> None:
    assert WatchOptions().arguments() == [
        "--json",
        "--window-ms=2000",
        "--decay-window-ms=0",
        "--poll-ms=200",
        "--min-severity=high",
    ]


def test_options_add_flags_and_sorted_unique_ignores() -> None:
    options = WatchOptions(
        ignore=("com.b", "com.a", "com.b"), udp_flows=True, auto_block=True, min_severity="medium"
    )
    args = options.arguments()
    assert args[:5] == [
        "--json",
        "--window-ms=2000",
        "--decay-window-ms=0",
        "--poll-ms=200",
        "--min-severity=medium",
    ]
    assert args[5:] == ["--ignore=com.a", "--ignore=com.b", "--udp-flows", "--auto-block"]


def test_plist_runs_watch_and_restarts_it() -> None:
    exe = "/usr/local/libexec/safemaxxing/safemaxxing"
    job = plistlib.loads(daemon_plist(exe, WatchOptions(include_system=True)))
    assert job["Label"] == LABEL
    assert job["ProgramArguments"][:3] == [exe, "watch", "--json"]
    assert job["ProgramArguments"][-1] == "--include-system"
    assert job["RunAtLoad"] is True and job["KeepAlive"] is True
    assert job["ThrottleInterval"] == THROTTLE_S
    assert job["StandardOutPath"] == str(LOG)
    assert job["StandardErrorPath"] == str(ERR_LOG)


def make_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "libexec" / "safemaxxing"
    (bundle / "_internal").mkdir(parents=True)
    exe = bundle / "safemaxxing"
    exe.write_text("")
    exe.chmod(0o755)
    (bundle / "_internal" / "Python").write_text("")
    for d in (tmp_path, tmp_path / "libexec", bundle, bundle / "_internal"):
        d.chmod(0o755)
    return exe


def check(exe: Path, tmp_path: Path) -> str:
    # The test files are ours, so "root" here is our own uid.
    return unsafe_reason(exe, frozen=True, owners=frozenset({os.getuid()}), top=tmp_path)


def test_a_root_owned_frozen_bundle_is_accepted(tmp_path: Path) -> None:
    exe = make_bundle(tmp_path)
    (exe.parent / "_internal" / "link").symlink_to("Python")
    assert check(exe, tmp_path) == ""


def test_a_source_checkout_is_refused(tmp_path: Path) -> None:
    assert "source checkout" in unsafe_reason(make_bundle(tmp_path), frozen=False)


def test_a_file_owned_by_another_user_is_refused(tmp_path: Path) -> None:
    exe = make_bundle(tmp_path)
    problem = unsafe_reason(exe, frozen=True, owners=frozenset({0}), top=tmp_path)
    assert f"uid {os.getuid()}" in problem


def test_a_group_writable_library_is_refused(tmp_path: Path) -> None:
    exe = make_bundle(tmp_path)
    lib = exe.parent / "_internal" / "Python"
    lib.chmod(0o664)
    assert check(exe, tmp_path) == f"{lib.resolve()} is writable by its group or by everyone"


def test_a_world_writable_parent_is_refused(tmp_path: Path) -> None:
    exe = make_bundle(tmp_path)
    (tmp_path / "libexec").chmod(0o777)
    assert "libexec is writable" in check(exe, tmp_path)


def test_a_symlink_out_of_the_bundle_is_refused(tmp_path: Path) -> None:
    exe = make_bundle(tmp_path)
    outside = tmp_path / "evil.dylib"
    outside.write_text("")
    (exe.parent / "_internal" / "libfoo.dylib").symlink_to(outside)
    assert "points outside" in check(exe, tmp_path)


def test_an_executable_reached_through_a_symlink_is_checked_where_it_lives(
    tmp_path: Path,
) -> None:
    exe = make_bundle(tmp_path)
    link = tmp_path / "bin" / "safemaxxing"
    link.parent.mkdir(mode=0o755)
    link.symlink_to(exe)
    (exe.parent / "_internal" / "Python").chmod(0o666)
    assert "writable" in check(link, tmp_path)


def test_parse_print_reports_the_signal_that_killed_the_job() -> None:
    # As seen after `pkill` on macOS 27: launchd restarted the job (runs = 2).
    text = (
        "\tstate = running\n\truns = 2\n\tpid = 7074\n\tlast terminating signal = Terminated: 15\n"
    )
    assert parse_print(text) == ("running", 7074, "Terminated: 15")


def test_parse_print_takes_the_jobs_own_fields() -> None:
    assert parse_print(LAUNCHCTL_PRINT) == ("running", 4242, "1")
    assert parse_print("\tstate = not running\n\tlast exit code = 0\n") == (
        "not running",
        None,
        "0",
    )


class FakeLaunchctl:
    def __init__(self, bootstrap_rc: int = 0) -> None:
        self.bootstrap_rc = bootstrap_rc
        self.loaded = False
        self.calls: list[list[str]] = []

    async def __call__(self, argv: Sequence[str], stdin: str | None = None) -> CommandResult:
        args = list(argv)
        self.calls.append(args)
        if args[1] == "bootstrap":
            self.loaded = self.bootstrap_rc == 0
            return CommandResult(self.bootstrap_rc, "", "Bootstrap failed: 5: I/O error\n")
        if args[1] == "bootout":
            self.loaded = False
            return CommandResult(0, "", "")
        if args[1] == "print":
            return (
                CommandResult(0, LAUNCHCTL_PRINT, "") if self.loaded else CommandResult(113, "", "")
            )
        raise AssertionError(f"unexpected launchctl call: {args}")


async def test_install_reloads_and_status_reads_launchd(tmp_path: Path) -> None:
    launchctl = FakeLaunchctl()
    daemon = WatchDaemon(runner=launchctl, plist=tmp_path / f"{LABEL}.plist")
    assert await daemon.install("/opt/sm/safemaxxing", WatchOptions(udp_flows=True)) == ""
    assert stat.S_IMODE(daemon.plist.stat().st_mode) == 0o644
    assert [c[1] for c in launchctl.calls] == ["bootout", "bootstrap"]
    assert launchctl.calls[0][2] == f"system/{LABEL}"
    status = await daemon.daemon_status()
    assert (status.installed, status.loaded, status.state, status.pid) == (
        True,
        True,
        "running",
        4242,
    )
    assert status.arguments[:2] == ("/opt/sm/safemaxxing", "watch")
    assert "--udp-flows" in status.arguments


async def test_install_reports_bootstrap_failure(tmp_path: Path) -> None:
    daemon = WatchDaemon(runner=FakeLaunchctl(bootstrap_rc=5), plist=tmp_path / "x.plist")
    assert await daemon.install("/x", WatchOptions()) == "Bootstrap failed: 5: I/O error"


async def test_uninstall_stops_and_deletes(tmp_path: Path) -> None:
    daemon = WatchDaemon(runner=FakeLaunchctl(), plist=tmp_path / f"{LABEL}.plist")
    await daemon.install("/x", WatchOptions())
    await daemon.uninstall()
    status = await daemon.daemon_status()
    assert not status.installed and not status.loaded and status.arguments == ()


def test_recent_alerts_summarises_the_last_lines(tmp_path: Path) -> None:
    log = tmp_path / "watch.log"
    alerts = [{"severity": "high", "summary": f"alert {i}"} for i in range(7)]
    log.write_text("".join(json.dumps(a) + "\n" for a in alerts) + "not json\n")
    assert recent_alerts(log, count=3) == ["[high] alert 5", "[high] alert 6", "not json"]
    assert recent_alerts(tmp_path / "missing.log") == []


@pytest.fixture
def cli_as_root(monkeypatch: pytest.MonkeyPatch) -> None:
    from safemaxxing import cli

    monkeypatch.setattr(cli, "is_root", lambda: True)


def test_daemon_install_needs_root(monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from safemaxxing import cli

    monkeypatch.setattr(cli, "is_root", lambda: False)
    result = CliRunner().invoke(cli.app, ["daemon", "install"])
    assert result.exit_code == 1
    assert "needs root" in result.output


@pytest.mark.usefixtures("cli_as_root")
def test_daemon_install_refuses_a_source_checkout(monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from safemaxxing import cli

    def never(*_: object) -> None:
        raise AssertionError("must not reach launchd")

    monkeypatch.setattr(cli.WatchDaemon, "install", never)
    result = CliRunner().invoke(cli.app, ["daemon", "install"])
    assert result.exit_code == 1
    assert "refusing to install the daemon" in result.output


@pytest.mark.usefixtures("cli_as_root")
def test_daemon_install_rejects_an_unknown_severity() -> None:
    from typer.testing import CliRunner

    from safemaxxing import cli

    result = CliRunner().invoke(cli.app, ["daemon", "install", "--min-severity", "loud"])
    assert result.exit_code != 0
    assert "unknown severity" in result.output
