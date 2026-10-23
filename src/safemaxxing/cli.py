"""Command-line entry point."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from safemaxxing import __version__
from safemaxxing.correlation import CorrelationConfig
from safemaxxing.diagnostics import Status, collect_log_sample, run_doctor, summarize_sample
from safemaxxing.firewall import PfFirewall, ProcessController, is_root
from safemaxxing.models import ActionResult, Alert, Event, Severity
from safemaxxing.sensors import (
    DISCOVERY_PREDICATE,
    WIDE_DISCOVERY_PREDICATE,
    SensorError,
)
from safemaxxing.supervisor import Supervisor

app = typer.Typer(
    name="safemaxxing",
    help="Privacy supervisor & egress firewall for macOS (sensor → network correlation).",
    no_args_is_help=True,
)
console = Console()

WindowMs = Annotated[int, typer.Option("--window-ms", help="Correlation window in ms.", min=1)]
PollMs = Annotated[int, typer.Option("--poll-ms", help="Socket table poll interval in ms.", min=20)]
Loopback = Annotated[bool, typer.Option("--include-loopback", help="Also track 127.0.0.1/::1.")]
NoDns = Annotated[bool, typer.Option("--no-dns", help="Disable reverse DNS lookups.")]
IncludeSystem = Annotated[
    bool,
    typer.Option(
        "--include-system", help="Also correlate sockets of SIP-protected Apple binaries."
    ),
]
IncludeDns = Annotated[
    bool, typer.Option("--include-dns", help="Also alert on DNS lookups (ports 53/853/5353).")
]
Ignore = Annotated[
    list[str] | None,
    typer.Option("--ignore", help="Bundle id or process name to ignore (repeatable)."),
]


def _supervisor(
    window_ms: int,
    poll_ms: int,
    include_loopback: bool,
    no_dns: bool,
    ignore: list[str] | None,
    include_system: bool,
    include_dns: bool,
) -> Supervisor:
    config = CorrelationConfig(
        window_s=window_ms / 1000,
        ignore=frozenset(ignore or ()),
        include_system=include_system,
        include_dns=include_dns,
    )
    return Supervisor.default(
        config=config,
        poll_interval_s=poll_ms / 1000,
        include_loopback=include_loopback,
        resolve_hostnames=not no_dns,
    )


def _warn_if_not_root() -> None:
    if not is_root():
        console.print(
            "[yellow]Not running as root: other users' sockets, pfctl and signalling "
            "foreign processes will be unavailable. Use sudo for full coverage.[/]"
        )


def _print_result(result: ActionResult) -> None:
    style = "green" if result.ok else "bold red"
    verdict = "ok" if result.ok else "failed"
    console.print(f"[{style}]{result.kind.value} {result.target}: {verdict}[/] {result.detail}")
    if not result.ok:
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Print the version."""
    console.print(__version__)


@app.command()
def tui(
    window_ms: WindowMs = 2000,
    poll_ms: PollMs = 200,
    include_loopback: Loopback = False,
    no_dns: NoDns = False,
    ignore: Ignore = None,
    include_system: IncludeSystem = False,
    include_dns: IncludeDns = False,
) -> None:
    """Interactive dashboard."""
    from safemaxxing.tui.app import SafemaxxingApp

    _warn_if_not_root()
    supervisor = _supervisor(
        window_ms, poll_ms, include_loopback, no_dns, ignore, include_system, include_dns
    )
    SafemaxxingApp(supervisor).run()


def _alert_json(alert: Alert) -> str:
    payload = dataclasses.asdict(alert)
    payload["severity"] = alert.severity.label
    payload["sensors"] = sorted(s.value for s in alert.sensors)
    payload["summary"] = alert.summary
    return json.dumps(payload, default=str)


@app.command()
def watch(
    window_ms: WindowMs = 2000,
    poll_ms: PollMs = 200,
    include_loopback: Loopback = False,
    no_dns: NoDns = False,
    ignore: Ignore = None,
    include_system: IncludeSystem = False,
    include_dns: IncludeDns = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit alerts as JSON lines.")] = False,
    show_events: Annotated[
        bool, typer.Option("--events", help="Also print sensor events.")
    ] = False,
    auto_block: Annotated[
        bool, typer.Option("--auto-block", help="Block the destination IP of qualifying alerts.")
    ] = False,
    auto_suspend: Annotated[
        bool, typer.Option("--auto-suspend", help="SIGSTOP the process of qualifying alerts.")
    ] = False,
    min_severity: Annotated[
        str, typer.Option("--min-severity", help="Threshold for --auto-* actions.")
    ] = "high",
) -> None:
    """Headless mode: stream alerts to stdout, optionally enforcing automatically."""
    try:
        threshold = Severity[min_severity.upper()]
    except KeyError:
        raise typer.BadParameter(f"unknown severity {min_severity!r}") from None
    if not as_json:
        _warn_if_not_root()
    supervisor = _supervisor(
        window_ms, poll_ms, include_loopback, no_dns, ignore, include_system, include_dns
    )
    firewall, processes = PfFirewall(), ProcessController()

    async def loop() -> None:
        enforced: set[int] = set()
        async for update in supervisor.stream():
            hidden = isinstance(update, Event) and update.system and not include_system
            if isinstance(update, Event) and show_events and not as_json and not hidden:
                service = f" ({update.service})" if update.service else ""
                console.print(
                    f"[dim]{update.sensor.value:<14}[/] {escape(update.identity)} "
                    f"pid={update.pid}[dim]{escape(service)}[/]"
                )
            if not isinstance(update, Alert):
                continue
            if as_json:
                print(_alert_json(update), flush=True)
            else:
                tag = f"ALERT #{update.id}" + (" updated" if update.updated else "")
                console.print(
                    f"[bold red]{tag}[/] {escape(f'[{update.severity.label}]')} "
                    f"{escape(update.summary)}"
                )
            # An updated alert may cross the threshold later; act at most once per alert.
            if update.severity < threshold or update.id in enforced:
                continue
            enforced.add(update.id)
            conn = update.finding.connection
            results: list[ActionResult] = []
            if auto_block:
                results.append(await firewall.block(conn.remote_address))
            if auto_suspend:
                results.append(processes.suspend(conn.pid))
            for result in results:
                if not as_json:
                    console.print(f"  -> {result.kind.value} {result.target}: ok={result.ok}")

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(loop())


@app.command()
def block(ip: str) -> None:
    """Add an IP to the safemaxxing_block pf table."""
    _print_result(asyncio.run(PfFirewall().block(ip)))


@app.command()
def unblock(ip: str) -> None:
    """Remove an IP from the safemaxxing_block pf table."""
    _print_result(asyncio.run(PfFirewall().unblock(ip)))


@app.command()
def blocked() -> None:
    """List blocked IPs."""
    for ip in asyncio.run(PfFirewall().blocked()):
        console.print(ip)


@app.command()
def flush() -> None:
    """Remove every IP from the block table."""
    _print_result(asyncio.run(PfFirewall().flush()))


@app.command()
def freeze(pid: int) -> None:
    """Suspend a process (SIGSTOP)."""
    _print_result(ProcessController().suspend(pid))


@app.command()
def thaw(pid: int) -> None:
    """Resume a suspended process (SIGCONT)."""
    _print_result(ProcessController().resume(pid))


@app.command()
def kill(pid: int) -> None:
    """Terminate a process (SIGKILL)."""
    _print_result(ProcessController().kill(pid))


_STATUS_STYLE = {Status.OK: "[green]✔", Status.WARN: "[yellow]!", Status.FAIL: "[red]✘"}


@app.command()
def doctor(poll_ms: PollMs = 200) -> None:
    """Check root, pf state/anchor, socket visibility, Full Disk Access and log predicates."""
    checks = run_doctor(poll_interval_s=poll_ms / 1000)
    for check in checks:
        console.print(
            f"{_STATUS_STYLE[check.status]}[/] {check.name}: [dim]{escape(check.detail)}[/]"
        )
    if any(c.status is Status.FAIL for c in checks):
        raise typer.Exit(1)


@app.command()
def sample(
    seconds: Annotated[float, typer.Option("--seconds", min=0.5)] = 5.0,
    out: Annotated[
        Path | None, typer.Option("--out", help="Write raw entries as JSON lines.")
    ] = None,
    debug: Annotated[
        bool, typer.Option("--debug", help="Use `--level debug` (much noisier, finds more).")
    ] = False,
    wide: Annotated[
        bool,
        typer.Option("--wide", help="Search every subsystem by keyword (camera, mic, TCC)."),
    ] = False,
) -> None:
    """Capture real `log stream` output and report redaction / parser coverage."""
    predicate = WIDE_DISCOVERY_PREDICATE if wide else DISCOVERY_PREDICATE
    level = "debug" if debug else "info"
    try:
        entries = asyncio.run(collect_log_sample(seconds, level=level, predicate=predicate))
    except (OSError, SensorError) as exc:
        console.print(f"[bold red]log stream failed:[/] {exc}")
        raise typer.Exit(1) from None
    if out is not None:
        with out.open("w") as fh:
            for entry in entries:
                fh.write(json.dumps(entry) + "\n")
    table = Table(title=f"log stream sample: {len(entries)} entries in {seconds:g}s")
    for column in ("subsystem", "entries", "<private> msg", "no image path", "no pid"):
        table.add_column(column)
    for column in ("parsed", "w/ pid", "w/ bundle", "top processes"):
        table.add_column(column)
    stats = summarize_sample(entries)
    for name, s in sorted(stats.items()):
        top = ", ".join(f"{p}×{n}" for p, n in s.processes.most_common(3))
        table.add_row(
            name,
            *map(str, (s.entries, s.redacted_message, s.redacted_image_path, s.missing_pid)),
            *map(str, (s.parsed, s.with_pid, s.with_bundle)),
            top,
        )
    console.print(table)
    for name, s in sorted(stats.items()):
        for example in s.unparsed_examples:
            console.print(f"[dim]unparsed {name}:[/] {escape(example)}")
        if s.parsed:
            sensors = ", ".join(f"{k}×{v}" for k, v in s.sensors.most_common())
            levels = ", ".join(f"{k}×{v}" for k, v in s.levels.most_common())
            console.print(f"[bold]{name}[/]: {escape(sensors)}  levels: {escape(levels)}")
        for example in s.parsed_examples:
            console.print(f"[green]parsed {name}:[/] {escape(example)}")


if __name__ == "__main__":
    app()
