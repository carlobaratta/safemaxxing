"""Command-line entry point."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from safemaxxing import __version__
from safemaxxing.boot import LOG, PLIST, BootJob
from safemaxxing.correlation import CorrelationConfig
from safemaxxing.daemon import ERR_LOG as DAEMON_ERR_LOG
from safemaxxing.daemon import LOG as DAEMON_LOG
from safemaxxing.daemon import PLIST as DAEMON_PLIST
from safemaxxing.daemon import WatchDaemon, WatchOptions, recent_alerts, unsafe_reason
from safemaxxing.diagnostics import Status, collect_log_sample, run_doctor, summarize_sample
from safemaxxing.firewall import BLOCKLIST, BlockList, PfFirewall, ProcessController, is_root
from safemaxxing.lockdown.controller import LockdownController
from safemaxxing.lockdown.dns import BLOCKLIST_CACHE, fetch_blocklist, load_blocklist
from safemaxxing.lockdown.sni import client_hellos
from safemaxxing.lockdown.watchdog import PLIST as WATCHDOG_PLIST
from safemaxxing.lockdown.watchdog import WatchdogJob
from safemaxxing.models import ActionResult, Alert, Event, IndicatorState, Severity
from safemaxxing.pktap import pktap_unavailable
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
boot_app = typer.Typer(
    help="Reapply saved blocks after a reboot with a launchd job (install/uninstall need root).",
    no_args_is_help=True,
)
app.add_typer(boot_app, name="boot")
daemon_app = typer.Typer(
    help="Keep `watch --json` running as root in the background with a launchd daemon "
    "(install/uninstall need root; installs only from the root-owned .pkg build).",
    no_args_is_help=True,
)
app.add_typer(daemon_app, name="daemon")
paranoia_app = typer.Typer(
    help="Paranoia Mode: the dead-man watchdog and the DNS blocklist.", no_args_is_help=True
)
app.add_typer(paranoia_app, name="paranoia")

WindowMs = Annotated[int, typer.Option("--window-ms", help="Correlation window in ms.", min=1)]
DecayWindowMs = Annotated[
    int,
    typer.Option(
        "--decay-window-ms",
        help="Adaptive decay window in ms: still correlate a connection up to this long after a "
        "sensor access (fading confidence, one severity step lower). 0 disables it.",
        min=0,
    ),
]
PollMs = Annotated[int, typer.Option("--poll-ms", help="Socket table poll interval in ms.", min=20)]
Loopback = Annotated[bool, typer.Option("--include-loopback", help="Also track 127.0.0.1/::1.")]
NoDns = Annotated[bool, typer.Option("--no-dns", help="Disable reverse DNS lookups.")]
IncludeSystem = Annotated[
    bool,
    typer.Option(
        "--include-system",
        help="Also show events and correlate sockets of SIP-protected Apple binaries.",
    ),
]
IncludeDns = Annotated[
    bool, typer.Option("--include-dns", help="Also alert on DNS lookups (ports 53/853/5353).")
]
UdpFlows = Annotated[
    bool,
    typer.Option(
        "--udp-flows",
        help="Also capture outbound UDP with pktap (tcpdump, needs root): finds where sockets "
        "the socket table shows without a peer send, e.g. a WebRTC call.",
    ),
]
TcpFlows = Annotated[
    bool,
    typer.Option(
        "--tcp-flows",
        help="Also capture outbound TCP SYNs with pktap (needs root): catches a socket that "
        "opens and closes between two polls.",
    ),
]
ThroughputOpt = Annotated[
    bool,
    typer.Option(
        "--throughput",
        help="Flag a pre-established connection when its outbound byte rate spikes (pktap, "
        "needs root). Covers TCP only with --tcp-flows, else UDP flows.",
    ),
]
AutoBlock = Annotated[
    bool, typer.Option("--auto-block", help="Block the destination IP of qualifying alerts.")
]
AutoSuspend = Annotated[
    bool, typer.Option("--auto-suspend", help="SIGSTOP the process of qualifying alerts.")
]
MinSeverity = Annotated[
    str,
    typer.Option(
        "--min-severity", help="Threshold for --auto-* actions: low, medium, high, critical."
    ),
]
Ignore = Annotated[
    list[str] | None,
    typer.Option("--ignore", help="Bundle id or process name to ignore (repeatable)."),
]
Ip = Annotated[str, typer.Argument(help="IPv4 or IPv6 address.")]
Pid = Annotated[int, typer.Argument(help="Process id.")]


def _supervisor(
    window_ms: int,
    poll_ms: int,
    include_loopback: bool,
    no_dns: bool,
    ignore: list[str] | None,
    include_system: bool,
    include_dns: bool,
    udp_flows: bool,
    tcp_flows: bool = False,
    throughput: bool = False,
    decay_window_ms: int = 0,
    on_indicator: Callable[[IndicatorState], None] | None = None,
) -> Supervisor:
    if (udp_flows or tcp_flows or throughput) and (problem := pktap_unavailable()):
        flag = "--udp-flows" if udp_flows else "--tcp-flows" if tcp_flows else "--throughput"
        console.print(f"[bold red]{flag}:[/] {escape(problem)}")
        raise typer.Exit(1)
    config = CorrelationConfig(
        window_s=window_ms / 1000,
        decay_window_s=decay_window_ms / 1000,
        ignore=frozenset(ignore or ()),
        include_system=include_system,
        include_dns=include_dns,
    )
    return Supervisor.default(
        config=config,
        poll_interval_s=poll_ms / 1000,
        include_loopback=include_loopback,
        resolve_hostnames=not no_dns,
        udp_flows=udp_flows,
        tcp_flows=tcp_flows,
        throughput=throughput,
        on_indicator=on_indicator,
    )


def _warn_if_not_root() -> None:
    if not is_root():
        console.print(
            "[yellow]Not running as root: other users' sockets, pfctl and signalling "
            "foreign processes will be unavailable. Use sudo for full coverage.[/]"
        )


def _firewall() -> PfFirewall:
    """A firewall that also saves each change to BLOCKLIST for the boot job."""
    return PfFirewall(store=BlockList())


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
    decay_window_ms: DecayWindowMs = 0,
    poll_ms: PollMs = 200,
    include_loopback: Loopback = False,
    no_dns: NoDns = False,
    ignore: Ignore = None,
    include_system: IncludeSystem = False,
    include_dns: IncludeDns = False,
    udp_flows: UdpFlows = False,
    tcp_flows: TcpFlows = False,
    throughput: ThroughputOpt = False,
) -> None:
    """Interactive dashboard: alert feed, pf/pktap status, inspector and sensor events.

    Keys: b/u block/unblock the destination IP, s/r SIGSTOP/SIGCONT, k SIGKILL (asks first),
    Enter/space timeline, / filter (Esc clears), c clear the feed, q quit. Run as root for
    full visibility.
    """
    from safemaxxing.tui.app import SafemaxxingApp

    _warn_if_not_root()
    # Paranoia Mode (P) needs root; without it the button only says so.
    lockdown = (
        LockdownController(blocklist=load_blocklist(), hellos=client_hellos) if is_root() else None
    )
    supervisor = _supervisor(
        window_ms,
        poll_ms,
        include_loopback,
        no_dns,
        ignore,
        include_system,
        include_dns,
        udp_flows,
        tcp_flows,
        throughput,
        decay_window_ms,
        on_indicator=lockdown.observe_indicator if lockdown is not None else None,
    )
    SafemaxxingApp(supervisor, lockdown=lockdown).run()


@app.command()
def menubar(
    window_ms: WindowMs = 2000,
    poll_ms: PollMs = 200,
    include_loopback: Loopback = False,
    no_dns: NoDns = False,
    ignore: Ignore = None,
    include_system: IncludeSystem = False,
    include_dns: IncludeDns = False,
    udp_flows: UdpFlows = False,
) -> None:
    """macOS menu-bar companion: a live status icon, the last alerts with quick actions, the
    Auto-Block/Auto-Suspend toggles and the blocked-IP list. Needs the `menubar` extra (rumps)
    and root for full visibility.
    """
    from safemaxxing.menubar import MENUBAR_HINT, MenuBarConfig, menubar_available, run_menubar

    if not menubar_available():
        console.print(f"[bold red]menubar:[/] {escape(MENUBAR_HINT)}")
        raise typer.Exit(1)
    _warn_if_not_root()
    supervisor = _supervisor(
        window_ms,
        poll_ms,
        include_loopback,
        no_dns,
        ignore,
        include_system,
        include_dns,
        udp_flows,
    )
    config = MenuBarConfig(include_system=include_system)
    console.print("menubar running: look for the safemaxxing icon in the menu bar; Ctrl-C quits")

    def warn(message: str) -> None:
        console.print(f"[yellow]![/] {escape(message)}")

    run_menubar(supervisor, _firewall(), ProcessController(), config, warn=warn)


def _severity(name: str) -> Severity:
    try:
        return Severity[name.upper()]
    except KeyError:
        raise typer.BadParameter(f"unknown severity {name!r}") from None


def _alert_json(alert: Alert) -> str:
    payload = dataclasses.asdict(alert)
    payload["severity"] = alert.severity.label
    payload["sensors"] = sorted(s.value for s in alert.sensors)
    payload["summary"] = alert.summary
    return json.dumps(payload, default=str)


@app.command()
def watch(
    window_ms: WindowMs = 2000,
    decay_window_ms: DecayWindowMs = 0,
    poll_ms: PollMs = 200,
    include_loopback: Loopback = False,
    no_dns: NoDns = False,
    ignore: Ignore = None,
    include_system: IncludeSystem = False,
    include_dns: IncludeDns = False,
    udp_flows: UdpFlows = False,
    tcp_flows: TcpFlows = False,
    throughput: ThroughputOpt = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit alerts as JSON lines.")] = False,
    show_events: Annotated[
        bool, typer.Option("--events", help="Also print sensor events (not with --json).")
    ] = False,
    auto_block: AutoBlock = False,
    auto_suspend: AutoSuspend = False,
    min_severity: MinSeverity = "high",
) -> None:
    """Headless mode: stream alerts to stdout, optionally enforcing automatically."""
    threshold = _severity(min_severity)
    if not as_json:
        _warn_if_not_root()
    supervisor = _supervisor(
        window_ms,
        poll_ms,
        include_loopback,
        no_dns,
        ignore,
        include_system,
        include_dns,
        udp_flows,
        tcp_flows,
        throughput,
        decay_window_ms,
    )
    firewall, processes = _firewall(), ProcessController()

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
def block(ip: Ip) -> None:
    """Add an IP to the safemaxxing_block pf table and save it for `boot install`."""
    _print_result(asyncio.run(_firewall().block(ip)))


@app.command()
def unblock(ip: Ip) -> None:
    """Remove an IP from the safemaxxing_block pf table and from the saved list."""
    _print_result(asyncio.run(_firewall().unblock(ip)))


@app.command()
def blocked() -> None:
    """List blocked IPs."""
    for ip in asyncio.run(PfFirewall().blocked()):
        console.print(ip)


@app.command()
def flush() -> None:
    """Remove every IP from the block table and the saved list (rule stays loaded, pf on)."""
    _print_result(asyncio.run(_firewall().flush()))


def _require_root() -> None:
    if not is_root():
        console.print("[bold red]needs root:[/] re-run with sudo")
        raise typer.Exit(1)


@boot_app.command("install")
def boot_install() -> None:
    """Save the current blocks and load a launchd job that reapplies them at every boot."""
    _require_root()

    async def run() -> str:
        store = BlockList()
        for ip in await PfFirewall().blocked():
            store.add(ip)
        return await BootJob().install()

    problem = asyncio.run(run())
    if problem:
        console.print(f"[bold red]launchctl bootstrap failed:[/] {escape(problem)}")
        raise typer.Exit(1)
    count = len(BlockList().load())
    console.print(f"[green]installed {PLIST}[/] ({count} saved address(es) in {BLOCKLIST})")


@boot_app.command("uninstall")
def boot_uninstall() -> None:
    """Unload and delete the launchd job; current blocks and the saved list stay."""
    _require_root()
    asyncio.run(BootJob().uninstall())
    console.print(f"[green]removed {PLIST}[/]")


@boot_app.command("status")
def boot_status() -> None:
    """Show whether the job is installed and loaded, and the saved and live block counts."""
    status = asyncio.run(BootJob().status())
    saved = BlockList().load()
    console.print(f"job {PLIST}: installed={status.installed} loaded={status.loaded}")
    if not is_root():
        console.print(f"saved {BLOCKLIST}: {len(saved)}  live table: needs root  log: {LOG}")
        return
    live = asyncio.run(PfFirewall().blocked())
    console.print(f"saved {BLOCKLIST}: {len(saved)}  live table: {len(live)}  log: {LOG}")
    for ip in sorted(set(saved) - set(live)):
        console.print(f"[yellow]saved, not live:[/] {ip}")
    for ip in sorted(set(live) - set(saved)):
        console.print(f"[yellow]live, not saved:[/] {ip}")


@daemon_app.command("install")
def daemon_install(
    window_ms: WindowMs = 2000,
    decay_window_ms: DecayWindowMs = 0,
    poll_ms: PollMs = 200,
    include_loopback: Loopback = False,
    no_dns: NoDns = False,
    ignore: Ignore = None,
    include_system: IncludeSystem = False,
    include_dns: IncludeDns = False,
    udp_flows: UdpFlows = False,
    tcp_flows: TcpFlows = False,
    throughput: ThroughputOpt = False,
    auto_block: AutoBlock = False,
    auto_suspend: AutoSuspend = False,
    min_severity: MinSeverity = "high",
) -> None:
    """Load a launchd daemon running `watch --json` with these options, restarted if it exits.

    Alerts go to the daemon's log as JSON lines. Running it again replaces the options.
    """
    _require_root()
    _severity(min_severity)
    # The resolved bundle path, so the plist does not go through a symlink someone else may own.
    executable = Path(sys.executable).resolve()
    if problem := unsafe_reason(executable, frozen=bool(getattr(sys, "frozen", False))):
        console.print(f"[bold red]refusing to install the daemon:[/] {escape(problem)}")
        raise typer.Exit(1)
    if (udp_flows or tcp_flows or throughput) and (pktap_problem := pktap_unavailable()):
        console.print(f"[bold red]pktap:[/] {escape(pktap_problem)}")
        raise typer.Exit(1)
    options = WatchOptions(
        window_ms=window_ms,
        decay_window_ms=decay_window_ms,
        poll_ms=poll_ms,
        include_loopback=include_loopback,
        no_dns=no_dns,
        ignore=tuple(ignore or ()),
        include_system=include_system,
        include_dns=include_dns,
        udp_flows=udp_flows,
        tcp_flows=tcp_flows,
        throughput=throughput,
        auto_block=auto_block,
        auto_suspend=auto_suspend,
        min_severity=min_severity.lower(),
    )
    problem = asyncio.run(WatchDaemon().install(str(executable), options))
    if problem:
        console.print(f"[bold red]launchctl bootstrap failed:[/] {escape(problem)}")
        raise typer.Exit(1)
    console.print(f"[green]installed {DAEMON_PLIST}[/]: alerts go to {DAEMON_LOG}")


@daemon_app.command("uninstall")
def daemon_uninstall() -> None:
    """Stop the daemon and delete its plist; its logs and any blocks it made stay."""
    _require_root()
    asyncio.run(WatchDaemon().uninstall())
    console.print(f"[green]removed {DAEMON_PLIST}[/]")


@daemon_app.command("status")
def daemon_status() -> None:
    """Show whether the daemon is installed and running, its command line and last alerts."""
    status = asyncio.run(WatchDaemon().daemon_status())
    console.print(f"job {DAEMON_PLIST}: installed={status.installed} loaded={status.loaded}")
    if status.loaded:
        pid = f" pid={status.pid}" if status.pid else ""
        last = f" last exit: {status.last_exit}" if status.last_exit else ""
        console.print(f"state: {escape(status.state or 'unknown')}{pid}{escape(last)}")
    if status.arguments:
        console.print(f"runs: {escape(' '.join(status.arguments))}")
    console.print(f"log: {DAEMON_LOG}  errors: {DAEMON_ERR_LOG}")
    for line in recent_alerts():
        console.print(f"  {escape(line)}")


@app.command()
def freeze(pid: Pid) -> None:
    """Suspend a process (SIGSTOP)."""
    _print_result(ProcessController().suspend(pid))


@app.command()
def thaw(pid: Pid) -> None:
    """Resume a suspended process (SIGCONT)."""
    _print_result(ProcessController().resume(pid))


@app.command()
def kill(pid: Pid) -> None:
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
def permissions(
    check_signatures: Annotated[
        bool,
        typer.Option(
            "--check-signatures/--no-check-signatures",
            help="Also run codesign on each path client (slower).",
        ),
    ] = True,
) -> None:
    """List apps holding sensitive TCC permissions (camera, microphone, screen, input
    monitoring, accessibility, full disk access) and flag high-risk holders.

    Reads the system and per-user TCC databases read-only; needs Full Disk Access on this
    terminal (see `doctor`). Run as root to read the system database.
    """
    from safemaxxing import tcc_inspector

    entries, unavailable = tcc_inspector.inspect()
    for reason in unavailable:
        console.print(f"[yellow]![/] {escape(reason)}")
    if not entries:
        if unavailable:
            console.print("[bold red]no TCC database readable[/] — grant Full Disk Access")
            raise typer.Exit(1)
        console.print("no sensitive TCC grants found")
        return

    table = Table(title="TCC permissions")
    table.add_column("Service")
    table.add_column("Client", overflow="fold")
    table.add_column("Scope")
    table.add_column("Risk", style="red")
    risky = 0
    for entry in sorted(entries, key=lambda e: (bool(e.path), e.service_label, e.client)):
        exists = entry.path is None or Path(entry.path).exists()
        signing = (
            tcc_inspector.codesign_identity(entry.path)
            if check_signatures and entry.path and exists
            else None
        )
        reasons = tcc_inspector.risk_reasons(entry, exists=exists, signing=signing)
        if reasons:
            risky += 1
        scope = "system" if entry.source == tcc_inspector.SYSTEM_TCC_DB else "user"
        table.add_row(
            entry.service_label,
            escape(entry.client),
            scope,
            escape(", ".join(reasons)) if reasons else "[dim]-[/]",
        )
    console.print(table)
    summary = f"{len(entries)} sensitive grant(s)"
    tail = f"[red]{risky} high-risk[/]" if risky else "none high-risk"
    console.print(f"{summary}, {tail}")


@app.command()
def sample(
    seconds: Annotated[
        float, typer.Option("--seconds", min=0.5, help="How long to sample `log stream`.")
    ] = 5.0,
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
        for update in s.indicator_updates:
            console.print(f"[cyan]indicator {name}:[/] {escape(update)}")
        for example in s.unparsed_examples:
            console.print(f"[dim]unparsed {name}:[/] {escape(example)}")
        if s.parsed:
            sensors = ", ".join(f"{k}×{v}" for k, v in s.sensors.most_common())
            levels = ", ".join(f"{k}×{v}" for k, v in s.levels.most_common())
            console.print(f"[bold]{name}[/]: {escape(sensors)}  levels: {escape(levels)}")
        for example in s.parsed_examples:
            console.print(f"[green]parsed {name}:[/] {escape(example)}")


@paranoia_app.command("install")
def paranoia_install() -> None:
    """Load the watchdog that restores pf if safemaxxing stops while Paranoia Mode is on.

    Idle until Paranoia Mode arms it; Paranoia Mode refuses to start without it.
    """
    _require_root()
    problem = asyncio.run(WatchdogJob().install())
    if problem:
        console.print(f"[bold red]launchctl bootstrap failed:[/] {escape(problem)}")
        raise typer.Exit(1)
    console.print(f"[green]installed {WATCHDOG_PLIST}[/]")


@paranoia_app.command("uninstall")
def paranoia_uninstall() -> None:
    """Unload and delete the watchdog job (Paranoia Mode will refuse to start)."""
    _require_root()
    asyncio.run(WatchdogJob().uninstall())
    console.print(f"[green]removed {WATCHDOG_PLIST}[/]")


@paranoia_app.command("blocklist")
def paranoia_blocklist(
    url: Annotated[str, typer.Option(help="HTTPS URL of a hosts or Adblock Plus list.")] = (
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    ),
) -> None:
    """Download the DNS blocklist the sinkhole uses (run it outside Paranoia Mode)."""
    _require_root()
    blocklist = asyncio.run(fetch_blocklist(url))
    console.print(f"[green]{len(blocklist)} domains saved to {BLOCKLIST_CACHE}[/]")


if __name__ == "__main__":
    app()
