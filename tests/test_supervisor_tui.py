from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from conftest import T0, make_conn, make_event
from test_firewall import FakePf
from textual.widgets import DataTable

from safemaxxing.correlation import CorrelationConfig, CorrelationEngine
from safemaxxing.firewall import PfFirewall, ProcessController
from safemaxxing.models import Alert, Event, NetworkConnection
from safemaxxing.supervisor import Supervisor
from safemaxxing.tui.app import SafemaxxingApp


async def events_source(hold: bool = False) -> AsyncIterator[Event]:
    yield make_event()
    if hold:
        await asyncio.Event().wait()


async def conns_source(hold: bool = False) -> AsyncIterator[NetworkConnection]:
    await asyncio.sleep(0.01)
    yield make_conn()
    if hold:
        await asyncio.Event().wait()


def supervisor(hold: bool = False) -> Supervisor:
    engine = CorrelationEngine(CorrelationConfig(), clock=lambda: T0)
    return Supervisor(events_source(hold), conns_source(hold), engine)


async def test_supervisor_stream_yields_alert() -> None:
    updates = [u async for u in supervisor().stream()]
    alerts = [u for u in updates if isinstance(u, Alert)]
    assert len(alerts) == 1
    assert any(isinstance(u, Event) for u in updates)
    assert any(isinstance(u, NetworkConnection) for u in updates)


async def test_supervisor_propagates_source_errors() -> None:
    async def broken() -> AsyncIterator[Event]:
        raise FileNotFoundError("/usr/bin/log")
        yield make_event()

    sup = Supervisor(broken(), conns_source())
    try:
        async for _ in sup.stream():
            pass
    except FileNotFoundError:
        return
    raise AssertionError("expected FileNotFoundError")


async def test_tui_shows_alert_and_enforces() -> None:
    pf = FakePf(enabled=True)
    signals: list[tuple[int, int]] = []
    app = SafemaxxingApp(
        supervisor(hold=True),
        firewall=PfFirewall(runner=pf),
        processes=ProcessController(kill=lambda pid, sig: signals.append((pid, sig))),
    )
    async with app.run_test() as pilot:
        for _ in range(50):
            await pilot.pause(0.02)
            if app.alerts:
                break
        table = app.query_one("#alerts", DataTable)
        assert table.row_count == 1
        table.focus()
        await pilot.press("b")
        await pilot.pause()
        assert pf.table == {"203.0.113.9"}
        await pilot.press("s")
        await pilot.press("k")
        await pilot.click("#yes")
        await pilot.pause()
        assert [pid for pid, _ in signals] == [4242, 4242]
        await pilot.press("c")
        assert table.row_count == 0
