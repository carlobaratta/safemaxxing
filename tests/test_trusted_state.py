"""State files root's processes read back: a copy another user could write is ignored, and an
automatic response never stops a macOS system binary."""

from __future__ import annotations

import os
import signal
from pathlib import Path

from safemaxxing.firewall import ProcessController
from safemaxxing.lockdown.controller import PinStore
from safemaxxing.lockdown.dns import load_blocklist

LOGINWINDOW = "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"


def test_pins_round_trip_and_a_shared_file_is_ignored(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    store = PinStore(path)
    store.pin("com.example.app", "TEAM123456")
    assert PinStore(path).get("com.example.app") == "TEAM123456"
    os.chmod(path, 0o666)  # anyone could have swapped in their own Team ID
    assert PinStore(path).get("com.example.app") is None
    path.write_text("[not, a, mapping]")
    os.chmod(path, 0o644)
    assert PinStore(path).get("com.example.app") is None


def test_dns_blocklist_cache_must_be_trusted(tmp_path: Path) -> None:
    cache = tmp_path / "blocklist.hosts"
    cache.write_text("0.0.0.0 tracker.example\n")
    os.chmod(cache, 0o644)
    assert len(load_blocklist(cache)) == 1
    os.chmod(cache, 0o666)
    assert len(load_blocklist(cache)) == 0
    assert len(load_blocklist(tmp_path / "missing")) == 0


def test_auto_suspend_never_stops_a_system_binary() -> None:
    sent: list[tuple[int, int]] = []
    processes = ProcessController(kill=lambda pid, sig: sent.append((pid, sig)))
    skipped = processes.auto_suspend(4242, LOGINWINDOW)
    assert not skipped.ok and "macOS system binary" in skipped.detail and sent == []
    assert processes.auto_suspend(4242, "/Applications/Spy.app/Contents/MacOS/spy").ok
    assert sent == [(4242, signal.SIGSTOP)]
    assert processes.system_binary(1, LOGINWINDOW) == LOGINWINDOW
    assert processes.system_binary(1, "/usr/local/bin/tool") is None
