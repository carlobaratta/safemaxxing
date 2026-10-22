"""Live checks against the real Darwin kernel and unified log.

Run on a Mac with:  sudo SAFEMAXXING_LIVE=1 "$(which uv)" run pytest -m live -v -s
They add (and always remove) one IP in the safemaxxing_block table.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys

import pytest

from safemaxxing.diagnostics import Status, collect_log_sample, run_doctor, summarize_sample
from safemaxxing.firewall import (
    ANCHOR,
    PFCTL,
    TABLE,
    PfFirewall,
    meaningful_stderr,
    run_command,
    table_missing,
)
from safemaxxing.sensors import WIDE_DISCOVERY_PREDICATE, parse_entry

LIVE = sys.platform == "darwin" and os.geteuid() == 0 and os.environ.get("SAFEMAXXING_LIVE") == "1"
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not LIVE, reason="needs macOS, root and SAFEMAXXING_LIVE=1"),
]

TARGET_IP = os.environ.get("SAFEMAXXING_LIVE_IP", "1.1.1.1")
HTTPS_PORT = int(os.environ.get("SAFEMAXXING_LIVE_PORT", "443"))
HTTP_PORT = int(os.environ.get("SAFEMAXXING_LIVE_HTTP_PORT", "80"))
SAMPLE_SECONDS = float(os.environ.get("SAFEMAXXING_LIVE_SAMPLE_S", "5"))


def can_connect(ip: str, port: int, timeout_s: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True
    except OSError:
        return False


@pytest.fixture
async def firewall() -> PfFirewall:
    fw = PfFirewall()
    if TARGET_IP in await fw.blocked():
        pytest.skip(f"{TARGET_IP} is already blocked by the user; not touching it")
    if not can_connect(TARGET_IP, HTTPS_PORT):
        pytest.skip(f"no baseline connectivity to {TARGET_IP}:{HTTPS_PORT}")
    return fw


def test_doctor_has_no_failures() -> None:
    checks = run_doctor()
    for check in checks:
        print(f"[{check.status}] {check.name}: {check.detail}")
    assert [c for c in checks if c.status is Status.FAIL] == []


async def test_anchor_rules_and_table_parse_cleanly() -> None:
    fw = PfFirewall()
    await fw.setup()
    assert await fw.is_enabled() is True
    rules = await run_command([PFCTL, "-a", ANCHOR, "-s", "rules"])
    print(rules.stdout)
    assert rules.returncode == 0 and meaningful_stderr(rules.stderr) == []
    assert f"<{TABLE}>" in rules.stdout
    table = await run_command([PFCTL, "-a", ANCHOR, "-t", TABLE, "-T", "show"])
    if table_missing(table.stderr):
        return  # Normal until the first `-T add` creates it.
    assert table.returncode == 0 and meaningful_stderr(table.stderr) == []


async def test_block_drops_new_connections_and_unblock_restores(firewall: PfFirewall) -> None:
    try:
        assert (await firewall.block(TARGET_IP)).ok
        assert TARGET_IP in await firewall.blocked()
        assert not await asyncio.to_thread(can_connect, TARGET_IP, HTTPS_PORT, 2.0)
    finally:
        assert (await firewall.unblock(TARGET_IP)).ok
    assert await asyncio.to_thread(can_connect, TARGET_IP, HTTPS_PORT, 3.0)


async def test_block_kills_already_open_connection(firewall: PfFirewall) -> None:
    sock = socket.create_connection((TARGET_IP, HTTP_PORT), timeout=3.0)
    try:
        assert (await firewall.block(TARGET_IP)).ok
        sock.settimeout(2.0)
        with pytest.raises(OSError):  # TimeoutError or a reset: either way no reply arrives
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + TARGET_IP.encode() + b"\r\n\r\n")
            if not sock.recv(1):
                raise ConnectionResetError("closed")
    finally:
        sock.close()
        assert (await firewall.unblock(TARGET_IP)).ok


async def test_log_stream_predicate_and_parser_on_real_entries() -> None:
    entries = await collect_log_sample(SAMPLE_SECONDS)
    for entry in entries:
        parse_entry(entry)
    stats = summarize_sample(entries)
    print(f"\n{len(entries)} entries in {SAMPLE_SECONDS:g}s")
    for name, s in sorted(stats.items()):
        print(
            f"{name}: entries={s.entries} parsed={s.parsed} with_pid={s.with_pid} "
            f"with_bundle={s.with_bundle} private_msg={s.redacted_message} "
            f"no_image={s.redacted_image_path} top={s.processes.most_common(3)}"
        )
        for example in s.unparsed_examples:
            print(f"  unparsed: {example}")


async def test_wide_discovery_predicate_accepted_by_log() -> None:
    entries = await collect_log_sample(1.0, predicate=WIDE_DISCOVERY_PREDICATE)
    print(f"\nwide predicate: {len(entries)} entries in 1s")
