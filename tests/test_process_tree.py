from __future__ import annotations

from safemaxxing.process_tree import LAUNCHD_PID, ProcessChainResolver


def tree(parents: dict[int, int], responsible: dict[int, int] | None = None) -> ProcessChainResolver:
    """A resolver over an explicit pid graph: `parents[pid]` is the parent, `responsible[pid]`
    the responsible pid. Missing entries resolve to None, as the real lookups do for a pid
    that is gone or inaccessible."""
    resp = responsible or {}
    return ProcessChainResolver(
        parent=lambda pid: parents.get(pid), responsible=lambda pid: resp.get(pid)
    )


def test_chain_is_just_the_pid_without_lookups() -> None:
    # Off macOS, or without privilege, both lookups return None: behave like pid equality.
    resolver = tree({})
    assert resolver.chain(4242) == frozenset({4242})


def test_chain_follows_parents_up_to_launchd() -> None:
    # curl (501) spawned by a helper (412) spawned by the app (300), a child of launchd.
    resolver = tree({501: 412, 412: 300, 300: LAUNCHD_PID})
    assert resolver.chain(501) == frozenset({501, 412, 300})


def test_launchd_and_kernel_are_not_actors() -> None:
    assert tree({}).chain(LAUNCHD_PID) == frozenset()
    assert tree({}).chain(0) == frozenset()


def test_responsible_pid_links_a_non_descendant_daemon() -> None:
    # nsurlsessiond (200) is a child of launchd, not of the app; only its responsible pid
    # (the app, 300) ties the socket back to the process that used the sensor.
    resolver = tree({200: LAUNCHD_PID, 300: LAUNCHD_PID}, responsible={200: 300})
    assert resolver.chain(200) == frozenset({200, 300})


def test_cycle_from_reused_pid_is_bounded() -> None:
    # A corrupted ppid cycle (900 -> 901 -> 900) must terminate, not spin.
    resolver = tree({900: 901, 901: 900})
    assert resolver.chain(900) == frozenset({900, 901})


def test_depth_is_capped() -> None:
    parents = {pid: pid + 1 for pid in range(100, 130)}
    resolver = ProcessChainResolver(parent=lambda pid: parents.get(pid), max_chain=4)
    assert len(resolver.chain(100)) == 4
