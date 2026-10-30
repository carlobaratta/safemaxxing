"""Loads the Paranoia Mode rulesets and tables through `pfctl` (needs root)."""

from __future__ import annotations

from collections.abc import Iterable

from safemaxxing.firewall import (
    ANCHOR,
    PFCTL,
    FirewallError,
    Runner,
    anchor_rules,
    meaningful_stderr,
    run_command,
)
from safemaxxing.lockdown.rules import GRANTS_ANCHOR, Grant, grant_rules


class LockdownFirewall:
    """Swaps our anchor between the v0.2 ruleset and the default-deny one, and owns the grants
    sub-anchor. Every ruleset is parsed with `pfctl -n` before it is loaded, and a load
    replaces the anchor atomically (all rule types in one pf transaction)."""

    def __init__(self, runner: Runner = run_command, anchor: str = ANCHOR) -> None:
        self._run = runner
        self.anchor = anchor
        self.grants_anchor = GRANTS_ANCHOR if anchor == ANCHOR else f"{anchor}/grants"

    async def _pfctl(self, argv: list[str], stdin: str | None = None) -> None:
        res = await self._run(argv, stdin=stdin)
        problems = meaningful_stderr(res.stderr)
        if res.returncode != 0 or problems:
            detail = "; ".join(problems) or f"exit {res.returncode}"
            raise FirewallError(f"{' '.join(argv[1:])}: {detail}")

    async def check(self, rules: str, anchor: str | None = None) -> None:
        """Parse `rules` without loading them; raises FirewallError if pf rejects them."""
        await self._pfctl([PFCTL, "-a", anchor or self.anchor, "-n", "-f", "-"], rules)

    async def load(self, rules: str, anchor: str | None = None) -> None:
        """Check, then load `rules` into `anchor` (ours by default), replacing what it held."""
        await self.check(rules, anchor)
        await self._pfctl([PFCTL, "-a", anchor or self.anchor, "-f", "-"], rules)

    async def set_grants(self, grants: Iterable[Grant]) -> None:
        """Replace the grants sub-anchor with one rule per grant."""
        await self.load(grant_rules(grants), self.grants_anchor)

    async def replace_table(self, table: str, addresses: Iterable[str]) -> None:
        """Make `table` hold exactly `addresses` (emptied when there are none)."""
        addrs = sorted(set(addresses))
        verb = ["replace", *addrs] if addrs else ["flush"]
        await self._pfctl([PFCTL, "-a", self.anchor, "-t", table, "-T", *verb])

    async def restore_normal(self) -> None:
        """Back to v0.2: block table only, no grants. The same two steps the watchdog runs."""
        await self.load(anchor_rules())
        await self._pfctl([PFCTL, "-a", self.grants_anchor, "-F", "rules"])
