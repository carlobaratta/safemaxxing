## What and why

<!-- One or two sentences. Link the TODO.md item or issue. -->

## Checks

- [ ] `uv run ruff format --check . && uv run ruff check .`
- [ ] `uv run mypy`
- [ ] `uv run pytest -q`
- [ ] Live suite on a Mac (`sudo SAFEMAXXING_LIVE=1 "$(which uv)" run pytest -m live`), or: not run, because …
- [ ] New log formats added verbatim as fixtures in `tests/test_sensors.py`
- [ ] TODO.md / TESTLOG.md / CHANGELOG.md updated
- [ ] README / ARCHITECTURE.md updated if a command, option or module changed

## Security-sensitive?

<!-- Tick if it applies, and say what you checked. -->

- [ ] Changes what runs as root, what pf loads, which processes get signalled, or the
      automatic responses: SECURITY.md ("Scope", "What safemaxxing changes") still holds
- [ ] Changes packaging, entitlements or the release workflow: signing / notarization
      dry-run, or not run, because …
