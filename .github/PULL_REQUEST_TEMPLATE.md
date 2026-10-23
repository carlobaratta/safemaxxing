## What and why

<!-- One or two sentences. Link the TODO.md item or issue. -->

## Checks

- [ ] `uv run ruff format --check . && uv run ruff check .`
- [ ] `uv run mypy`
- [ ] `uv run pytest -q`
- [ ] Live suite on a Mac (`sudo SAFEMAXXING_LIVE=1 "$(which uv)" run pytest -m live`), or: not run, because …
- [ ] New log formats added verbatim as fixtures in `tests/test_sensors.py`
- [ ] TODO.md / TESTLOG.md / CHANGELOG.md updated
