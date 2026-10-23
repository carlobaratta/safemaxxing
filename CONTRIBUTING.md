# Contributing

## Development loop

Requirements: Python 3.12+ and [`uv`](https://docs.astral.sh/uv/). The unit tests mock every
native call (`log`, `pfctl`, `lsof`, `kill`), so they also run on Linux.

```bash
uv sync
uv run ruff format . && uv run ruff check .
uv run mypy            # strict, covers src/ and tests/
uv run pytest -q
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs the same four checks on
macOS arm64 and Intel with Python 3.12 and 3.13. A pull request must keep all of them green.

## Live tests on a Mac

`tests/live/` talks to the real Darwin kernel and unified log. It is skipped unless it runs
on macOS, as root, with `SAFEMAXXING_LIVE=1`:

```bash
sudo SAFEMAXXING_LIVE=1 "$(which uv)" run pytest -m live -v -s
```

| Variable | Default | Meaning |
|----------|---------|---------|
| `SAFEMAXXING_LIVE_IP` | `1.1.1.1` | IP added to and always removed from `safemaxxing_block` |
| `SAFEMAXXING_LIVE_PORT` | `443` | HTTPS port probed on that IP |
| `SAFEMAXXING_LIVE_HTTP_PORT` | `80` | HTTP port probed on that IP |
| `SAFEMAXXING_LIVE_SAMPLE_S` | `5` | Seconds of `log stream` sampled |

For a full validation run, use `scripts/macos_validate.sh`. It asks for sudo once,
pauses so you can open Photo Booth and Voice Memos during the log sample, and writes:

- `testlogs/<stamp>-macos.log`: commands and output. Commit it.
- `testlogs/<stamp>-sample.jsonl`: the raw `log stream` entries. It is git-ignored: it holds the
  Mac's full unified log for the sample window.

The script reads only three variables: `SAFEMAXXING_LIVE_IP`, `SAMPLE_S` (default 15) and
`PF_DISABLED_TEST=1`. The other live variables do not reach it through sudo. `PF_DISABLED_TEST=1` runs
`pfctl -d` first and checks that `block` re-enables pf, which leaves pf enabled afterwards.

## Branches

All work lands on `main`, the default branch and the target of pull requests. The
`claude/amazing-pasteur-hj7ek5` and `claude/gifted-pascal-tp5iot` branches are kept for
history only; do not push to them.

## Tracking work

- [TODO.md](TODO.md) holds the task list. Use the format and section rules in its header.
  A finished task moves to **Completed** with its date and commit.
- [TESTLOG.md](TESTLOG.md) records each test session, newest first: environment, goal,
  code changes, exact commands, raw results, problems and next steps.
- [CHANGELOG.md](CHANGELOG.md) records user-visible changes under **Unreleased** until a
  release is tagged.
- `testlogs/*.log` files are committed only from the Mac that produced them. A copy committed
  from elsewhere makes the next `git pull` on the Mac fail.

## Parser changes

macOS changes its log formats between releases. Before you change a parser in `sensors.py`,
add the real log line verbatim as a fixture in `tests/test_sensors.py`. Take it from a `sample
--out` capture, and remove anything personal first.

## Commits

Each commit is one logical change, with a message in the imperative that says what changed
and why, for example `Ignore coreaudiod's ScreenCapture checks for audio clients`. Put
tracking-file updates in their own commit (`Log the … in TESTLOG.md and TODO.md`).

## Security issues

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
