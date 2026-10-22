# TESTLOG

Newest session first. Each session: environment, goal, code changes, exact commands, raw results,
problems/regressions, next steps. Raw logs from `scripts/macos_validate.sh` go in `testlogs/`.

<!-- Template:
## [YYYY-MM-DD HH:MM] - Session name / Target
- **Environment:** macOS Darwin, arch (Apple Silicon/Intel), OS version, UID/privileges
- **Goal:**
- **Code changes:**
- **Commands run:**
- **Result and raw data:**
- **Problems / regressions:**
- **Next steps:**
-->

## [2026-10-22 11:43] - Baseline + Task 1-4 preparation (Linux container, NOT the Mac)

- **Environment:** Linux 6.18.44 x86_64 (Claude Code cloud container), CPython 3.13.16,
  uv 0.11.32, uid=0 (root). **Not Darwin:** no `pfctl`, `log`, real `lsof` or TCC, so nothing
  here validates native macOS calls. The live suite is skipped automatically.
- **Goal:** record the static baseline on branch `claude/gifted-pascal-tp5iot` @66596f3, close
  the gaps found in Tasks 1-4, and prepare a one-shot script for the real Mac.
  (The branch `claude/amazing-pasteur-hj7ek5` named in the brief does not exist on the remote;
  its history is in this branch.)
- **Code changes:**
  - `src/safemaxxing/diagnostics.py`: `check_socket_visibility` FAILs if lsof is missing or
    prints nothing, accepts lsof exit 1 with output (unreadable fds), and is OK only when
    `root`/`_daemon` sockets are visible. Visibility depends on root, not Full Disk Access;
    FDA keeps its own probe (reading the system `TCC.db`).
  - `tests/test_diagnostics.py`: new test for daemons, users-only and lsof-missing cases.
  - `tests/live/test_live_macos.py`: `test_reverse_dns_never_exceeds_timeout_on_real_resolver`
    (each `resolve()` < 150 ms with a 100 ms timeout).
  - `scripts/macos_validate.sh`: collects all evidence for Tasks 1-4 into `testlogs/`.
- **Audit of existing code against the brief (no change needed):**
  - Task 1: `doctor` already checks euid 0, `pfctl -s info` Enabled/Disabled, parent anchor,
    our anchor, FDA, snapshot latency and the `log` predicate.
  - Task 2: `PfFirewall._enable` already runs `pfctl -E`, then `-e`; a missing anchor/table
    is treated as empty; the anchor has no `table` definition, so reloads don't reset it.
  - Task 4: `HostnameResolver` uses a dedicated 4-thread pool with a 100 ms timeout, and the
    poll loop only calls `prefetch`. Covered by `test_poller_not_blocked_by_hung_dns`.
- **Commands run:**
  ```sh
  uv run ruff check
  uv run mypy --strict
  uv run pytest -q
  ```
- **Result and raw data:**
  ```text
  # baseline @66596f3
  All checks passed!
  Success: no issues found in 20 source files
  102 passed, 6 skipped in 2.81s

  # after changes @ab5aaaa
  All checks passed!
  Success: no issues found in 20 source files
  103 passed, 7 skipped in 2.09s
  ```
  The 7 skipped tests are the `live` suite (`needs macOS, root and SAFEMAXXING_LIVE=1`).
- **Problems / regressions:** none on Linux. The brief expects 41 tests; the suite has 103.
  Tasks 2 (kernel block), 3 (`<private>` on the current macOS) and 4 (real resolver) are
  **not yet validated**: they need the Mac.
- **Next steps:** on the Mac, from the repo root:
  ```sh
  git pull origin claude/gifted-pascal-tp5iot
  scripts/macos_validate.sh          # optional: SAFEMAXXING_LIVE_IP=9.9.9.9 SAMPLE_S=10
  ```
  Paste the key parts of `testlogs/<stamp>-macos.log` into a new section above. Add any
  unparsed log lines to `tests/test_sensors.py` as verbatim fixtures before changing parsers.
