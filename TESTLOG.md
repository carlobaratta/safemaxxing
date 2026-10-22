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

## [2026-10-22 13:50 +0200] - Fixes from the first Mac run (Linux container)

- **Environment:** Linux 6.18.44 x86_64 cloud container, CPython 3.13.16, uid=0. Static
  checks only; nothing native was re-run.
- **Goal:** fix the anomalies seen in the 13:45 Mac run.
- **Code changes:**
  - `src/safemaxxing/diagnostics.py`: when `pfctl` returns `/dev/pf: Permission denied`,
    `pf status`, `pf parent anchor` and `anchor com.apple/safemaxxing` are now WARN
    "needs root". Before, the parent check wrongly said the anchor was missing and told the
    user to run `pfctl -f /etc/pf.conf`. The exit code stays 1 because root still FAILs.
  - `tests/test_diagnostics.py`: test with the real non-root output.
  - `tests/test_sensors.py`: the two new verbatim noise lines (cmio `setting <private> :
    <private>`, Geotagging `near-owner`) must not become events.
  - `scripts/macos_validate.sh`: `chown` an existing root-owned `.pytest_cache`;
    `-p no:cacheprovider` for `sudo pytest`; waits for Enter so camera/mic can be opened
    before the sample; opt-in `PF_DISABLED_TEST=1` for the Disabled → Enabled path.
  - `testlogs/20261022-1345-macos.log`: raw log of the Mac run, verbatim.
- **Commands run:**
  ```sh
  uv run ruff check && uv run mypy --strict && uv run pytest -q
  ```
- **Result and raw data:**
  ```text
  All checks passed!
  Success: no issues found in 20 source files
  104 passed, 7 skipped in 2.41s
  ```
- **Problems / regressions:** none.
- **Next steps:** on the Mac, `git pull`, then `PF_DISABLED_TEST=1 scripts/macos_validate.sh`.
  Open Photo Booth and Voice Memos at the prompt.

## [2026-10-22 13:45 +0200] - First real Mac run: Tasks 1-4 (macOS 27.0.1, Apple M4)

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4 (Apple Silicon), user `carlo`
  uid=501 (admin), root steps via sudo; Python 3.13.14, uv from Homebrew. Local branch
  `claude/amazing-pasteur-hj7ek5` at f58a357.
- **Goal:** validate native calls: doctor, pf block in the kernel, `log stream` redaction,
  real reverse DNS.
- **Code changes:** none (run of f58a357).
- **Commands run:** `scripts/macos_validate.sh` (full list and output in
  `testlogs/20261022-1345-macos.log`).
- **Result and raw data:**
  - Static: ruff 0, mypy 0 (20 files), pytest `103 passed, 7 skipped, 1 warning`.
  - **Task 1** `sudo safemaxxing doctor`: exit 0, every check OK except
    `Full Disk Access: not granted` (WARN). pf `Enabled`; anchor holds
    `block drop out quick from any to <safemaxxing_block>`; `foreign sockets: 32 pids visible
    incl. daemons _mdnsresponder, _netbios, _trustd`; `socket snapshot: 8 ms per poll`.
  - **Task 2** live block of 1.1.1.1:
    ```text
    before   curl https://1.1.1.1/  -> 301 in 0.057s
    block    block_ip 1.1.1.1: ok 1/1 addresses added.   (-T show: 1.1.1.1)
    blocked  curl -> curl: (28) Connection timed out after 3006 ms -> 000
    unblock  unblock_ip 1.1.1.1: ok 1/1 addresses deleted. (-T show: empty)
    after    curl -> 301 in 0.044s
    ```
    `pfctl -a com.apple/safemaxxing -s rules` and `-T show` print only the usual ALTQ notice.
    The live tests for new and already-open connections PASSED.
  - **Task 3** sample 8 s: 146 entries (cmio 2, locationd 144). `no image path` = 0 and
    `no pid` = 0, so **PID and processImagePath arrive in clear**. `<private>` affects only
    message fields (cmio 2/2, locationd 44/144: Geotagging `address`, `data`, `rssi`...).
    Parsed: 2 locationd events `markReceivingLocationInformation` for the client FindMyDevice
    (`root:com.apple.locationd.bundle-/System/Library/PrivateFrameworks/FindMyDevice.framework`).
    The unparsed lines are noise (cmio RegisterAssistantService, Geotagging BLE), so dropping
    them is correct. Wide predicate: 0 entries in 1 s (accepted by `log`).
  - **Task 4** reverse DNS with a 100 ms timeout:
    ```text
    1.1.1.1: 'one.one.one.one' in 74 ms    8.8.8.8: 'dns.google' in 10 ms
    9.9.9.9: None in 100 ms (cap hit)      17.253.144.10: 'icloud.com' in 83 ms
    192.0.2.1 / 203.0.113.7: None in 0 ms (non-global, never sent)
    ```
  - Live suite: **7 passed** in 12.80 s.
- **Problems / regressions vs Linux:**
  1. Non-root `doctor` printed `✘ pf parent anchor: ... missing ... sudo pfctl -f /etc/pf.conf`.
     That is false: the real cause is `/dev/pf: Permission denied`. Fixed in bc5a019.
  2. `PytestCacheWarning: Permission denied .pytest_cache`: an earlier `sudo pytest` left
     the cache owned by root. One-off fix: `sudo chown -R "$USER" .pytest_cache`; the script
     now avoids it.
  3. No camera or mic was in use during the sample, so the TCC, cmio and coreaudio parsers
     were **not** exercised with real accesses.
  4. pf was already Enabled (for 32 min), so the automatic `pfctl -E` path was not
     exercised.
- **Next steps:** re-run with the camera and mic active, and with `PF_DISABLED_TEST=1`.

## [2026-10-22 11:43 UTC] - Baseline + Task 1-4 preparation (Linux container, NOT the Mac)

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
