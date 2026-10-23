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

## [2026-10-23 15:00 +0200] - Every ScreenCapture line in the 14:24 sample (Mac + Linux container)

- **Environment:** Mac (macOS 27.0.1, arm64, uid 501) for the dump; Linux container for the
  fix and the checks.
- **Goal:** check whether tccd's lines for the `msgID=525.x` requests still become
  `screen_capture`.
- **Commands run (Mac):** a Python script over `testlogs/20261023-1424-sample.jsonl` that
  prints `processID process | eventMessage[:220]` for every line containing `ScreenCapture`,
  then `sort | uniq -c`.
- **Result and raw data (counts, processes):**
  ```text
  5 407 tccd | <TCCDProcess: identifier=com.apple.WindowServer, pid=406> has the ...tcc.manager... kTCCServiceScreenCapture
  5 407 tccd | <TCCDProcess: identifier=com.apple.audio.coreaudiod, pid=525> has the ...tcc.manager... kTCCServiceScreenCapture
  2 407 tccd | system tccd handled entitlements check for: kTCCServiceScreenCapture
  2 407 tccd | Handling access request to kTCCServiceScreenCapture, from Sub:{com.apple.VoiceMemos}... pid=34399
  2 407 tccd | Handling access request to kTCCServiceScreenCapture, from Sub:{com.apple.PhotoBooth}... pid=34389
  2 407 tccd | Auth:Allowed (Entitled) to kTCCServiceScreenCapture because accessing process ...ringlighthelper, pid=34393
  2 407 tccd | <TCCDProcess: identifier=com.apple.controlcenter, pid=689> has the com.apple.private.tcc.allow entitlement ...
  3 525 coreaudiod   | SEND ... msgID=525.369/372/374 ... ScreenCapture, target_token={pid:34389|34393|34399}
  3 406 WindowServer | SEND ... msgID=406.215/216/218 ... ScreenCapture, target_token={pid:34389|34393|34399}
  6 407 tccd | REQUEST_MSG msgID=525.x / 406.x ... preflight=true target_token={pid:...}
  4 407 tccd | AUTHREQ_CTX msgID=525.x / 406.x ... preflight=yes
  ```
  Every request is a **preflight** made by WindowServer or coreaudiod for the apps that had
  just started. No line comes from an app capturing the screen. Before the fix, `REQUEST_MSG`,
  `Handling access request`, `Auth:Allowed` and the WindowServer `SEND` still produced
  `screen_capture`.
- **Code changes:** `src/safemaxxing/sensors.py`: a single rule replaces the coreaudiod
  special case. A `screen_capture` event requires the logging pid to equal the accessing
  pid. `tests/test_sensors.py`: one fixture per line kind (expected None); an app's own SEND
  (constructed) still counts; coreaudiod's mic request (constructed) is still attributed to
  the client. The old WindowServer attribution test moves to the Camera service so it keeps
  testing the generic rule.
- **Commands run (container):** `uv run ruff check && uv run ruff format --check src tests && uv run mypy --strict && uv run pytest -q`
  → `All checks passed!` · `20 files already formatted` · `Success: no issues found in 20 source files` · `124 passed, 7 skipped in 2.81s`
- **Problems / regressions:** known limit: a real capture is detected only from the app's
  own client-side line (Info level) or from an `scr:` indicator (never observed yet).
  Not validated live.
- **Next steps:** test a real screen capture during `sample`.

## [2026-10-23 14:50 +0200] - pid 525 identified: coreaudiod (Mac + Linux container)

- **Environment:** Mac (macOS 27.0.1, arm64, uid 501) for the lookup; Linux container for
  the fix and the static checks.
- **Goal:** explain the 20 `screen_capture` events for Photo Booth (pid 34389) in the 14:24 run.
- **Commands run (Mac):**
  ```sh
  python3 -I -c '
  import json, sys
  for line in open(sys.argv[1]):
      e = json.loads(line)
      if e.get("processID") == 525:
          print("pid 525 =", e.get("processImagePath")); break
  ' testlogs/20261023-1424-sample.jsonl
  ```
- **Result and raw data:** `pid 525 = /usr/sbin/coreaudiod`. coreaudiod is a broker: its
  `SEND ... service=kTCCServiceScreenCapture, target_token={pid:34389}` asks on behalf of
  Photo Booth, which only used camera and mic. These are not screen captures.
- **Code changes:** `src/safemaxxing/sensors.py`: TCC lines logged by `coreaudiod` with
  service ScreenCapture are dropped. `tests/test_sensors.py`: verbatim fixture (the
  ScreenCapture line) plus a constructed mic counter-example, which is still attributed to
  the client.
- **Commands run (container):** `uv run ruff check && uv run mypy --strict && uv run pytest -q`
  → `All checks passed!` · `Success: no issues found in 20 source files` ·
  `122 passed, 7 skipped in 3.06s`
- **Problems / regressions:** only the lines logged by coreaudiod are covered. If tccd logs
  its own lines for the same `msgID=525.x`, they can still become `screen_capture`
  (not verified).
- **Next steps:** dump every ScreenCapture line from the JSON sample.

## [2026-10-23 14:40 +0200] - Indicator test from the 14:24 run (Linux container)

- **Environment:** Linux x86_64 cloud container, CPython 3.13.16, uid=0. Static checks only.
- **Goal:** pin the real camera/location/mic indicator sequence.
- **Code changes:** `tests/test_sensors.py` gets
  `test_real_indicator_sequence_with_camera_location_and_microphone` (5 verbatim lines →
  cam, loc, loc, mic). `src/safemaxxing/sensors.py`: comment updated, since `mic` has now
  been observed.
- **Commands run:** `uv run ruff check && uv run ruff format --check src tests && uv run mypy --strict && uv run pytest -q`
- **Result and raw data:** `All checks passed!` · `Success: no issues found in 20 source
  files` · `121 passed, 7 skipped in 2.88s`
- **Problems / regressions:** none.
- **Next steps:** identify pid 525 (screen capture for Photo Booth); reboot persistence.

## [2026-10-23 14:24 +0200] - Fourth Mac run: camera + mic live, pf cold start after reboot

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, uid=501 + sudo. Local branch
  `claude/amazing-pasteur-hj7ek5` fast-forwarded to **97763f1** (merged code). Raw log and
  JSON on the Mac: `testlogs/20261023-1424-macos.log`, `testlogs/20261023-1424-sample.jsonl`.
- **Goal:** Task 3 with Photo Booth and Voice Memos opened *during* a 15 s sample; full run
  on the merged code.
- **Code changes:** none (run of 97763f1).
- **Commands run:** `git pull --ff-only origin claude/gifted-pascal-tp5iot`, then
  `scripts/macos_validate.sh`.
- **Result and raw data:**
  - Static: ruff 0, mypy 0, pytest `120 passed, 7 skipped` (cache warning gone).
  - **Task 1:** non-root shows the 3 pf checks as `needs root`. Root: exit 0; after the
    reboot `! pf status: Disabled (enabled automatically on first block)` and
    `anchor com.apple/safemaxxing: not created yet (loads on first block)`.
  - **Task 2c (cold start):**
    ```text
    pfctl -s info                     -> Status: Disabled
    pfctl -a com.apple/safemaxxing -s rules            -> pfctl: DIOCGETRULES: Invalid argument (exit 0)
    pfctl -a ... -t safemaxxing_block -T show          -> pfctl: Table does not exist. (exit 255)
    curl 1.1.1.1 -> 301 (0.109s)
    safemaxxing block 1.1.1.1         -> ok 1 table created.; 1/1 addresses added.
    pfctl -s info                     -> Status: Enabled for 0 days 00:00:00
    curl -> 000 (timeout 3.003s); unblock -> ok 1/1 addresses deleted.; curl -> 301 (0.084s)
    ```
  - **Task 3, sample 15 s, 3755 entries:**
    | subsystem | entries | `<private>` | parsed | w/ pid | sensors |
    |---|---|---|---|---|---|
    | com.apple.TCC | 210 | 21 | 121 | 121 | tcc 53, microphone 41, screen_capture 20, camera 7 |
    | com.apple.cmio | 2436 | 2303 | 32 | 32 | camera 32 (Photo Booth `CMIODeviceStartStream`) |
    | com.apple.controlcenter | 5 | 0 | 4 | 0 | location 2, camera 1, microphone 1 |
    | com.apple.coreaudio | 389 | 0 | 0 | 0 | — |
    | com.apple.locationd | 715 | 371 | 24 | 14 | location 24 |

    PID and processImagePath arrived in clear on every subsystem (`no image path` = `no pid` = 0).
    - TCC: `microphone Photo Booth pid=34389` and `camera Photo Booth pid=34389` from Photo
      Booth's own `SEND` lines. Also `screen_capture pid:34389` from
      `msgID=525.369 ... service=kTCCServiceScreenCapture, target_token={pid:34389}`: process
      525 asks on behalf of Photo Booth, **to be checked**. `photolibraryd`'s `tcc.manager`
      self check was dropped (generic rule ✓). `com.apple.campo` pid 729 `has the
      com.apple.private.tcc.allow entitlement for service kTCCServicePhotos` was parsed as
      tcc (a pre-granted access by a system agent).
    - cmio: `CMIOHardware.cpp:741:CMIODeviceStartStream (35 36)` with Photo Booth's pid ✓,
      plus the `... backtrace N` lines of the same call.
    - Indicator timeline: `[cam:PhotoBooth]` → `[cam, loc:VoiceMemos]` → `[cam]` →
      `[cam, loc:VoiceMemos]` → `[cam, loc:VoiceMemos, mic:VoiceMemos]`. **First real
      `mic:`**; Voice Memos uses location to tag recordings.
    - coreaudio: 389 lines (corespeech, VoiceMemos, coreaudiod), none matches the
      start-IO + input hints, e.g. `[AMCP] ... Voice isolation DSP is available for client
      with bundle id com.apple.PhotoBooth`.
    - locationd: new stop line `{"msg":"stopped receiving location information",
      "client":"root:p\/System\/...CoreParsec.framework:"}`, correctly not an access.
  - **Live suite 7/7 PASSED** (12.97 s). Live sample: indicator
    `[cam:com.apple.PhotoBooth, mic:com.apple.VoiceMemos]` → camera + microphone events.
    Wide predicate 522 entries/s with audio active.
  - **Task 4:** 21 / 35 / 42 ms (cold cache after the reboot); `17.253.144.10: None in 101 ms`
    (cap; < 150 ms).
- **Problems / regressions:** (1) after a reboot pf is disabled and the anchor/table are
  gone, so **blocks don't persist** (expected with the current design, never written
  down); (2) 20 `screen_capture` events for Photo Booth via pid 525 need checking; (3)
  `backtrace` lines inflate the cmio count. No regression vs the previous runs.
- **Next steps:** identify pid 525; decide on reboot persistence.

## [2026-10-23 14:30 +0200] - Diverged branches merged (Linux container)

- **Environment:** Linux x86_64 cloud container, CPython 3.13.16, uid=0. Static checks only.
- **Goal:** unblock the Mac. `git pull origin claude/gifted-pascal-tp5iot` failed with
  "divergent branches". The plain `git pull` fast-forwarded the local branch to
  `origin/claude/amazing-pasteur-hj7ek5` (61a6547), which has no `scripts/` folder:
  `zsh: no such file or directory: scripts/macos_validate.sh`.
- **Cause:** after 66596f3 another session pushed 071bdce and 61a6547 to
  `claude/amazing-pasteur-hj7ek5`, while this session pushed 7 commits to
  `claude/gifted-pascal-tp5iot`. The two lines had no commit in common after 66596f3.
- **Code changes:** merge 2be7366 (its message reads "Log the branch divergence..." because the first `git commit` stopped on the unstaged resolution and the next commit completed the merge). The only conflict was `tests/test_sensors.py` (both sides
  appended tests), resolved by keeping both. `sensors.py` merged automatically: sandboxd /
  TCC-manager filter plus the other session's `system` flag and 5-tuple `_classify_tcc`.
- **Commands run:**
  ```sh
  git merge --no-ff origin/claude/amazing-pasteur-hj7ek5
  uv run ruff check && uv run mypy --strict && uv run pytest -q
  ```
- **Result and raw data:**
  ```text
  All checks passed!
  Success: no issues found in 20 source files
  120 passed, 7 skipped in 2.94s
  ```
- **Problems / regressions:** none in the tests. Note: the new default correlation window is
  2 s (was 0.5 s), and system-binary events are now hidden unless `--include-system`.
- **Next steps:** on the Mac,
  `git pull --ff-only origin claude/gifted-pascal-tp5iot && scripts/macos_validate.sh`.

## [2026-10-22 13:55 +0200] - Fixes from the third Mac run (Linux container)

- **Environment:** Linux 6.18.44 x86_64 cloud container, CPython 3.13.16, uid=0. Static
  checks only.
- **Goal:** act on the 13:51 run.
- **Code changes:**
  - `src/safemaxxing/sensors.py`: `sandboxd` added to `BROKER_PROCESSES`; any TCC line with
    `com.apple.private.tcc.manager` (a daemon's own right to query for others) is dropped.
  - `src/safemaxxing/diagnostics.py`, `cli.py`: `sample` prints each Control Center
    indicator update as `indicator <subsystem>: [kind:bundle, ...]`. A `[]` removal is no
    longer listed as unparsed. Each sensor kind keeps at least one parsed example.
  - `tests/live/test_live_macos.py`: also prints sensors, levels, indicators, parsed examples.
  - `scripts/macos_validate.sh`: Enter first, then open the apps within a 15 s sample; raw
    entries go to `testlogs/<stamp>-sample.jsonl`.
  - Tests: verbatim sandboxd lines, a generic manager line, CoreRoutine "Background
    Session" still attributed, indicator timeline.
- **Commands run:** `uv run ruff check && uv run mypy --strict && uv run pytest -q`
- **Result and raw data:**
  ```text
  All checks passed!
  Success: no issues found in 20 source files
  108 passed, 7 skipped in 2.34s
  ```
- **Problems / regressions:** none.
- **Next steps:** `git pull` then `scripts/macos_validate.sh` (PF_DISABLED_TEST not needed).

## [2026-10-22 13:51 +0200] - Third Mac run: pf auto-enable, non-root doctor, sensors in use

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, uid=501 + sudo, HEAD a534d12
  (pull OK after removing the colliding testlog). Pasted from "Task 1" onward.
- **Goal:** validate the non-root doctor fix and pf Disabled → auto-enable; sample with
  Photo Booth (camera) and Voice Memos (mic).
- **Code changes:** none (run of a534d12).
- **Commands run:** `PF_DISABLED_TEST=1 scripts/macos_validate.sh`; raw log on the Mac at
  `testlogs/20261022-1351-macos.log`.
- **Result and raw data:**
  - **Task 1 non-root:** `! pf status / pf parent anchor / anchor com.apple/safemaxxing:
    needs root (/dev/pf: Permission denied)` → **fix confirmed**. Root: exit 0, 31 pids
    incl. `_mdnsresponder`, `_netbios`.
  - **Task 2b:**
    ```text
    $ sudo pfctl -d                       -> pf disabled; Status: Disabled for 0 days 00:00:00
    $ sudo safemaxxing block 1.1.1.1      -> block_ip 1.1.1.1: ok 1/1 addresses added.
    $ sudo pfctl -s info                  -> Status: Enabled for 0 days 00:00:00
    curl 301 (0.042s) -> 000 (timeout 3.001s) -> unblock -> 301 (0.044s)
    ```
    **Automatic re-enable confirmed.**
  - **Task 3 `sample` 8 s** (216 entries):
    - `com.apple.TCC` 65 entries, 9 `<private>`, 41 parsed, all `tcc` (no camera/mic).
      Mostly `sandboxd` pid 401 checking `kTCCServiceSystemPolicyAllFiles` for others →
      **false attribution, fixed in 65305d6**. `CoreRoutine.helperservice` pid 36094
      correctly attributed.
    - `com.apple.cmio` 8 entries, all from `cameracaptured`, all
      `CMIOExtensionStream _initWithLocalizedName...<private>`: not start events.
    - `com.apple.locationd` 143 entries, 8 parsed (client CoreParsec).
    - **No `com.apple.coreaudio` entries and no indicator lines.** The apps were opened
      *before* Enter, so their start lines were logged before the stream began (script
      flaw, fixed in 65305d6).
  - **Live sample 5 s** (500 entries, apps open):
    - cmio 344 entries (`registerassistantservice` 207, `Photo Booth` 82,
      `cameracaptured` 23), 252 with `<private>`, **2 parsed with pid** (sensor not
      printed by the old test).
    - TCC 4 entries, 3 parsed (incl. `voicememod`).
    - controlcenter: `[sensor-indicators] Active activity attributions changed to []`, the
      apps being closed. Handled correctly (no new attribution), but listed as "unparsed".
  - **Task 4:** DNS 1-3 ms (warm cache); `17.253.144.10` → `www.brkgls.com` in 90 ms
    (< 100 ms cap).
  - Live suite **7/7 PASSED** in 12.75 s.
- **Redaction (Task 3):** on every subsystem `no image path` = 0 and `no pid` = 0, so PID
  and processImagePath arrive in clear. `<private>` appears only inside messages: cmio
  73% (252/344), locationd ~25%, TCC 14% (9/65). Bundle IDs in TCC `TCCDProcess` blocks
  are in clear.
- **Problems / regressions vs Linux:** (1) sandboxd false positives (fixed); (2) camera/mic
  start not captured, a procedure problem (fixed); (3) no coreaudio lines while recording:
  the mic depends on the `mic:` indicator, still to be observed.
- **Next steps:** re-run the sample with the apps opened *during* the 15 s.

## [2026-10-22 13:50 +0200] - Second Mac run: STALE code (pull aborted)

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, uid=501 + sudo. Local branch
  `claude/amazing-pasteur-hj7ek5` still at **f58a357**.
- **Goal:** validate bc5a019 (non-root doctor), pf Disabled → auto-enable
  (`PF_DISABLED_TEST=1`), and the sample with camera and mic active.
- **Code changes:** none (the pull did not apply).
- **Commands run:**
  ```sh
  git pull origin claude/gifted-pascal-tp5iot
  PF_DISABLED_TEST=1 scripts/macos_validate.sh
  ```
- **Result and raw data:**
  ```text
  error: The following untracked working tree files would be overwritten by merge:
          testlogs/20261022-1345-macos.log
  Aborting
  ```
  The script ran anyway at f58a357, the old version: no pause before the sample, no
  `PF_DISABLED_TEST`, doctor still says "parent anchor missing" without sudo, and the
  `.pytest_cache` warning is still there. The results repeat the 13:45 run:
  - doctor (root) exit 0, 30 pids incl. `_mdnsresponder`, `_netbios`; snapshot 8-9 ms.
  - Block of 1.1.1.1: `301` → `000` (timeout 3.007 s) → `301`. pf was already Enabled
    (for 37 min).
  - Sample 8 s: 111 locationd entries, 33 with `<private>`, 0 without image path or pid.
    New client parsed correctly: `CoreParsec`
    (`root:com.apple.locationd.bundle-/System/Library/PrivateFrameworks/CoreParsec.framework`).
    No camera or mic activity.
  - DNS: every answer in 1-3 ms (mDNSResponder cache, warm after the previous run;
    9.9.9.9 now resolves to `dns9.quad9.net`).
  - Live suite 7/7 PASSED in 12.51 s.
  - Raw log is on the Mac at `testlogs/20261022-1350-macos.log` (not committed from here).
- **Problems / regressions:** no code regression. Process problem: committing from the
  container a log that the script also creates on the Mac makes `git pull` fail. From now on
  `testlogs/` is committed **only from the Mac**.
- **Next steps:** on the Mac:
  ```sh
  rm testlogs/20261022-1345-macos.log   # identical copy is already in the repo
  git pull origin claude/gifted-pascal-tp5iot
  git log --oneline -1                  # must show 511c802 or later
  PF_DISABLED_TEST=1 scripts/macos_validate.sh
  ```

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
