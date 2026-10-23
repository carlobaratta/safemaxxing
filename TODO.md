# TODO

Format: `- [ ] [P1] Title @area #tag (details / key commands)`.
Rule: max 1-2 tasks in **Now**; every finished task moves to **Completed** with date and commit.
Each test session is logged in [TESTLOG.md](TESTLOG.md); raw logs live in `testlogs/`.

## Inbox

- [ ] [P1] Use a single branch: `claude/amazing-pasteur-hj7ek5` (another session) and `claude/gifted-pascal-tp5iot` (this one) diverged on 2026-10-23 @process #git (merged in @2d6586d; on the Mac: `git pull --ff-only origin claude/gifted-pascal-tp5iot`)

- [ ] [P1] Process rule: `testlogs/*.log` are committed only from the Mac, never from the container @process #tracking (a container commit made `git pull` fail at 13:50)
- [ ] [P2] No `com.apple.coreaudio` lines at all while Voice Memos recorded: rely on the `mic:` indicator, or find the new subsystem with `sample --wide --debug` @sensors #mic
- [ ] [P3] `calaccessd` (7 TCC lines at 13:51) may be another broker: check its lines in the raw JSON @sensors #tcc
- [ ] [P2] Decide whether the `pfctl -E` reference token should be released (`pfctl -X <token>`) on `flush` @firewall #pf (today pf stays enabled after the first block, by design)
- [ ] [P3] `socket snapshot` without root falls back to lsof: say "needs root" there too @cli #doctor

## Now (In Progress)

- [ ] [P1] Task 3b: log sample with camera and mic opened *during* the sample @sensors #log (`git pull`, `scripts/macos_validate.sh`: Enter first, then open Photo Booth + record in Voice Memos within 15 s; expect `indicator ... [cam:com.apple.PhotoBooth]` and `[mic:com.apple.VoiceMemos]`, camera/microphone events; raw entries in `testlogs/<stamp>-sample.jsonl`)

## Next Up

- [ ] [P2] Grant Full Disk Access to the terminal and confirm the FDA check turns OK @cli #fda (System Settings → Privacy & Security → Full Disk Access)
- [ ] [P2] Watch `sudo uv run safemaxxing tui` for freezes for a few minutes of normal browsing @network #dns

## Backlog / Future

- [ ] [P2] SNI / TLS ClientHello capture to name destinations without reverse DNS @network #sni
- [ ] [P2] Packaging: signed, notarized build; launchd daemon for headless `watch` @packaging #release
- [ ] [P3] Menu-bar app (status, last alerts, one-click block) @ui #menubar
- [ ] [P3] Read TCC.db (with Full Disk Access) to show which apps hold camera/mic grants @sensors #tcc
- [ ] [P3] CI job on a macOS runner for the non-root parts of the live suite @ci #macos

## Completed

- [x] [P1] Merge `claude/amazing-pasteur-hj7ek5` into this branch: 1 conflict (tests appended on both sides), ruff/mypy 0, 120 passed @process #git (done: 2026-10-23 @2d6586d)
- [x] [P1] (other session) Hide system-binary events, skip DNS egress (53/853/5353), fix swallowed `[high]` markup: first real alert, Brave mic → UDP :53 after 267 ms @correlation #macos (done: 2026-10-23 @071bdce)
- [x] [P1] (other session) One alert per connection, 2 s default window, name pid-only events via psutil: Brave + Google Meet run @correlation #macos (done: 2026-10-23 @61a6547)

- [x] [P1] sandboxd / TCC-manager self checks no longer reported as accesses; `sample` shows the indicator timeline and one example per sensor; script samples *while* the apps open @sensors #tcc (done: 2026-10-22 @65305d6)
- [x] [P1] Task 2b: pf Disabled → `safemaxxing block` re-enables it (`Status: Disabled` → `Enabled`), curl 301 → 000 → 301 @firewall #pf (done: 2026-10-22 @a534d12, Mac run 13:51)
- [x] [P2] Non-root `doctor` now reads "needs root (/dev/pf: Permission denied)" for the 3 pf checks @cli #doctor (done: 2026-10-22 @a534d12, Mac run 13:51)
- [x] [P1] Unblock the pull on the Mac (removed the colliding testlog) @process #git (done: 2026-10-22, Mac run 13:51 at a534d12)

- [x] [P2] Second Mac run (stale code f58a357): block/unblock, doctor, DNS and live suite 7/7 confirmed again; CoreParsec location client parsed @macos #validation (done: 2026-10-22 @f58a357, Mac run 13:50)

- [x] [P1] Doctor non-root: pf checks say "needs root" instead of "parent anchor missing"; Mac noise fixtures; script fixes; raw log archived @cli #doctor (done: 2026-10-22 @bc5a019)
- [x] [P1] Task 4: reverse DNS on the real resolver stays within budget: max 100 ms (9.9.9.9 timed out at the cap), live test PASSED @network #dns (done: 2026-10-22 @f58a357, Mac run 13:45)
- [x] [P1] Task 3a: real 8 s + 5 s `log stream` sample on macOS 27.0.1; PID and processImagePath arrive in clear, only message fields are `<private>`; no parser change needed @sensors #log (done: 2026-10-22 @f58a357, Mac run 13:45)
- [x] [P1] Task 2: live kernel block of 1.1.1.1: curl 301 → 000 (timeout 3 s) → 301 after unblock; anchor and table show no warnings @firewall #pf (done: 2026-10-22 @f58a357, Mac run 13:45)
- [x] [P1] Task 1: `sudo safemaxxing doctor` on macOS 27.0.1 / Apple M4: 0 FAIL, 1 WARN (Full Disk Access) @cli #doctor (done: 2026-10-22 @f58a357, Mac run 13:45)
- [x] [P1] Static checks on the Mac: ruff 0, mypy 0, pytest 103 passed / 7 skipped; live suite 7/7 PASSED @tests #macos (done: 2026-10-22 @f58a357)
- [x] [P1] Base suite with mocks green on Linux: 102 tests (the brief said 41; the suite has grown) + 6 live tests skipped @tests #baseline (done: 2026-10-22 @66596f3)
- [x] [P1] Doctor: root, pf status (Enabled/Disabled), parent anchor, our anchor, foreign sockets, Full Disk Access, snapshot latency, log predicate @cli #doctor (done: 2026-10-22 @49f16e3)
- [x] [P1] Firewall: auto-enable pf with `pfctl -E`, falling back to `-e`; anchor `com.apple/safemaxxing` without a `table` definition so reloads never reset it @firewall #pf (done: 2026-10-22 @49f16e3)
- [x] [P1] Darwin pfctl quirks: stderr decoding, missing anchor/table replies, benign `-f` warning; unblock independent of setup @firewall #pf (done: 2026-10-22 @f655d9f, @74eafa3)
- [x] [P1] Log parsers for formats seen on macOS 27.0.1: TCCDProcess blocks, `<private>`/`<mask.hash>` tokens, locationd clients, Control Center sensor-indicator attributions @sensors #log (done: 2026-10-22 @bd884f9, @66596f3)
- [x] [P1] Non-blocking reverse DNS: dedicated thread pool, 100 ms timeout, prefetch only in the poll loop @network #dns (done: 2026-10-22 @49f16e3)
- [x] [P1] Doctor: foreign-socket check distinguishes system daemons and reports lsof failures; live DNS-budget test; `scripts/macos_validate.sh` @cli #doctor (done: 2026-10-22 @ab5aaaa)
- [x] [P1] Create TODO.md and TESTLOG.md @process #tracking (done: 2026-10-22 @f58a357)
