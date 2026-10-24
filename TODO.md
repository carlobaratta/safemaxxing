# TODO

Format: `- [ ] [P1] Title @area #tag (details / key commands)`.
Rule: max 1-2 tasks in **Now**; every finished task moves to **Completed** with date and commit.
Each test session is logged in [TESTLOG.md](TESTLOG.md); raw logs live in `testlogs/`.
Rule: `testlogs/*.log` are committed only from the Mac that produced them (a copy committed
elsewhere makes the next `git pull` there fail); raw `testlogs/*.jsonl` are never committed.

## Inbox

- [ ] [P2] Tag `v0.1.0` on `main` once the screen-recording check in **Now** is done; the `claude/*` branches stay as history (frozen at 40ed2b8) @process #release

- [ ] [P2] Decide whether the `pfctl -E` reference token should be released (`pfctl -X <token>`) on `flush` @firewall #pf (today pf stays enabled after the first block, by design)

## Now (In Progress)

- [ ] [P1] Screen *recording* (video) live: start a QuickTime / Cmd+Shift+5 recording and keep it going for a few seconds *inside* the 15 s sample @sensors #tcc (the QuickTime run at 2026-10-23 produced no ScreenCapture line and no `scr:`: recording probably not started)

## Next Up


- [ ] [P2] Screen sharing from a third-party app via ScreenCaptureKit (e.g. Meet in Brave): does replayd send with `target_token={pid:app}`? The logging-pid rule would drop it; then only `scr:<bundle>` would catch it @sensors #tcc

- [ ] [P2] Live `watch` with Photo Booth / Voice Memos: confirm they are hidden as system apps (`/System/Applications`) and shown with `--include-system` @correlation #macos
- [ ] [P3] cmio `CMIODeviceStartStream backtrace N` lines count as extra camera events (32 for one start); cooldown collapses them, but `sample` counts are inflated @sensors #cmio

- [ ] [P2] Grant Full Disk Access to the terminal and confirm the FDA check turns OK @cli #fda (System Settings → Privacy & Security → Full Disk Access)
- [ ] [P2] Watch `sudo uv run safemaxxing tui` for freezes for a few minutes of normal browsing @network #dns

## Backlog / Future

- [ ] [P2] SNI / TLS ClientHello capture to name destinations without reverse DNS @network #sni
- [ ] [P2] Packaging: signed, notarized build; launchd daemon for headless `watch` @packaging #release
- [ ] [P3] Menu-bar app (status, last alerts, one-click block) @ui #menubar
- [ ] [P3] Read TCC.db (with Full Disk Access) to show which apps hold camera/mic grants @sensors #tcc
- [ ] [P3] CI job on a macOS runner for the non-root parts of the live suite @ci #macos

## Completed

- [x] [P1] Reboot test of `boot install`: after a real restart the job rebuilt the table (`1 table created`, `1/1 addresses added`) and re-enabled pf; `boot status` saved 1 = live 1, `curl https://1.1.1.1` timed out; see TESTLOG 2026-10-24 20:38 @firewall #pf (done: 2026-10-24, Mac run)
- [x] [P1] Blocks can survive a reboot: `block`/`unblock`/`flush` save to `/Library/Application Support/safemaxxing/blocklist`; `boot install|status|uninstall` manage a launchd job that waits for pf.conf, loads the anchor, `pfctl -T add -f` the list and `pfctl -E`, using only /bin/sh and /sbin/pfctl. Script tested under sh with a fake pfctl, then across a real reboot @firewall #pf (done: 2026-10-24 @2e55bba)
- [x] [P2] Indicator events of Apple apps are now hidden without `--include-system`: `system` only when every running process that may carry the bundle id (any enclosing .app, or an unreadable Info.plist outside SIP) runs from a SIP path. They stay correlated, so a spoofed bundle id still alerts. Hostile Info.plists (malformed, FIFO) no longer crash or hang `log stream` @sensors #system (done: 2026-10-23 @eb9c13b)
- [x] [P3] `calaccessd` is a broker (checks Calendar/Reminders for routined): added to `BROKER_PROCESSES`, verbatim fixture; 7 false events gone on the real captures @sensors #tcc (done: 2026-10-23 @d9ca8c8)
- [x] [P3] coreaudio closed as "indicator + TCC are enough": IO-start lines exist (audiomxd `input_running`) but add nothing over tccd's mic request and `mic:`; see TESTLOG 16:33 @sensors #mic (done: 2026-10-23, no code change)
- [x] [P3] Non-root `doctor`: `socket snapshot` now reads "needs root (psutil denied): lsof fallback, slower" like the pf checks; CI `build` job installs the wheel with the locked dependencies @cli #doctor (done: 2026-10-23 @4d97f18)
- [x] [P1] Day-to-day work moved onto `main`, cloud session included; `claude/*` branches frozen @process #git (done: 2026-10-23 @40ed2b8)
- [x] [P1] `main` created from 25744dc and set as GitHub's default branch; `claude/*` branches kept, all three at the same commit @process #git (done: 2026-10-23 @25744dc)
- [x] [P2] Docstrings for every public API outside `sensors.py`, `--help` for every argument, CI actions bumped to checkout@v7 / setup-uv@v7, TESTLOG entries back in newest-first order @docs #github (done: 2026-10-23 @2857704)
- [x] [P1] GitHub documentation pass: README checked claim by claim against the code (Italian, all options documented), SECURITY/CONTRIBUTING/CHANGELOG, issue and PR templates, Dependabot, CI permissions/concurrency, raw `testlogs/*.jsonl` git-ignored; 14:24 raw log committed from the Mac @docs #github (done: 2026-10-23 @57fdd2d, @313920e)
- [x] [P1] Screen capture live (Cmd+Shift+5 ×2): first real `scr:` indicator (`scr:com.apple.systemuiserver`), replayd pid 733's own request counted; pinned as a test @sensors #tcc (done: 2026-10-23 @ec1c8ee)

- [x] [P1] Screen capture counts only when the capturing process logs its own request: drops WindowServer/coreaudiod preflights and tccd's echoes (all 9 line kinds from the 14:24 dump) @sensors #tcc (done: 2026-10-23 @09c2673)

- [x] [P1] pid 525 = `/usr/sbin/coreaudiod`: its `kTCCServiceScreenCapture` requests for audio clients are no longer screen captures (mic requests still attributed) @sensors #tcc (done: 2026-10-23 @1cbeb54)

- [x] [P1] Task 3b: camera, mic and location caught live: TCC camera/mic for Photo Booth pid 34389, cmio `CMIODeviceStartStream` with pid, indicator `cam:`/`loc:`/`mic:` (first real `mic`), real sequence pinned as a test @sensors #log (done: 2026-10-23 @c19cc1b, Mac run 14:24)
- [x] [P1] Task 2c: pf cold start after reboot: `Disabled`, anchor `DIOCGETRULES: Invalid argument`, table missing → `block` creates the table, loads the anchor, enables pf; curl 301 → 000 → 301 @firewall #pf (done: 2026-10-23 @97763f1, Mac run 14:24)
- [x] [P2] photolibraryd's `tcc.manager` self check dropped by the generic rule (a daemon it was not written for) @sensors #tcc (done: 2026-10-23 @65305d6, Mac run 14:24)

- [x] [P1] Merge `claude/amazing-pasteur-hj7ek5` into this branch: 1 conflict (tests appended on both sides), ruff/mypy 0, 120 passed @process #git (done: 2026-10-23 @2be7366)
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
