# TODO

Format: `- [ ] [P1] Title @area #tag (details / key commands)`.
Rule: max 1-2 tasks in **Now**; every finished task moves to **Completed** with date and commit.
Each test session is logged in [TESTLOG.md](TESTLOG.md); raw logs live in `testlogs/`.
Rule: `testlogs/*.log` are committed only from the Mac that produced them (a copy committed
elsewhere makes the next `git pull` there fail); raw `testlogs/*.jsonl` are never committed.

## Inbox


## Now (In Progress)

- [ ] [P2] pktap egress source, phase 2: wire `PktapCapture` into `Supervisor` (a second connection source), `doctor` and the CLI, then check a Meet call in Brave raises the alert end to end. Always-on (per-pid ruled out: TESTLOG 08:35); the interface design of 2026-10-26 (`AlwaysOnFlows`, `--udp-flows`, `pktap_unavailable`, restarts) is in that session's scratchpad, not in the repo @network #udp (phase 1 in Completed)

## Next Up

- [ ] [P2] Grant Full Disk Access to the terminal and confirm the FDA check turns OK @cli #fda (System Settings → Privacy & Security → Full Disk Access)
- [ ] [P2] Watch `sudo uv run safemaxxing tui` for freezes for a few minutes of normal browsing @network #dns
- [ ] [P2] Live `watch` with Photo Booth / Voice Memos: confirm they are hidden as system apps (`/System/Applications`) and shown with `--include-system` @correlation #macos
- [ ] [P2] Decide whether the `pfctl -E` reference token should be released (`pfctl -X <token>`) on `flush` @firewall #pf (today pf stays enabled after the first block, by design; proposal: keep it and say so in SECURITY.md)
- [ ] [P2] launchd daemon for headless `watch` (the 0.2.0 feature; reuses the `boot` job's launchd setup) @packaging #launchd

## Backlog / Future

- [ ] [P3] pktap: drop directed broadcasts from user processes (the interfaces' broadcast addresses via `psutil.net_if_addrs`); bundle id for `.systemextension` binaries (Avast's shows None) @network #udp
- [ ] [P2] SNI / TLS ClientHello capture to name destinations without reverse DNS @network #sni
- [ ] [P2] Packaging: signed, notarized build @packaging #release
- [ ] [P3] Menu-bar app (status, last alerts, one-click block) @ui #menubar
- [ ] [P3] Read TCC.db (with Full Disk Access) to show which apps hold camera/mic grants @sensors #tcc
- [ ] [P3] CI job on a macOS runner for the non-root parts of the live suite @ci #macos

## Completed

- [x] [P2] pktap measured during a Meet call: always-on tcpdump 0.45% of one core at 151 lines/s, parser 6.45 µs/line (~0.10%); `-Q pid=16105` (Brave main) caught 0 of 7458 packets, so per-pid capture is ruled out; `-Q` is applied in userspace. Command now has `--immediate-mode` and excludes DNS ports; proc-less `llw0` lines pinned @network #udp (done: 2026-10-27, Mac run 08:35 @298328d)
- [x] [P2] pktap source run as root during a Meet call: the real output parses, and gives 1 connection `Brave Browser Helper 16112 → 74.125.250.248:3478` (bundle `com.brave.Browser`), plus Avast DNS (dropped later as port 53) and `kernel_task` NetBIOS broadcasts. pid 0 is now system @network #udp (done: 2026-10-27, Mac run 08:34 @298328d)
- [x] [P2] pktap egress source, phase 1: `PktapEvent`/`Direction` in `models.py`; `safemaxxing/pktap.py` with the line parser (process names capped at 16 characters, so a name cannot forge the metadata fields), `PktapFlowTracker` (first outbound packet per flow = one `NetworkConnection`, status `PKTAP`, idle 60 s, bounded table, system/link-local filter, process looked up per flow and never cached) and `PktapCapture` (tcpdump stopped with SIGTERM, then SIGKILL, and always reaped; inner generators closed with `aclosing`). Fixtures cut from the 5 captures in `tests/fixtures/pktap/`; 47 new tests, suite 207 passed. Not yet run as root @network #udp (done: 2026-10-27 @298328d)
- [x] [P2] Unconnected UDP egress source investigated during a Meet call in Brave: `nettop` (no root) counts bytes per socket but shows `*:*` as peer (`udp4 *:53266<->*:*`, ~66 KB/s out); pktap via `sudo tcpdump -k -i pktap,en0` names `proc Brave Browser He:16112`, `out`, and the destination `74.125.250.240:3478`. pf logging not needed @network #udp (done: 2026-10-26, Mac run 14:04, no code change)
- [x] [P2] Released `v0.1.1` (alpha) on `main`: CHANGELOG `[0.1.1] - 2026-10-26`, `__version__` 0.1.1, GitHub pre-release like 0.1.0 @process #release (done: 2026-10-26)
- [x] [P3] Indicator flicker merged: an attribution back within 2 s (`INDICATOR_MERGE_S`) of going off is the same use; short spans are kept, so a blinking Brave share is one event per share. cmio `backtrace N` lines dropped. Replay: camera 55 → 5 (Brave), 40 → 10, 42 → 12; `scr:` 10 → 2, 13 → 1, 2 → 1 @sensors #indicator (done: 2026-10-26 @7c7260c, TESTLOG 13:54)
- [x] [P3] coreaudiod TCC preflights dropped: the whole request is linked by `activityIdentifier` and dropped when tccd's REQUEST_MSG says `preflight=true`; real requests (Voice Memos, `preflight=false`) still count. Replay: no mic event left for `screencapture` 3506 or Brave 1761 @sensors #mic (done: 2026-10-26 @1eb829f, TESTLOG 13:54)
- [x] [P2] Live Brave alert from a Meet share: closed as not possible with the socket table. Meet's media/QUIC is on Brave's NetworkService helper (6266), on 12 UDP sockets with no remote address, and its TCP :443 connections are reused, so no new egress follows the event. Follow-up in **Now** @correlation #macos (done: 2026-10-26, Mac run 13:27, no code change)
- [x] [P2] Live `watch --events` during a Meet share in Brave: `screen_capture com.brave.Browser pid=6254 (ScreenCapture)`, visible without `--include-system`; camera/mic attributed to Brave and its VideoCaptureService (6299) / AudioService (6298) helpers @sensors #tcc (done: 2026-10-26, Mac run 13:20 at 5040508, no code change)
- [x] [P2] replayd's ScreenCapture requests attributed to the client from tccd's REQUEST_MSG `AUDIT_TOKEN_KEY={pid:N}`; `replayd` is a broker. Replay of the real samples: Brave 1761 ×540 and 6254 ×244, `screencapture` 3506 ×4, instead of `replayd`; Cmd+Shift+5 clients are still SIP binaries, so still hidden @sensors #tcc (done: 2026-10-26 @ff1c9f7, TESTLOG 10:41)
- [x] [P2] Meet in Brave with a working window share (Brave restarted after the Screen Recording grant): all 244 replayd REQUEST_MSGs carry `AUDIT_TOKEN_KEY={pid:6254}` = Brave, none preflight; `scr:` shows as 10 short spans, not one continuous span @sensors #tcc (done: 2026-10-26, Mac run 10:30, no code change)
- [x] [P2] Third-party screen sharing (Meet in Brave): replayd sends on the app's behalf, Brave's pid only in tccd's REQUEST_MSG audit token; the parser gives the events to replayd, so they are hidden as system and only `scr:com.brave.Browser` remains. Fix task in **Next Up** @sensors #tcc (done: 2026-10-26, Mac run 10:23, no code change)
- [x] [P3] coreaudiod mic preflights checked against Brave/Meet: preflight only, no real mic use; real mic seen only through `mic:`. Drop task in **Next Up** @sensors #mic (done: 2026-10-26, Mac run 10:23, no code change)
- [x] [P2] Tagged `v0.1.0` on `main`; CHANGELOG `[Unreleased]` became `[0.1.0] - 2026-10-24`; the `claude/*` branches stay as history (frozen at fbc006a) @process #release (done: 2026-10-24)
- [x] [P1] Screen *recording* live (Cmd+Shift+5, ~8 s inside a 25 s sample): replayd's own ScreenCapture requests plus `scr:com.apple.systemuiserver` on for 7.4 s = the recording; attributed to SIP system processes, so hidden without `--include-system` @sensors #tcc (done: 2026-10-24, Mac run 20:42, no code change)
- [x] [P1] Reboot test of `boot install`: after a real restart the job rebuilt the table (`1 table created`, `1/1 addresses added`) and re-enabled pf; `boot status` saved 1 = live 1, `curl https://1.1.1.1` timed out; see TESTLOG 2026-10-24 20:38 @firewall #pf (done: 2026-10-24, Mac run)
- [x] [P1] Blocks can survive a reboot: `block`/`unblock`/`flush` save to `/Library/Application Support/safemaxxing/blocklist`; `boot install|status|uninstall` manage a launchd job that waits for pf.conf, loads the anchor, `pfctl -T add -f` the list and `pfctl -E`, using only /bin/sh and /sbin/pfctl. Script tested under sh with a fake pfctl, then across a real reboot @firewall #pf (done: 2026-10-24 @9b0af93)
- [x] [P2] Indicator events of Apple apps are now hidden without `--include-system`: `system` only when every running process that may carry the bundle id (any enclosing .app, or an unreadable Info.plist outside SIP) runs from a SIP path. They stay correlated, so a spoofed bundle id still alerts. Hostile Info.plists (malformed, FIFO) no longer crash or hang `log stream` @sensors #system (done: 2026-10-23 @fca16c9)
- [x] [P3] `calaccessd` is a broker (checks Calendar/Reminders for routined): added to `BROKER_PROCESSES`, verbatim fixture; 7 false events gone on the real captures @sensors #tcc (done: 2026-10-23 @9bd6f54)
- [x] [P3] coreaudio closed as "indicator + TCC are enough": IO-start lines exist (audiomxd `input_running`) but add nothing over tccd's mic request and `mic:`; see TESTLOG 16:33 @sensors #mic (done: 2026-10-23, no code change)
- [x] [P3] Non-root `doctor`: `socket snapshot` now reads "needs root (psutil denied): lsof fallback, slower" like the pf checks; CI `build` job installs the wheel with the locked dependencies @cli #doctor (done: 2026-10-23 @fb802ee)
- [x] [P1] Day-to-day work moved onto `main`, cloud session included; `claude/*` branches frozen @process #git (done: 2026-10-23 @fbc006a)
- [x] [P1] `main` created from b695eb2 and set as GitHub's default branch; `claude/*` branches kept, all three at the same commit @process #git (done: 2026-10-23 @b695eb2)
- [x] [P2] Docstrings for every public API outside `sensors.py`, `--help` for every argument, CI actions bumped to checkout@v7 / setup-uv@v7, TESTLOG entries back in newest-first order @docs #github (done: 2026-10-23 @04f9d02)
- [x] [P1] GitHub documentation pass: README checked claim by claim against the code (Italian, all options documented), SECURITY/CONTRIBUTING/CHANGELOG, issue and PR templates, Dependabot, CI permissions/concurrency, raw `testlogs/*.jsonl` git-ignored; 14:24 raw log committed from the Mac @docs #github (done: 2026-10-23 @dd2540c, @7da88af)
- [x] [P1] Screen capture live (Cmd+Shift+5 ×2): first real `scr:` indicator (`scr:com.apple.systemuiserver`), replayd pid 733's own request counted; pinned as a test @sensors #tcc (done: 2026-10-23 @df634b1)

- [x] [P1] Screen capture counts only when the capturing process logs its own request: drops WindowServer/coreaudiod preflights and tccd's echoes (all 9 line kinds from the 14:24 dump) @sensors #tcc (done: 2026-10-23 @17ee6c8)

- [x] [P1] pid 525 = `/usr/sbin/coreaudiod`: its `kTCCServiceScreenCapture` requests for audio clients are no longer screen captures (mic requests still attributed) @sensors #tcc (done: 2026-10-23 @e5a62bc)

- [x] [P1] Task 3b: camera, mic and location caught live: TCC camera/mic for Photo Booth pid 34389, cmio `CMIODeviceStartStream` with pid, indicator `cam:`/`loc:`/`mic:` (first real `mic`), real sequence pinned as a test @sensors #log (done: 2026-10-23 @10ac350, Mac run 14:24)
- [x] [P1] Task 2c: pf cold start after reboot: `Disabled`, anchor `DIOCGETRULES: Invalid argument`, table missing → `block` creates the table, loads the anchor, enables pf; curl 301 → 000 → 301 @firewall #pf (done: 2026-10-23 @65370e5, Mac run 14:24)
- [x] [P2] photolibraryd's `tcc.manager` self check dropped by the generic rule (a daemon it was not written for) @sensors #tcc (done: 2026-10-23 @70fbd74, Mac run 14:24)

- [x] [P1] Merge `claude/amazing-pasteur-hj7ek5` into this branch: 1 conflict (tests appended on both sides), ruff/mypy 0, 120 passed @process #git (done: 2026-10-23 @c9155e4)
- [x] [P1] (other session) Hide system-binary events, skip DNS egress (53/853/5353), fix swallowed `[high]` markup: first real alert, Brave mic → UDP :53 after 267 ms @correlation #macos (done: 2026-10-23 @c6cdc44)
- [x] [P1] (other session) One alert per connection, 2 s default window, name pid-only events via psutil: Brave + Google Meet run @correlation #macos (done: 2026-10-23 @b7f39ba)

- [x] [P1] sandboxd / TCC-manager self checks no longer reported as accesses; `sample` shows the indicator timeline and one example per sensor; script samples *while* the apps open @sensors #tcc (done: 2026-10-22 @70fbd74)
- [x] [P1] Task 2b: pf Disabled → `safemaxxing block` re-enables it (`Status: Disabled` → `Enabled`), curl 301 → 000 → 301 @firewall #pf (done: 2026-10-22 @5b18f0f, Mac run 13:51)
- [x] [P2] Non-root `doctor` now reads "needs root (/dev/pf: Permission denied)" for the 3 pf checks @cli #doctor (done: 2026-10-22 @5b18f0f, Mac run 13:51)
- [x] [P1] Unblock the pull on the Mac (removed the colliding testlog) @process #git (done: 2026-10-22, Mac run 13:51 at 5b18f0f)

- [x] [P2] Second Mac run (stale code c895276): block/unblock, doctor, DNS and live suite 7/7 confirmed again; CoreParsec location client parsed @macos #validation (done: 2026-10-22 @c895276, Mac run 13:50)

- [x] [P1] Doctor non-root: pf checks say "needs root" instead of "parent anchor missing"; Mac noise fixtures; script fixes; raw log archived @cli #doctor (done: 2026-10-22 @34c9f53)
- [x] [P1] Task 4: reverse DNS on the real resolver stays within budget: max 100 ms (9.9.9.9 timed out at the cap), live test PASSED @network #dns (done: 2026-10-22 @c895276, Mac run 13:45)
- [x] [P1] Task 3a: real 8 s + 5 s `log stream` sample on macOS 27.0.1; PID and processImagePath arrive in clear, only message fields are `<private>`; no parser change needed @sensors #log (done: 2026-10-22 @c895276, Mac run 13:45)
- [x] [P1] Task 2: live kernel block of 1.1.1.1: curl 301 → 000 (timeout 3 s) → 301 after unblock; anchor and table show no warnings @firewall #pf (done: 2026-10-22 @c895276, Mac run 13:45)
- [x] [P1] Task 1: `sudo safemaxxing doctor` on macOS 27.0.1 / Apple M4: 0 FAIL, 1 WARN (Full Disk Access) @cli #doctor (done: 2026-10-22 @c895276, Mac run 13:45)
- [x] [P1] Static checks on the Mac: ruff 0, mypy 0, pytest 103 passed / 7 skipped; live suite 7/7 PASSED @tests #macos (done: 2026-10-22 @c895276)
- [x] [P1] Base suite with mocks green on Linux: 102 tests (the brief said 41; the suite has grown) + 6 live tests skipped @tests #baseline (done: 2026-10-22 @32c1b74)
- [x] [P1] Doctor: root, pf status (Enabled/Disabled), parent anchor, our anchor, foreign sockets, Full Disk Access, snapshot latency, log predicate @cli #doctor (done: 2026-10-22 @9d90a90)
- [x] [P1] Firewall: auto-enable pf with `pfctl -E`, falling back to `-e`; anchor `com.apple/safemaxxing` without a `table` definition so reloads never reset it @firewall #pf (done: 2026-10-22 @9d90a90)
- [x] [P1] Darwin pfctl quirks: stderr decoding, missing anchor/table replies, benign `-f` warning; unblock independent of setup @firewall #pf (done: 2026-10-22 @d26885a, @631b592)
- [x] [P1] Log parsers for formats seen on macOS 27.0.1: TCCDProcess blocks, `<private>`/`<mask.hash>` tokens, locationd clients, Control Center sensor-indicator attributions @sensors #log (done: 2026-10-22 @a25e3fb, @32c1b74)
- [x] [P1] Non-blocking reverse DNS: dedicated thread pool, 100 ms timeout, prefetch only in the poll loop @network #dns (done: 2026-10-22 @9d90a90)
- [x] [P1] Doctor: foreign-socket check distinguishes system daemons and reports lsof failures; live DNS-budget test; `scripts/macos_validate.sh` @cli #doctor (done: 2026-10-22 @9421e63)
- [x] [P1] Create TODO.md and TESTLOG.md @process #tracking (done: 2026-10-22 @c895276)
