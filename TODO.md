# TODO

Format: `- [ ] [P1] Title @area #tag (details / key commands)`.
Rule: max 1-2 tasks in **Now**; every finished task moves to **Completed** with date and commit.
Each test session is logged in [TESTLOG.md](TESTLOG.md).

## Inbox

- [ ] [P2] Decide whether `pfctl -E` reference token should be released (`pfctl -X <token>`) on `flush` @firewall #pf (today pf stays enabled after the first block, by design)
- [ ] [P3] Commit the first `testlogs/*-macos.log` raw logs or gitignore them @process #tracking

## Now (In Progress)

- [ ] [P1] Run the macOS validation script on the real Mac and paste the results into TESTLOG.md @macos #validation (`scripts/macos_validate.sh`, needs sudo; writes `testlogs/<stamp>-macos.log`)

## Next Up

- [ ] [P1] Task 1: real `sudo uv run safemaxxing doctor` with 0 FAIL @cli #doctor (check root, `pfctl -s info` Enabled/Disabled, foreign sockets incl. `root`/`_daemon`, Full Disk Access via system TCC.db)
- [ ] [P1] Task 2: live pf block/unblock of a public IP @firewall #pf (`safemaxxing block 1.1.1.1` → curl `000`; `unblock` → HTTP code; `pfctl -a com.apple/safemaxxing -s rules` and `-T show` without warnings; pf auto-enabled if it was Disabled)
- [ ] [P1] Task 3: 5-10 s `log stream` sample on the current macOS @sensors #log (`sudo uv run safemaxxing sample --seconds 8`, also `--wide` and `--debug`; record `<private>` counts for TCC/cmio/coreaudio/locationd; add verbatim new lines as test fixtures and fix parsers)
- [ ] [P1] Task 4: confirm reverse DNS never stalls the 200 ms poller on the real resolver @network #dns (`pytest -m live -k reverse_dns`; watch for freezes in `safemaxxing tui`)
- [ ] [P2] Final closure: ruff 0, mypy --strict 0, pytest 100% on the Mac; update TODO.md and TESTLOG.md @process #closure

## Backlog / Future

- [ ] [P2] SNI / TLS ClientHello capture to name destinations without reverse DNS @network #sni
- [ ] [P2] Packaging: signed, notarized build; launchd daemon for headless `watch` @packaging #release
- [ ] [P3] Menu-bar app (status, last alerts, one-click block) @ui #menubar
- [ ] [P3] Read TCC.db (with Full Disk Access) to show which apps hold camera/mic grants @sensors #tcc
- [ ] [P3] CI job on a macOS runner for the non-root parts of the live suite @ci #macos

## Completed

- [x] [P1] Base suite with mocks green on Linux: 102 tests (the brief said 41; the suite has grown) + 6 live tests skipped @tests #baseline (done: 2026-10-22 @66596f3)
- [x] [P1] Doctor: root, pf status (Enabled/Disabled), parent anchor, our anchor, foreign sockets, Full Disk Access, snapshot latency, log predicate @cli #doctor (done: 2026-10-22 @49f16e3)
- [x] [P1] Firewall: auto-enable pf with `pfctl -E`, falling back to `-e`; anchor `com.apple/safemaxxing` without a `table` definition so reloads never reset it @firewall #pf (done: 2026-10-22 @49f16e3)
- [x] [P1] Darwin pfctl quirks: stderr decoding, missing anchor/table replies, benign `-f` warning; unblock independent of setup @firewall #pf (done: 2026-10-22 @f655d9f, @74eafa3)
- [x] [P1] Log parsers for formats seen on macOS 27.0.1: TCCDProcess blocks, `<private>`/`<mask.hash>` tokens, locationd clients, Control Center sensor-indicator attributions @sensors #log (done: 2026-10-22 @bd884f9, @66596f3)
- [x] [P1] Non-blocking reverse DNS: dedicated thread pool, 100 ms timeout, prefetch only in the poll loop @network #dns (done: 2026-10-22 @49f16e3)
- [x] [P1] Doctor: foreign-socket check distinguishes system daemons and reports lsof failures; live DNS-budget test; `scripts/macos_validate.sh` @cli #doctor (done: 2026-10-22 @ab5aaaa)
- [x] [P1] Create TODO.md and TESTLOG.md @process #tracking (done: 2026-10-22, this commit)
