# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `safemaxxing.pktap`, the first part of a pktap egress source for UDP sockets that are never
  `connect()`ed. These sockets have no remote address in the socket table, as with Meet's
  media in Brave. The module has `PktapEvent` and `Direction` in `models.py`, a parser for
  `tcpdump -k -n -q -tt` lines, and `PktapFlowTracker`. The tracker turns the first
  outbound packet of each flow into a `NetworkConnection` with status `PKTAP`. It drops
  link-local, multicast and broadcast destinations, and SIP binaries unless
  `include_system`. `PktapCapture` runs tcpdump and always stops and reaps it. The source is
  not wired into `Supervisor` or the CLI yet. The capture runs in `--immediate-mode` and
  leaves out DNS ports. During a Meet call it costs about 0.5% of one core. (298328d)
- `--udp-flows` for `tui` and `watch` (root only) runs the pktap capture next to the socket
  table, as a second connection source in `Supervisor`.
  - Flows that are already open at start-up are tracked but are not new.
  - tcpdump is restarted up to 5 times in a row, with a doubling backoff.
  - pktap flows appear in the TUI's connections table with state `PKTAP`.
  - `doctor` gains a `pktap capture (--udp-flows)` check: it WARNs, never FAILs. (d56aeef)

## [0.1.1] - 2026-10-26

Parser fixes from the Meet-in-Brave runs of 2026-10-26, checked by replaying every raw sample
in `testlogs/` before and after each fix: see TESTLOG.md.

### Fixed

- ScreenCaptureKit screen sharing is attributed to the app that captures, not to `replayd`.
  The pid comes from the subject audit token in tccd's `REQUEST_MSG`. Before this fix, a
  window shared from Meet in Brave was attributed to `replayd`. It was then hidden as a
  system event, and only the `scr:` indicator named Brave. `replayd` now counts as a broker,
  so its own SEND lines and its mic preflights are no longer events. Its own non-sensor TCC
  checks are not reported either, which is the rule for other brokers. (ff1c9f7)
- coreaudiod's TCC *preflights* (`preflight=true`) are no longer microphone or other TCC
  events. Only tccd's `REQUEST_MSG` carries the flag, so the parser links every line of the
  request through its `activityIdentifier` and drops them all. This removes the mic events
  for `screencapture` (Cmd+Shift+5) and for Brave, which had no `mic:` indicator.
  coreaudiod's real requests, such as a Voice Memos recording, still count. (1eb829f)
- A Control Center attribution that comes back within 2 s of going off is now one use, not a
  new event. Before, a Cmd+Shift+5 recording gave 2 `scr:` events, and a Brave window share
  gave one per second. cmio's `CMIODeviceStartStream backtrace N` lines no longer count as
  camera starts: Brave's single start gave 52 events, now 1. (7c7260c)

## [0.1.0] - 2026-10-24

First tagged release (alpha). Validated on macOS 27.0.1, Apple Silicon: see TESTLOG.md.

### Added

- Sensor-to-egress correlation supervisor. It reads `log stream` for TCC, locationd,
  coreaudio and cmio. It also polls the socket table through psutil or lsof. Each alert pairs
  a sensor event with an outbound connection in the window. (a5263bd)
- Textual TUI, headless `watch` with JSON lines, `--auto-block` and `--auto-suspend`. (a5263bd)
- pf egress blocking in the anchor `com.apple/safemaxxing` (table `safemaxxing_block`).
  Process control through `SIGSTOP`, `SIGCONT` and `SIGKILL`. (a5263bd)
- `doctor`: checks root, pf status, the parent anchor, our anchor, foreign sockets, Full Disk
  Access, snapshot latency and the log predicate. (9d90a90, 9421e63)
- `sample`: a per-subsystem redaction and parsing report. It also shows `--wide` sensor
  discovery and the Control Center indicator timeline. (9d90a90, 631b592, bb985e3, 70fbd74)
- The Control Center sensor indicator (`cam:`, `mic:`, `loc:`) is now the main attribution
  source. (a25e3fb) All four indicators (`cam`, `mic`, `loc`, `scr`) have now been seen on
  macOS 27.0.1. The first real `mic:` and `scr:` sequences are pinned as fixtures.
  (10ac350, df634b1)
- Live test suite for macOS (`pytest -m live`) and `scripts/macos_validate.sh`.
  (9d90a90, 9421e63)

- Blocks can survive a reboot. `block`, `unblock` and `flush` save each successful change to
  `/Library/Application Support/safemaxxing/blocklist`. `boot install` loads a launchd job
  that reapplies the list at boot with `/bin/sh` and `/sbin/pfctl` only. `boot status` and
  `boot uninstall` show and remove it. (9b0af93)

### Changed

- Docstrings on every public class and function, except in `sensors.py`. `--help` now
  documents the `block`/`unblock` and `freeze`/`thaw`/`kill` arguments, `sample --seconds`
  and the `--min-severity` values.
- CI uses `actions/checkout@v7` and `astral-sh/setup-uv@v7`.
- The version is read from `src/safemaxxing/__init__.py` only. A CI `build` job checks that
  the wheel metadata carries it and that the entry point runs.
- The default correlation window is now 2 s (it was 0.5 s). Each connection raises at most one
  alert. Events that carry only a pid are named through psutil. (b7f39ba)
- Events and sockets from system binaries are hidden unless `--include-system`. DNS egress
  (ports 53, 853 and 5353) is skipped unless `--include-dns`. (c6cdc44, 32c1b74)
- Reverse DNS runs in the background on its own thread pool. The poll loop only prefetches
  and reads the cache, so it never waits for a lookup. (9d90a90)
- A screen capture counts only when the capturing process logs its own request. (17ee6c8)
- Control Center indicator events of Apple apps are hidden unless `--include-system`. This
  happens only when every running process that may carry the bundle id runs from a SIP path.
  They are still correlated, so another app claiming that bundle id still raises an alert.
  (fca16c9)

### Fixed

- Any running app's Info.plist is read as untrusted input. A malformed one no longer
  crashes the sensor stream, and a FIFO no longer blocks it. (fca16c9)
- Darwin `pfctl` quirks: stderr decoding, missing anchor or table replies, the harmless
  ALTQ notices (9d90a90), and the `-f` flushing warning (d26885a). (70ff41d, 631b592)
- pf cold start: `pfctl -E`, then `-e`, checked with `-s info`. (9d90a90)
- Broker attribution. `tccd`, `coreaudiod`, `sandboxd` and `calaccessd`, and TCC-manager self
  checks, no longer count as the accessing app. (a25e3fb, 32c1b74, 70fbd74, e5a62bc, 9bd6f54)
- Without root, `doctor` now reports the pf checks and the socket snapshot as "needs root".
  It no longer reports a missing anchor. (34c9f53, fb802ee)
- Severity markup (`[high]`) was swallowed in the text output of `watch`. (c6cdc44)

[Unreleased]: https://github.com/carlobaratta/safemaxxing/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/carlobaratta/safemaxxing/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/carlobaratta/safemaxxing/releases/tag/v0.1.0
