# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). No release has been tagged yet; everything so far
is the first development line of 0.1.0.

## [Unreleased]

### Added

- Sensor-to-egress correlation supervisor. It reads `log stream` for TCC, locationd,
  coreaudio and cmio. It also polls the socket table through psutil or lsof. Each alert pairs
  a sensor event with an outbound connection in the window. (6aca95d)
- Textual TUI, headless `watch` with JSON lines, `--auto-block` and `--auto-suspend`. (6aca95d)
- pf egress blocking in the anchor `com.apple/safemaxxing` (table `safemaxxing_block`).
  Process control through `SIGSTOP`, `SIGCONT` and `SIGKILL`. (6aca95d)
- `doctor`: checks root, pf status, the parent anchor, our anchor, foreign sockets, Full Disk
  Access, snapshot latency and the log predicate. (49f16e3, ab5aaaa)
- `sample`: a per-subsystem redaction and parsing report. It also shows `--wide` sensor
  discovery and the Control Center indicator timeline. (49f16e3, 74eafa3, 51ae4bc, 65305d6)
- The Control Center sensor indicator (`cam:`, `mic:`, `loc:`) is now the main attribution
  source. (bd884f9) All four indicators (`cam`, `mic`, `loc`, `scr`) have now been seen on
  macOS 27.0.1. The first real `mic:` and `scr:` sequences are pinned as fixtures.
  (c19cc1b, ec1c8ee)
- Live test suite for macOS (`pytest -m live`) and `scripts/macos_validate.sh`.
  (49f16e3, ab5aaaa)

- Blocks can survive a reboot. `block`, `unblock` and `flush` save each successful change to
  `/Library/Application Support/safemaxxing/blocklist`. `boot install` loads a launchd job
  that reapplies the list at boot with `/bin/sh` and `/sbin/pfctl` only. `boot status` and
  `boot uninstall` show and remove it. (2e55bba)

### Changed

- Docstrings on every public class and function, except in `sensors.py`. `--help` now
  documents the `block`/`unblock` and `freeze`/`thaw`/`kill` arguments, `sample --seconds`
  and the `--min-severity` values.
- CI uses `actions/checkout@v7` and `astral-sh/setup-uv@v7`.
- The version is read from `src/safemaxxing/__init__.py` only. A CI `build` job checks that
  the wheel metadata carries it and that the entry point runs.
- The default correlation window is now 2 s (it was 0.5 s). Each connection raises at most one
  alert. Events that carry only a pid are named through psutil. (61a6547)
- Events and sockets from system binaries are hidden unless `--include-system`. DNS egress
  (ports 53, 853 and 5353) is skipped unless `--include-dns`. (071bdce, 66596f3)
- Reverse DNS runs in the background on its own thread pool. The poll loop only prefetches
  and reads the cache, so it never waits for a lookup. (49f16e3)
- A screen capture counts only when the capturing process logs its own request. (09c2673)
- Control Center indicator events of Apple apps are hidden unless `--include-system`. This
  happens only when every running process that may carry the bundle id runs from a SIP path.
  They are still correlated, so another app claiming that bundle id still raises an alert.
  (eb9c13b)

### Fixed

- Any running app's Info.plist is read as untrusted input. A malformed one no longer
  crashes the sensor stream, and a FIFO no longer blocks it. (eb9c13b)
- Darwin `pfctl` quirks: stderr decoding, missing anchor or table replies, the harmless
  ALTQ notices (49f16e3), and the `-f` flushing warning (f655d9f). (9ef0b91, 74eafa3)
- pf cold start: `pfctl -E`, then `-e`, checked with `-s info`. (49f16e3)
- Broker attribution. `tccd`, `coreaudiod`, `sandboxd` and `calaccessd`, and TCC-manager self
  checks, no longer count as the accessing app. (bd884f9, 66596f3, 65305d6, 1cbeb54, d9ca8c8)
- Without root, `doctor` now reports the pf checks and the socket snapshot as "needs root".
  It no longer reports a missing anchor. (bc5a019, 4d97f18)
- Severity markup (`[high]`) was swallowed in the text output of `watch`. (071bdce)
