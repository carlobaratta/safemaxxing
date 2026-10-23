# Security policy

safemaxxing runs as root, loads rules into pf and sends `SIGSTOP` / `SIGKILL` to other
processes. A bug here can cut a Mac off the network or stop the wrong process, so please report
problems privately first.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on
<https://github.com/carlobaratta/safemaxxing/security/advisories/new>.
Please do not open a public issue for a security problem.

Include the macOS version (`sw_vers`), the architecture, the commit (`git rev-parse --short
HEAD`), the output of `sudo uv run safemaxxing doctor`, and the steps to reproduce. Strip
anything personal from logs: raw `log stream` captures contain app activity and paths.

## Supported versions

safemaxxing is alpha (0.1.x). Only the latest commit on the development branch
(`claude/gifted-pascal-tp5iot`, until a `main` branch replaces it) receives fixes.
Validation so far has been on macOS 27.0.1, Apple Silicon (see [TESTLOG.md](TESTLOG.md)).

## Scope

In scope:

- a non-root user or another process making safemaxxing run a command, change pf rules or
  signal a process it did not intend to;
- pf rules that block more than the listed IPs, or IPs that stay blocked after
  `safemaxxing flush`;
- `--auto-block` / `--auto-suspend` acting on a process or IP other than the one in the alert;
- crashes or hangs triggered by crafted log lines or socket tables.

Not a vulnerability (these are documented limits, see "Limiti noti" in the README):

- exfiltration that reuses an already-open socket, goes through a system daemon, or lasts less
  than one poll interval;
- redacted (`<private>`) log fields that hide the actor;
- reverse DNS showing only an IP.

## What safemaxxing changes on the system

| Change | When | How to undo |
|--------|------|-------------|
| Rule `block drop out quick from any to <safemaxxing_block>` loaded in anchor `com.apple/safemaxxing` | first block (`block`, TUI `b`, `--auto-block`, live suite) | stays until reboot, or `sudo pfctl -a com.apple/safemaxxing -F rules` |
| IPs in table `safemaxxing_block` | every block | `unblock <ip>`, or `flush` to empty the table |
| Existing pf states to the blocked IP killed (`pfctl -k`) | every block | none; apps must reconnect |
| pf enabled (`pfctl -E`) | first block, if pf was disabled | `sudo pfctl -d` |
| Process stopped (`SIGSTOP`) | `freeze`, TUI `s`, `--auto-suspend` | `thaw <pid>` / TUI `r` |
| Process killed (`SIGKILL`) | `kill`, TUI `k` (with confirmation) | none |
| Raw unified-log file written | `sample --out PATH` (root-owned under sudo) | delete the file |
| `testlogs/` files written, `.pytest_cache` chowned to you | `scripts/macos_validate.sh` | delete the files |

`/etc/pf.conf` is never modified. Blocks do not survive a reboot: after a restart pf is back to
its boot state and the table is gone.

`--auto-block` and `--auto-suspend` act on a heuristic (a sensor event followed by egress in
the correlation window). Try them on a test machine before relying on them.
