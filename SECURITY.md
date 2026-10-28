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

safemaxxing is alpha (0.1.x). Only the latest commit on `main` receives fixes.
Validation so far has been on macOS 27.0.1, Apple Silicon (see [TESTLOG.md](TESTLOG.md)).

## Threat model

safemaxxing is a user-space privacy supervisor, not a kernel security product. It assumes a
sound kernel and a trusted root, and it reasons only about what macOS already reports.

What it defends against:

- a local app or malware that uses a sensor and then exfiltrates over a *new* socket or an
  unconnected UDP flow — it surfaces the sensor → egress correlation and lets you block the
  destination (pf) or stop the process (SIGSTOP / SIGKILL);
- after the fact, keeping a record of which process reached which address, and which sensor
  access preceded it.

Explicit non-goals (out of scope by design):

- a kernel rootkit, a compromised kernel, or anything that subverts the unified log, the socket
  table or pktap themselves — safemaxxing trusts those sources;
- a compromise of pf itself, or another root process rewriting the anchor or the block table;
- a malicious or already-compromised root user: safemaxxing runs as root and offers no defence
  against code that is already root;
- physical access, firmware, or the Secure Enclave;
- exfiltration that reuses an already-open socket, is relayed by a system daemon, or completes
  inside one poll interval (see the README's known limits).

This is the line between a user-space / pf supervisor and a kernel extension or an Endpoint
Security Framework client: the latter sees every exec and socket from the kernel and can block
inline, at the cost of a system extension, special entitlements and far more privilege.
safemaxxing deliberately stays in user space and leans on pf.

## Scope

In scope:

- a non-root user or another process making safemaxxing run a command, change pf rules or
  signal a process it did not intend to;
- pf rules that block more than the listed IPs, or IPs that stay blocked after
  `safemaxxing flush`;
- `--auto-block` / `--auto-suspend` acting on a process or IP other than the one in the alert;
- crashes or hangs triggered by crafted log lines, socket tables or a running app's
  `Info.plist`;
- an app hiding its sensor use from correlation by claiming another app's bundle id.

Not a vulnerability (these are documented limits, see "Limiti noti" in the README):

- exfiltration that reuses an already-open socket, goes through a system daemon, or lasts less
  than one poll interval;
- redacted (`<private>`) log fields that hide the actor;
- reverse DNS showing only an IP.

## What safemaxxing changes on the system

| Change | When | How to undo |
|--------|------|-------------|
| Rule `block drop out quick from any to <safemaxxing_block>` loaded in anchor `com.apple/safemaxxing` | first block (`block`, TUI `b`, `--auto-block`, live suite) | stays until reboot, or `sudo pfctl -a com.apple/safemaxxing -F rules` |
| Blocked IPs saved to `/Library/Application Support/safemaxxing/blocklist` (root, 0644) | every successful `block`, `unblock`, `flush` and `boot install` | `flush` empties it; delete the directory |
| launchd job `/Library/LaunchDaemons/io.github.carlobaratta.safemaxxing.restore.plist`, log `/var/log/safemaxxing-boot.log` | `boot install` | `sudo safemaxxing boot uninstall`; delete the log |
| IPs in table `safemaxxing_block` | every block | `unblock <ip>`, or `flush` to empty the table |
| Existing pf states to the blocked IP killed (`pfctl -k`) | every block | none; apps must reconnect |
| pf enabled (`pfctl -E`) | first block, if pf was disabled | `sudo pfctl -d` |
| Process stopped (`SIGSTOP`) | `freeze`, TUI `s`, `--auto-suspend` | `thaw <pid>` / TUI `r` |
| Process killed (`SIGKILL`) | `kill`, TUI `k` (with confirmation) | none |
| Raw unified-log file written | `sample --out PATH` (root-owned under sudo) | delete the file |
| `testlogs/` files written, `.pytest_cache` chowned to you | `scripts/macos_validate.sh` | delete the files |

`/etc/pf.conf` is never modified. Without `boot install`, blocks do not survive a reboot:
after a restart pf is back to its boot state and the table is gone. With it, a root launchd job
reapplies the saved list at boot and enables pf (`pfctl -E`) when the list is not empty.

The boot job runs `/bin/sh` and `/sbin/pfctl` only. It never runs safemaxxing itself, which
usually lives in a user-writable virtualenv: a root job pointing there would let any process
running as that user execute code as root. The only input the job reads is the root-owned list.

`--auto-block` and `--auto-suspend` act on a heuristic (a sensor event followed by egress in
the correlation window). Try them on a test machine before relying on them.

## pf: enabling, the reference token and `flush`

pf on macOS is reference-counted. `pfctl -E` enables it *and* takes a reference, so pf is not
disabled while any holder — safemaxxing, Internet Sharing, a VPN — still holds one; `pfctl -e`
is the plain enable without a reference. safemaxxing enables pf with `pfctl -E` and falls back
to `-e`, and it **never releases its reference** (it does not run `pfctl -X <token>`): pf, and
the blocks loaded in the anchor, are meant to outlive the process. The cost is a small,
deliberate reference leak — pf stays enabled after safemaxxing exits, which is the safe
direction to err in.

`safemaxxing flush` empties the `safemaxxing_block` table (`pfctl -T flush`) and clears the
saved blocklist. It deliberately does **not** run `pfctl -d`: disabling pf is global and would
take the firewall down for every other user of it. It also leaves the anchor rule loaded — a
`block drop out quick ... to <safemaxxing_block>` rule over an empty table matches nothing, so
it is inert until the next block and removing it is neither necessary nor worth risking the
ruleset. `/etc/pf.conf` is never touched; rules live only in the `com.apple/safemaxxing`
sub-anchor, which the stock ruleset already evaluates through `anchor "com.apple/*"`.

## Running as root, pktap and SIGSTOP

**Root.** Reading other users' sockets, driving pfctl and signalling foreign processes all need
root, so safemaxxing runs under `sudo`. Every parser therefore runs as root over untrusted
input — crafted log lines, socket tables, a running app's `Info.plist` — so those paths read
bounded amounts, never evaluate their input, and treat each field as hostile. Run it from a
root-owned location: a root process launched from a user-writable virtualenv would let any code
running as that user execute as root (the boot job avoids this by running only `/bin/sh` and
`/sbin/pfctl`, never safemaxxing itself).

**pktap.** `tcpdump -k` on a pktap interface is a system-wide packet capture: it exposes
per-packet process metadata for every process, not only the one under suspicion. It is
read-only — safemaxxing observes, it never injects — but it is privileged visibility, so the
capture is scoped to outbound packets and the data never leaves the machine.

**SIGSTOP on GUI processes.** `SIGSTOP` cannot be caught or ignored, which is what makes it a
reliable freeze — but stopping an AppKit process that holds a WindowServer resource can wedge
its windows or briefly stall the UI until `SIGCONT` (TUI `r` / `thaw`). `SIGKILL` on a stopped
GUI app can leave orphaned windows that clear on relaunch. Prefer freeze-then-inspect over kill,
and rehearse the automatic responses on a spare machine first.
