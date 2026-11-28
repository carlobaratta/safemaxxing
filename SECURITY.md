# Security policy

safemaxxing runs as root, loads rules into pf and sends `SIGSTOP` / `SIGKILL` to other
processes. A bug here can cut a Mac off the network or stop the wrong process, so please report
problems privately first.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on
<https://github.com/carlobaratta/safemaxxing/security/advisories/new>.
Please do not open a public issue for a security problem.

Include the macOS version (`sw_vers`), the architecture, the version (`safemaxxing version`)
or commit (`git rev-parse --short HEAD`), how it was installed (source, `.pkg`, Homebrew), the
output of `sudo uv run safemaxxing doctor`, and the steps to reproduce. Strip
anything personal from logs: raw `log stream` captures contain app activity and paths.

## Supported versions

safemaxxing is alpha (0.2.x). Only the latest commit on `main` receives fixes.
Validation so far has been on macOS 27.0.1, Apple Silicon (see [TESTLOG.md](TESTLOG.md)).

## Threat model

safemaxxing is a user-space privacy supervisor, not a kernel security product. It assumes a
sound kernel and a trusted root, and it reasons only about what macOS already reports.

What it defends against:

- a local app or malware that uses a sensor and then exfiltrates over a *new* socket or an
  unconnected UDP flow — it surfaces the sensor → egress correlation and lets you block the
  destination (pf) or stop the process (SIGSTOP / SIGKILL);
- after the fact, keeping a record of which process reached which address, and which sensor
  access preceded it;
- with Paranoia Mode on, an app that is not in use (no sensor, not frontmost, no manual lease)
  reaching the network at all, and a leased app whose running code fails verification
  (`csops`, entitlements, the Team ID pinned for it).

Explicit non-goals (out of scope by design):

- a kernel rootkit, a compromised kernel, or anything that subverts the unified log, the socket
  table or pktap themselves — safemaxxing trusts those sources;
- a compromise of pf itself, or another root process rewriting the anchor or the block table;
- a malicious or already-compromised root user: safemaxxing runs as root and offers no defence
  against code that is already root;
- physical access, firmware, or the Secure Enclave;
- exfiltration that reuses an already-open socket, is relayed by a system daemon, or completes
  inside one poll interval (see the README's known limits; `--throughput` and `--tcp-flows`
  narrow the first and the last);
- in Paranoia Mode, a process riding a destination granted to another app for its first
  packets (grants are per destination, so the piggyback audit stops it after the fact), and
  anything that happens after the watchdog restores the normal rules (the mode is fail-open).

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
- `--auto-block` / `--auto-suspend`, or the menu bar's Auto-Block / Auto-Suspend, acting on a
  process or IP other than the one in the alert, or more than once per alert;
- the menu bar showing idle (○) while nothing is being monitored;
- `permissions` or `doctor` writing to a TCC database, or reporting a clean result when a
  database was not read;
- a release binary or `.pkg` that a non-root process can modify, or inject code into, before
  it runs as root;
- crashes or hangs triggered by crafted log lines, socket tables or a running app's
  `Info.plist`;
- an app hiding its sensor use from correlation by claiming another app's bundle id;
- in Paranoia Mode, an unprivileged app getting traffic out without a lease, getting a grant
  without passing code verification, or turning the mode off (other than by its documented
  fail-open path being triggered by safemaxxing itself failing);
- `flush` disabling pf for other holders (it must only release safemaxxing's own reference).

Not a vulnerability (these are documented limits, see "Limiti noti" in the README):

- exfiltration that reuses an already-open socket, goes through a system daemon, or lasts less
  than one poll interval;
- redacted (`<private>`) log fields that hide the actor;
- reverse DNS showing only an IP.

## What safemaxxing changes on the system

| Change | When | How to undo |
|--------|------|-------------|
| Rule `block drop out quick from any to <safemaxxing_block>` loaded in anchor `com.apple/safemaxxing` | first block (`block`, TUI `b`, menu bar Block IP, `--auto-block`, Auto-Block Mode, live suite) | stays until reboot, or `sudo pfctl -a com.apple/safemaxxing -F rules` |
| Blocked IPs saved to `/Library/Application Support/safemaxxing/blocklist` (root, 0644) | every successful `block`, `unblock`, `flush` and `boot install` | `flush` empties it; delete the directory |
| launchd job `/Library/LaunchDaemons/io.github.carlobaratta.safemaxxing.restore.plist` (`Umask 077`), log `/var/log/safemaxxing-boot.log` (root, 0600) | `boot install` | `sudo safemaxxing boot uninstall`; delete the log |
| launchd daemon `/Library/LaunchDaemons/io.github.carlobaratta.safemaxxing.watch.plist` (`Umask 077`) running `watch --json` as root, logs `/var/log/safemaxxing-watch.log` and `.err` (root, 0600) | `daemon install` | `sudo safemaxxing daemon uninstall`; delete the logs |
| IPs in table `safemaxxing_block` | every block | `unblock <ip>`, or `flush` to empty the table |
| Existing pf states to the blocked IP killed (`pfctl -k`) | every block | none; apps must reconnect |
| pf reference taken (`pfctl -E`), token saved to `/Library/Application Support/safemaxxing/pf-reference` (root, 0600) | first block, Paranoia Mode, boot job | `flush` releases it (`pfctl -X`); pf stops only if nobody else holds it |
| `pf-reference.lock` next to it (an empty `flock` file) | every block and flush | delete it while no safemaxxing runs |
| launchd watchdog `/Library/LaunchDaemons/io.github.carlobaratta.safemaxxing.watchdog.plist` (`Umask 077`), log `/var/log/safemaxxing-watchdog.log` (root, 0600), idle unless `/var/run/safemaxxing/lockdown` exists | `paranoia install` | `sudo safemaxxing paranoia uninstall`; delete the log |
| Paranoia Mode ruleset in the anchor (default-deny, `grants` sub-anchor, tables `safemaxxing_dns`, `_ntp`, `_apple`, `_user`), DNS sinkhole on :53, `/var/run/safemaxxing/{lockdown,heartbeat,owner.lock}`, descriptor soft limit raised to 4096 | TUI `P` | `P` again, or the watchdog after 5 missed beats; a reboot clears it all |
| Team IDs pinned on first grant, `/Library/Application Support/safemaxxing/pins.json` | Paranoia Mode grants | delete the file |
| DNS blocklist `/Library/Application Support/safemaxxing/dns-blocklist.txt` | `paranoia blocklist` | delete the file |
| Process stopped (`SIGSTOP`) | `freeze`, TUI `s`, menu bar Freeze process, `--auto-suspend`, Auto-Suspend Mode, Paranoia Mode piggyback or failed re-verification | `thaw <pid>` / TUI `r` |
| Process killed (`SIGKILL`) | `kill`, TUI `k` (with confirmation) | none |
| Raw unified-log file written, mode 0600, owned by you even under sudo, never through a symlink | `sample --out PATH` | delete the file |
| Report file written, mode 0600, owned by you even under sudo, never through a symlink | `report --out PATH` | delete the file |
| `testlogs/` files written, `.pytest_cache` chowned to you | `scripts/macos_validate.sh` | delete the files |
| Bundle in `/usr/local/libexec/safemaxxing` (root-owned), link `/usr/local/bin/safemaxxing` | installing the `.pkg` | `sudo rm -rf /usr/local/libexec/safemaxxing /usr/local/bin/safemaxxing`, then `sudo pkgutil --forget com.github.carlobaratta.safemaxxing` |

`sudo safemaxxing purge` undoes what persists: it unloads and deletes the three launchd jobs,
empties safemaxxing's pf tables and anchor, releases its pf reference, and deletes the state,
run and log files safemaxxing created (anything else in its directories is reported and kept).
It does not resume paused processes, restore killed ones, touch `testlogs/`, or remove the
`.pkg` install, whose removal it prints. `--dry-run` lists what it would remove. It refuses while
Paranoia Mode is on or another `tui`, `watch` or `menubar` runs. [PRIVACY.md](PRIVACY.md) lists
what each file holds.

`permissions` and `doctor` only read the TCC databases, never write them. The menu bar
changes nothing beyond the actions in the table.

`/etc/pf.conf` is never modified. Without `boot install`, blocks do not survive a reboot:
after a restart pf is back to its boot state and the table is gone. With it, a root launchd job
reapplies the saved list at boot and enables pf (`pfctl -E`) when the list is not empty.

The boot job runs `/bin/sh`, `/sbin/pfctl` and base system tools (`grep`, `sleep`, `rm`,
`mv`) only. It never runs safemaxxing itself, which usually lives in a user-writable virtualenv: a root job pointing there would let any process
running as that user execute code as root. The only input the job reads is the root-owned list.

The `watch` daemon is different: it has to run safemaxxing itself as root. `daemon install`
therefore refuses unless it runs from the frozen binary, and every file of that bundle and
every directory above it is owned by root and not writable by group or others, with no symlink
leading out of the bundle. In practice that is only the `.pkg` install under
`/usr/local/libexec/safemaxxing`. The plist names the resolved bundle path, not the
`/usr/local/bin` link. A source checkout, virtualenv or Homebrew install is refused. The check
runs at install time; a later change to those files needs root anyway.

`--auto-block` and `--auto-suspend` act on a heuristic (a sensor event followed by egress in
the correlation window). Try them on a test machine before relying on them.

## pf: enabling, the reference token and `flush`

pf on macOS is reference-counted. `pfctl -E` enables it *and* takes a reference, returning a
token; `pfctl -X <token>` drops that one reference, and pf stops only when no holder is left.
`pfctl -d` is different: it stops pf for everyone and invalidates every token. safemaxxing
**never runs `pfctl -d`**.

safemaxxing holds one reference of its own, saved in
`/Library/Application Support/safemaxxing/pf-reference` (root, 0600) by the CLI, the TUI, the
daemon and the boot job:

- the first block takes it with `pfctl -E`, even when pf is already on, so a VPN or Internet
  Sharing releasing *its* reference cannot turn pf off under the block table; Paranoia Mode
  takes it before loading its default-deny ruleset, which pf would not enforce while off;
- `flush` empties the table, then releases the reference with `pfctl -X` only if the table is
  empty and the anchor holds just the block rule (not Paranoia Mode's ruleset). pf stops only
  if nobody else holds it; otherwise it stays on for its other holders;
- a token is valid only for one run of pf: a reboot or anyone's `pfctl -d` ends it, and the
  kernel can later give the same value to another program. So the record also keeps when pf's
  run began (from `pfctl -s info`'s "Enabled for ..."), and a token from an earlier run is
  forgotten, never released. A record that is not a root-owned, private regular file is
  ignored. A restart within 5 s of the moment the record was taken cannot be detected;
- a block and a flush in two processes cannot interleave: both hold an `flock` on
  `pf-reference.lock`, and every block checks again that pf is on, so a long-running TUI or
  daemon re-enables pf after a flush elsewhere;
- the boot job deletes a record from before the reboot and takes a fresh reference. A record
  written since `kern.boottime` while pf is on is kept, with no second `pfctl -E`: that is
  `boot install` loading the job on a live system, and `install` takes the reference first,
  under the lock, so the job finds it instead of leaking it;
- with the `pfctl -e` fallback there is no token, so nothing is released and pf stays on, as
  before. If the reference cannot be saved, the block still succeeds and says so.

`flush` leaves the anchor rule loaded: `block drop out quick ... to <safemaxxing_block>` over an
empty table matches nothing, so it is inert until the next block. `/etc/pf.conf` is never
touched; rules live only in the `com.apple/safemaxxing` sub-anchor, which the stock ruleset
already evaluates through `anchor "com.apple/*"`.

## Running as root, pktap and SIGSTOP

**Root.** Reading other users' sockets, driving pfctl and signalling foreign processes all need
root, so safemaxxing runs under `sudo`. Every parser therefore runs as root over untrusted
input — crafted log lines, socket tables, a running app's `Info.plist` — so those paths read
bounded amounts, never evaluate their input, and treat each field as hostile. Run it from a
root-owned location: a root process launched from a user-writable virtualenv would let any code
running as that user execute as root (the boot job and the watchdog avoid this by running only
`/bin/sh`, `/sbin/pfctl` and base system tools, never safemaxxing itself).

| Install | Owner of the code | Run as root? |
| --- | --- | --- |
| Source checkout, `sudo uv run …` | your user | development and testing on your own Mac only |
| `.pkg` from a release | root (`/usr/local/libexec/safemaxxing`) | yes: the intended way |
| Homebrew formula | your user (Homebrew prefix) | no: it has no `service` block, and `sudo` on it is the same risk as a virtualenv |

`daemon install` enforces the second row: it only installs from a root-owned bundle.

The release binary keeps library validation and DYLD variables enforced under the hardened
runtime (no `disable-library-validation`, no `allow-dyld-environment-variables`), so another
process cannot load its own dylib into it and borrow its root or its Full Disk Access grant.

**pktap.** `tcpdump -k` on a pktap interface is a system-wide packet capture: it exposes
per-packet process metadata for every process, not only the one under suspicion. It is
read-only — safemaxxing observes, it never injects — but it is privileged visibility, so the
capture is scoped to outbound packets and the data never leaves the machine.

**SIGSTOP on GUI processes.** `SIGSTOP` cannot be caught or ignored, which is what makes it a
reliable freeze — but stopping an AppKit process that holds a WindowServer resource can wedge
its windows or briefly stall the UI until `SIGCONT` (TUI `r` / `thaw`). `SIGKILL` on a stopped
GUI app can leave orphaned windows that clear on relaunch. Prefer freeze-then-inspect over kill,
and rehearse the automatic responses on a spare machine first.

## Hardening

What keeps a bug, a hostile local user or a malformed input from turning root into a weapon:

- **No shell.** Every external program (`pfctl`, `launchctl`, `tcpdump`, `log`, `codesign`,
  `lsof`, `pbcopy`, `osascript`) runs from an argument list by absolute path, never through a
  shell. The one shell command is the menu bar's "Open dashboard": a `shlex`-quoted line handed
  to Terminal as an AppleScript argument (not spliced into the script), which names the binary
  and `/usr/bin/sudo` by absolute path, so a `sudo` planted earlier on the user's `PATH` never
  sees the password.
- **pf stays in its anchor.** `run_command` refuses any `pfctl` call unless it reads pf's state,
  takes or releases a reference (`-E`, `-X <token>`), kills the states between two validated
  addresses (`-k A -k B`), or is scoped with `-a` to `com.apple/safemaxxing` or one of its sub-anchors.
  `pfctl -d` is refused outright. A ruleset is checked with `pfctl -n` before it is loaded, and
  anchors are replaced as a whole, so a syntax error leaves the previous rules in place.
- **Validated input.** An IP address is parsed with `ipaddress`; text longer than 64
  characters, a zone id (`%`), loopback, unspecified, multicast, link-local and reserved
  addresses are refused, and an IPv4-mapped IPv6 address becomes the IPv4 address. The saved
  block list is read back the same way, line by line, and the boot script refuses a list with a
  line that is not an address or a file not owned by root or writable by others.
- **State files.** Written atomically (`mkstemp` in the same directory, `fsync`, `rename`) with
  an explicit mode; read back with `O_NOFOLLOW`, size-capped, and only if root (or the current
  user) owns them and no one else can write them. A file that fails is ignored or refused, never
  trusted: a world-writable `pins.json` cannot swap a pinned Team ID, and a planted DNS
  blocklist is not loaded.
- **Logs and exports.** launchd jobs run with `Umask 077`; their logs are created or re-made
  0600 at install, refusing symlinks and hard links. `sample --out` and `report --out` create
  0600 files owned by the invoking user (`SUDO_UID`), never through a symlink or onto a hard
  link. The daemon logs alerts (app, pid, sensor, destination), not packet contents; there is no
  debug logging in the shipped program. `report --redact` replaces IP addresses, home paths,
  the login and the host name before a report is shared.
- **System processes.** `freeze` and `kill` ask before signalling a binary in a SIP-protected
  location (unless `--yes`), the TUI asks before pausing or killing one, and `--auto-suspend` /
  Auto-Suspend Mode never stop one.
- **Dependencies.** Four runtime libraries (Textual, Rich, Typer, psutil) plus rumps and PyObjC
  for the menu bar, all under MIT, BSD, ISC or PSF licenses
  ([docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md)); `tests/test_licenses.py`
  fails on a copyleft or unlicensed addition. The lock keeps Typer below 0.29, which would add
  pydantic's compiled core for nothing the CLI uses. Dependabot proposes updates.
