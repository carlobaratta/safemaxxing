# Privacy

safemaxxing watches which apps use the camera, microphone, location or screen and where they
connect right after. That is sensitive information about you and about the apps on your Mac.
This page says what safemaxxing reads, what it keeps, what it sends, and how to remove it all.

## In short

- **Everything is processed locally, on this Mac.** Sensor events, connections, packet
  metadata and alerts never leave it.
- **No telemetry.** No analytics, crash reporting, usage statistics or update checks. There is
  no account, no server and no third-party SDK. The runtime dependencies (Textual, Rich, Typer,
  psutil; rumps and PyObjC for the menu bar) are local libraries that make no network calls of
  their own.
- **safemaxxing never turns on a sensor.** It does not open the camera, microphone, location
  service or screen capture. It reads the unified log entries macOS writes when another app
  does.
- **Nothing is written to disk unless you ask.** The TUI, the menu bar and `watch` keep
  everything in memory and forget it when they quit. Files exist only for features you turn on
  (blocks that survive a reboot, the background daemon, Paranoia Mode) or exports you request.
- **`sudo safemaxxing purge` removes everything** safemaxxing put on the Mac (see below).

## What it reads

| Source | What is read | Where it goes |
|--------|--------------|---------------|
| Unified log (`log stream`) | Entries from TCC, Control Center's sensor indicator, CoreAudio, CoreMediaIO and locationd: process name, pid, bundle id, the sensor, the TCC service | Memory: the correlation window (2 s by default), the last 1000 alerts and 2000 log lines in the TUI |
| Socket table (psutil, `lsof`) | Each outbound socket's pid, protocol, local and remote address and port | Memory |
| pktap (`tcpdump -k -q`, only with `--udp-flows`, `--tcp-flows` or `--throughput`; root) | One summary line per packet: interface metadata, addresses, ports, length. Payloads are not printed or read | Memory |
| Paranoia Mode SNI audit (root) | The first 1600 bytes of outbound TLS ClientHello packets, to read the server name | Memory; the name, not the packet, can appear in an alert |
| Paranoia Mode pflog (root) | The first 128 bytes (headers) of packets the default-deny dropped | Memory |
| TCC databases (`permissions`, `doctor`) | Which apps hold camera, microphone, screen, input-monitoring, accessibility and Full Disk Access grants. Read-only, never written | Printed in your terminal |
| Code signatures (`codesign`, `csops`) | Signing identity and Team ID of the app behind a connection | Memory; the Team ID is saved only when Paranoia Mode pins it |

## What it sends over the network

1. **Reverse DNS, through your system resolver.** To show a host name next to an address,
   safemaxxing asks macOS (`getnameinfo`), which sends a PTR query to the DNS server you
   already use. `--no-dns` turns this off.
2. **Paranoia Mode's DNS sinkhole** answers blocked names locally and forwards the other
   queries to the resolvers macOS was already using, as macOS itself would have done.
3. **`safemaxxing paranoia blocklist`** downloads a hosts or Adblock Plus list, over HTTPS
   only, from the URL you pass (by default Steven Black's hosts file on GitHub). It runs only
   when you type that command.

Nothing else. The help screen and the report print the project's issue-tracker address, but
safemaxxing never opens it or sends anything to it.

## What it stores, and where

Only features you install or turn on write files. Every file below is root-owned, and every
log is readable by root only (0600).

| Path | What it holds | Mode | Written by |
|------|---------------|------|------------|
| `/Library/Application Support/safemaxxing/blocklist` | The IP addresses you blocked | 0644 | `block`, `unblock`, `flush`, `boot install` |
| `/Library/Application Support/safemaxxing/pf-reference` (+ `.lock`) | safemaxxing's pf reference token | 0600 | the first block, Paranoia Mode, the boot job |
| `/Library/Application Support/safemaxxing/pins.json` | Bundle id → Team ID pinned at a first verified grant | 0644 | Paranoia Mode |
| `/Library/Application Support/safemaxxing/dns-blocklist.txt` | The downloaded DNS blocklist | 0644 | `paranoia blocklist` |
| `/var/log/safemaxxing-watch.log`, `.err` | Alerts as JSON lines: app, pid, sensor, destination address and host name | 0600 | the `watch` daemon (`daemon install`) |
| `/var/log/safemaxxing-boot.log` | What the boot job restored | 0600 | the boot job (`boot install`) |
| `/var/log/safemaxxing-watchdog.log` | When the watchdog restored pf | 0600 | the watchdog (`paranoia install`) |
| `/var/run/safemaxxing/` | Paranoia Mode's heartbeat, armed flag and lock (cleared at reboot) | 0644 | Paranoia Mode |
| `/Library/LaunchDaemons/io.github.carlobaratta.safemaxxing.*.plist` | The launchd jobs; each runs with `Umask 077` | 0644 | `boot`, `daemon`, `paranoia install` |

Every state file is written atomically, never through a symlink, and read back only if root
(or you) owns it and no one else can write it.

**Exports you ask for** are created mode 0600, owned by you even under `sudo`, and never
through a symlink:

- `safemaxxing sample --out FILE`: raw unified-log entries. They name apps, paths and
  sometimes personal data: do not publish them.
- `safemaxxing report --out FILE`: the current protection state (pf, blocks, jobs, checks,
  recent alerts). For a public bug report use `--redact`, which replaces every IP address,
  home path, your login and the host name.

## Removing everything

```bash
sudo safemaxxing purge --dry-run
```

lists what would go; `sudo safemaxxing purge` asks once, then removes the launchd jobs, empties
and unloads safemaxxing's pf tables and rules, releases its pf reference (never `pfctl -d`),
and deletes the files in the table above. Files it did not create are reported and kept. It
refuses while Paranoia Mode is on or another `tui`, `watch` or `menubar` is running. The
program itself stays: the command prints how to remove the `.pkg` install too.

## Before you use it: what it can break

safemaxxing runs as root and changes the packet filter. Read [SECURITY.md](SECURITY.md) first.

- **pf.** safemaxxing loads rules only in its own anchor, `com.apple/safemaxxing`; it never
  edits `/etc/pf.conf` or the system's rules. Every `pfctl` call the program makes is checked
  against that scope before it runs, and the boot job's fixed script touches only the anchor's
  block table. A block still cuts every connection to that address, for every app,
  until you unblock it or the Mac reboots (or longer, with `boot install`).
- **Paranoia Mode is default-deny.** While it is on, an app reaches the network only while it
  uses a sensor or after you grant it (`g`). Calls, syncing, updates and VPNs can stop working;
  the `max` profile is stricter still and asks before it starts. A watchdog restores the normal
  rules if safemaxxing stops; a reboot clears everything.
- **Pausing or killing a process** can lose its unsaved work. Stopping a macOS system process
  (WindowServer, loginwindow, coreaudiod) can freeze the desktop or log you out, so the TUI and
  the CLI ask first, and automatic responses never stop one.
- **Alerts are a heuristic**: a sensor event followed by a connection within a time window. A
  benign app can match; a careful one can avoid matching. It is a supervisor, not a guarantee.
- **Use it on Macs you own or administer.** Recording which apps another person uses and where
  they connect can require their consent under the law where you are (in the EU, the GDPR and
  ePrivacy rules).

## The project website

`site/index.html` loads its two typefaces (Host Grotesk and JetBrains Mono, both under the SIL
Open Font License) from Google Fonts, so opening the page sends your IP address to Google. The
dashboard and the CLI load no fonts and contact no one; they use your terminal's font. To serve
the site without that request, download the two families and host them next to the page.

## Questions

Open an issue (without personal data) or, for anything security-sensitive, follow
[SECURITY.md](SECURITY.md#reporting-a-vulnerability).
