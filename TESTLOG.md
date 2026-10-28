# TESTLOG

Newest session first. Each session: environment, goal, code changes, exact commands, raw results,
problems/regressions, next steps. Raw logs from `scripts/macos_validate.sh` go in `testlogs/`.

<!-- Template:
## [YYYY-MM-DD HH:MM +ZZZZ] - Session name / Target
- **Environment:** macOS Darwin, arch (Apple Silicon/Intel), OS version, UID/privileges
- **Goal:**
- **Code changes:**
- **Commands run:**
- **Result and raw data:**
- **Problems / regressions:**
- **Next steps:**
-->

## [2026-10-28 11:19 +0100] - Full Disk Access granted: `doctor` all green (Mac)

- **Environment:** macOS 27.0.1, arm64, hostname `MacBook-Air-di-Carlo-2`, root, `main` at
  2be213c.
- **Goal:** the FDA task in TODO **Next Up**: grant Full Disk Access to the terminal and see
  the check turn OK.
- **Code changes:** none.
- **Commands run:** `sudo uv run safemaxxing doctor`, before and after adding the terminal in
  System Settings → Privacy & Security → Full Disk Access and reopening it.
- **Result and raw data:**
  - Before: 12 OK, 1 WARN, `! Full Disk Access: not granted to this terminal (optional today;
    needed for TCC.db inspection)`. Root alone is not enough: the grant belongs to the
    terminal app.
  - After (verbatim): 13 OK, 0 WARN, 0 FAIL.
    ```text
    ✔ pf status: Enabled
    ✔ anchor com.apple/safemaxxing: block drop out quick from any to <safemaxxing_block>
    ✔ foreign sockets: 38 pids visible incl. daemons _mdnsresponder, _netbios
    ✔ Full Disk Access: system TCC.db readable
    ✔ socket snapshot: 10 ms per poll (interval 200 ms)
    ✔ log stream predicate: accepted
    ✔ pktap capture (--udp-flows): tcpdump capturing
    ```
  - pktap capture is also OK as root, so `--udp-flows` is ready on this Mac.
- **Problems / regressions:** none.
- **Next steps:** reading TCC.db for camera/mic grants (Backlog) is now possible here.

## [2026-10-28 11:05 +0100] - pktap leftovers: hostnames, directed broadcasts, system-extension bundle ids (Mac, offline)

- **Environment:** macOS 27.0.1, arm64 Apple M4, `main` at 6bd75f7 plus uncommitted
  changes, not root.
- **Goal:** the three pktap Backlog items found in the live runs of 2026-10-27/28.
- **Code changes:**
  - **Hostnames.** `PktapCapture(resolver=...)` prefetches each new flow's destination and
    names flows from the cache. `PktapCapture.active()` returns named flows, and
    `Supervisor.active_connections()` uses it. `Supervisor.default` gives the monitor and
    pktap one shared `HostnameResolver`.
  - **Directed broadcasts.** `interface_broadcasts()` lists each interface's IPv4 broadcast
    from `psutil.net_if_addrs()`. It takes 1.14 ms here and gave en0 `10.243.255.255`, a /16.
    `PktapFlowTracker` reads it per new flow, because the network can change under a running
    capture, and drops flows sent there.
  - **System extensions.** `bundle_id_for_exe` falls back to the innermost `.systemextension`
    when no `.app` encloses the binary. An enclosing `.app` still wins. This also gives the
    bundle id to pid-only sensor events from such binaries, through `_ProcessEnricher`.
    `possible_exes_for_bundle` is unchanged.
- **Commands run:** `uv run ruff check src tests`, `uv run mypy --strict`, `uv run pytest -q`.
- **Result:** `All checks passed!`, `Success: no issues found in 24 source files`,
  `227 passed, 7 skipped in 4.36s`. The hostname test passed 3 times in a row: the yielded
  connection is unnamed until the lookup lands in the cache, and named once it has.
- **Problems / regressions:** none. Not run live: the end-to-end alert of 2026-10-28 already
  covers the path the changes touch.
- **Next steps:** none for pktap. The `Next Up` items need the Mac and the user.

## [2026-10-28 11:01 +0100] - `--udp-flows` end to end: a Meet call in Brave raises a critical alert (Mac)

- **Environment:** macOS 27.0.1, arm64 Apple M4, root, `main` at 74b4c14 (code unchanged since
  d56aeef). Network 10.243.5.87, the one where the probe saw UDP.
- **Goal:** the end-to-end check in TODO **Now**.
- **Commands run:** while the script ran, the user left and rejoined a Meet call in Brave:
  ```sh
  sudo uv run python <scratchpad>/pktap_e2e.py | tee testlogs/pktap-e2e-2.txt
  ```
  The script uses `Supervisor.default(udp_flows=True)`, so the same sources and engine as
  `watch --udp-flows`, with timestamps. It was stopped with Control+C.
- **Result and raw data (verbatim, `testlogs/pktap-e2e-2.txt`):**
  ```text
  10:57:30.288 start (pktap flows in the first 2 s are muted)
  10:57:41.851 event microphone  com.brave.Browser pid=16296 (Microphone)
  10:57:45.809 event microphone  com.brave.Browser pid=16296 (Microphone)
  10:57:45.964 event camera      com.brave.Browser pid=19819 (Camera)
  10:57:45.997 conn  PKTAP       udp Brave Browser Helper pid=16112 74.125.250.248:3478 bundle=com.brave.Browser
  10:57:46.014 ALERT #1 [critical] com.brave.Browser used camera+microphone then connected to 74.125.250.248:3478 after 188 ms
  10:57:46.173 conn  PKTAP       udp Brave Browser Helper pid=16112 74.125.250.248:19305 bundle=com.brave.Browser
  ```
  - **The alert works end to end.** The first UDP packet left 188 ms after Brave's
    microphone event, from the NetworkService helper (16112). It matches Brave's audio
    (16296) and video (19819) helpers by bundle id. Two sensors precede the same flow, so
    the severity is `critical`. The alert was printed 17 ms after the packet's timestamp.
  - The STUN flow to :19305, 176 ms later, raised no second alert: the 30 s cooldown applies
    per pid, sensor and remote IP.
  - The socket table showed only Brave's DNS to 10.128.132.57:53, which is dropped as DNS.
    So without pktap, this call raises no alert.
  - **Stopping works.** After Control+C, no `tcpdump`, `python` or `sudo` process was left
    (`pgrep`). This holds under `sudo` with its pty and `uv` in between. The script's last
    `stop:` line is missing because `tee` had already exited on the same Control+C. Earlier,
    Command+C had done nothing: on macOS it copies text and sends no signal.
- **Code changes:** none.
- **Problems / regressions:** none.
- **Next steps:** none for this task. Open: the Backlog items for pktap hostnames, directed
  broadcasts and `.systemextension` bundle ids, and networks that block UDP.

## [2026-10-28 10:56 +0100] - `--udp-flows` live: no flow on another network, the probe shows UDP works here (Mac)

- **Environment:** macOS 27.0.1, arm64 Apple M4, root, `main` at 74b4c14. Two networks:
  - 2026-10-27 15:07: hostname `Host-001`, router 192.168.1.1;
  - 2026-10-28: hostname `MacBook-Air-di-Carlo-2`, local address 10.243.5.87.
- **Goal:** the end-to-end check in TODO **Now**, a Meet call in Brave raising an alert with
  `--udp-flows`.
- **Commands run:**
  - On `Host-001`, `sudo uv run safemaxxing watch --udp-flows --events`. Then a scratchpad
    script, `pktap_e2e.py`, built on the same `Supervisor.default(udp_flows=True)`, which
    prints events, every pktap flow, Brave's socket-table connections and alerts, all with
    timestamps, into `testlogs/pktap-e2e.txt`. The call was rejoined while it ran.
  - On 10.243.5.87, during a call, `pktap_probe.sh` ran two raw tcpdumps for 15 s:
    - A, the exact `pktap_command()`;
    - B, `-Q "dir=out and pid=16112"`, any protocol.
- **Result and raw data:**
  - **`Host-001`: no alert and no pktap flow at all.** Events came in (verbatim):
    ```text
    15:07:22.647 event microphone  com.brave.Browser pid=16296 (Microphone)
    15:07:26.331 event camera      com.brave.Browser pid=19819 (Camera)
    15:07:22.202 conn  NONE        udp Brave Browser Helper pid=16112 192.168.1.1:53 bundle=com.brave.Browser
    ```
    Brave's only connections were DNS to the router. tcpdump (pid 48018) was alive and never
    restarted: 0.41 s CPU in 2 min 18 s, about 0.3%, so it was receiving packets. It printed
    no non-DNS outbound UDP from a non-system process.
  - **10.243.5.87: the exact command prints the call.**
    ```text
    A (udp filter): 1561 lines   2644 received by filter, 0 dropped by kernel, 873 by metadata filter
    B (NetworkService, any protocol): 1540 lines
    1539 udp Brave Browser He:16112 74.125.250.248.3478     (A and B alike)
      21 udp nsurlsessiond:759 17.248.x.x:443                (A only)
    ```
    1560 of A's 1561 lines parse; the last one is the empty line printed at SIGINT. Replayed
    through `PktapFlowTracker`, A gives exactly one connection:
    `Brave Browser Helper 16112 74.125.250.248:3478 com.brave.Browser`.
    B has no TCP at all: on this network the media goes over UDP only.
- **Conclusion:** the command and the parser work on a live call. On `Host-001` Meet sent no
  UDP. The likely cause is UDP being blocked there, so the call fell back to TCP inside a
  connection that was already open; no probe was run on that network, so this is not
  proven. pktap cannot see such a call, and the socket table sees no new connection either.
- **Code changes:** none.
- **Next steps:** run `pktap_e2e.py` again on this network and rejoin a call, to see the alert
  and the delay between the sensor event and the first UDP packet.

## [2026-10-27 08:47 +0100] - pktap phase 2: `--udp-flows`, Supervisor, doctor (Mac, not root, offline)

- **Environment:** macOS 27.0.1, arm64 Apple M4, `main` at 8efa930 plus uncommitted
  changes. Run as the user, not as root. No Meet call was available.
- **Goal:** wire the pktap source into the tool. This follows the 2026-10-26 design: an
  always-on capture, restarts, a root check and a doctor check.
- **Code changes:**
  - `pktap.py`:
    - `PktapFlowTracker` gains `mute_until()` (flows first seen before it are tracked, not
      returned) and `active()` (connections of the flows with a packet in the last
      `idle_s`).
    - `PktapCapture.connections()` mutes flows first seen within `warmup_s` (2 s) of each
      run's first packet. It restarts tcpdump up to `max_restarts` (5) times in a row, with
      a backoff of 1 s doubled each time up to 30 s, then raises the last `PktapError`.
    - A spawn failure is now a `PktapError`.
    - New `pktap_unavailable()`: the binary is missing, or the user is not root.
  - `supervisor.py`:
    - `Supervisor(pktap=...)` pumps the pktap connections next to the socket table.
    - `active_connections()` adds pktap's active flows, and a key seen by both sources
      appears once, because the TUI keys its rows on it.
    - `Supervisor.default(udp_flows=True)` builds the capture from `include_system`,
      `include_dns` and `include_loopback`.
  - `cli.py`: `--udp-flows` on `tui` and `watch`. It exits 1 with the reason when
    `pktap_unavailable()` gives one.
  - `diagnostics.py`: `check_pktap`. It WARNs without root. As root it runs
    `pktap_command()` for 2 s: still running means OK, otherwise it WARNs with the last
    stderr line.
  - README: the feature, the option table, doctor, the architecture and the known limits.
- **Commands run:**
  ```sh
  uv run ruff check src tests && uv run ruff format src tests
  uv run mypy --strict
  uv run pytest -q
  uv run safemaxxing watch --udp-flows; echo "exit=$?"
  uv run safemaxxing doctor | tail -3
  ```
- **Result and raw data:**
  ```text
  All checks passed!
  Success: no issues found in 24 source files
  222 passed, 7 skipped in 4.47s
  --udp-flows: capturing on pktap needs root: re-run with sudo
  exit=1
  ! pktap capture (--udp-flows): capturing on pktap needs root: re-run with sudo
  ```
  The pktap and supervisor tests ran 3 more times, all green, with no fake tcpdump left
  running afterwards.
- **Problems / regressions:**
  - Two phase-1 tests needed `warmup_s=0` / `max_restarts=0` under the new defaults: a
    recorded stream ends cleanly and would otherwise be restarted, and its first flow would
    be muted.
  - pktap flows have no hostname yet.
- **Next steps:** the end-to-end check on a real Meet call as root (TODO **Now**).

## [2026-10-27 08:37 +0100] - pktap CPU and per-pid capture measured during a Meet call (Mac)

- **Environment:** macOS 27.0.1, arm64 Apple M4, root. A Meet call in Brave: the
  NetworkService helper is pid 16112, and the user's `-Q` filter targeted pid 16105.
- **Goal:** answer two open design questions. Does a capture filtered by pid catch the call?
  What does the capture cost in CPU?
- **Commands run** (the `measure_pktap.sh` script from the 2026-10-26 design session). It
  runs `tcpdump -i pktap,all -k -n -l -q -tt [--immediate-mode] -Q "dir=out <extra>" udp and
  not port 53 and not port 853 and not port 5353` and reads the CPU time with `ps`:
  ```sh
  sudo sh measure_pktap.sh meet-main 20 "and pid=16105"
  sudo sh measure_pktap.sh meet-buf 60 "" buffered
  ```
- **Result and raw data (verbatim):**
  ```text
  label=meet-main seconds=20 cpu_s=0.10 cpu_pct=0.50 lines=1 lines_per_s=0.1
  7458 packets received by filter / 0 dropped by kernel / 7458 drops by metadata filter
  label=meet-buf seconds=60 cpu_s=0.27 cpu_pct=0.45 lines=9076 lines_per_s=151.3
  lines with ', out'=9075  lines with ', in'=0
  20386 packets received by filter / 0 dropped by kernel / 10240 drops by metadata filter
  ```
  - **Per pid: no.** The `-Q` filter on pid 16105 kept 0 of 7458 packets during the call. All
    the call's media comes from the helper, 16112, which is the case `actor_pids` in the
    design covers. A capture started from `event.pid` alone would see nothing.
  - **`-Q` is applied in tcpdump, not in the kernel.** Every packet still reaches tcpdump
    ("drops by metadata filter"), so a pid filter saves parsing but not the copy. With
    immediate mode and 0 lines printed, tcpdump used 0.50% of one core for about 373
    packets/s.
  - **CPU, always on:** 0.45% of one core for tcpdump, at 151 lines/s. On the same file,
    `parse_pktap_line` takes 6.45 µs per line, about 0.10% of one core at 151 lines/s.
  - **A new line shape:** 3150 of the 9076 lines (35%) are `(llw0, svc BE, out, ch)` with no
    `proc`, sent between ULA addresses (`fdcb:…` → `fd0c:…`). They have no pid, so they
    cannot be attributed, and the parser skips them. This is now pinned verbatim in
    `test_rejects_other_lines`.
  - In this capture: Brave Browser He:16112 → 74.125.250.248:3478, 5429 lines.
- **Code changes:**
  - `pktap_command()` adds `--immediate-mode`. On a pipe tcpdump buffers packets, up to about
    1 s late, without it.
  - The BPF filter is now `udp_filter()`, which excludes `DNS_PORTS` unless `include_dns`.
    That removes the Avast DNS flows of the previous run.
  - Suite: 209 passed, 7 skipped; ruff and mypy clean. As non-root, tcpdump accepts the new
    command and stops at `SIOCIFCREATE`.
- **Problems / regressions:** none. The CPU cost of `--immediate-mode` with a full Meet stream
  (no pid filter) has not been measured. The 0.50% above was measured on the same packet
  rate, but with nothing printed.
- **Decision proposed:** the capture stays always on. It costs well under 1% of a core, and
  a per-pid capture needs the whole process family and saves no kernel copy.

## [2026-10-27 08:34 +0100] - pktap source live as root during a Meet call (Mac)

- **Environment:** macOS 27.0.1, arm64 Apple M4, `main` at 90957d4 plus the uncommitted phase 1.
  Root, via `sudo uv run`. The user ran it during a Meet call in Brave.
- **Goal:** check that the real `pktap_command()` output matches the fixtures and gives
  connections.
- **Commands run:**
  ```sh
  sudo uv run python -c "import asyncio; from safemaxxing.pktap import PktapCapture
  async def main():
      async for c in PktapCapture().connections(): print(c.process_name, c.pid, c.remote, c.bundle_id)
  asyncio.run(main())"
  ```
- **Result and raw data (verbatim):**
  ```text
  Brave Browser Helper 16112 74.125.250.248:3478 com.brave.Browser
  com.avast.Antivirus.SystemExtension 30059 10.128.132.57:53 None
  com.avast.Antivirus.SystemExtension 30059 10.128.132.57:53 None
  kernel_task 0 10.244.255.255:137 None
  ```
  - **The format works live.** `-k -n -q -tt -l -i pktap,all -Q dir=out udp` prints the
    lines the parser expects. The Meet call is a single connection for the NetworkService
    helper (16112), and its full name comes from psutil. The bundle id is
    `com.brave.Browser`, the outermost .app, so it matches Brave's sensor events exactly.
  - **Avast's system extension (30059)** sends DNS to 10.128.132.57:53. Each query uses a
    new source port, so each one is a new flow. The correlation engine drops them (port 53)
    unless `include_dns`. Its bundle id is None because `enclosing_apps` looks only for `.app`
    and the binary sits in a `.systemextension`.
  - **kernel_task (pid 0)** sends NetBIOS (UDP 137) to the subnet's broadcast address
    10.244.255.255. `is_relevant_destination` only knows 255.255.255.255, and pid 0 has no
    executable path, so its flow was kept.
- **Code changes:** `PktapFlowTracker` treats `pid == 0` (`KERNEL_PID`) as system: it is
  dropped unless `include_system`. New test
  `test_kernel_netbios_broadcast_dropped_as_system`. Suite: 208 passed, 7 skipped; ruff and
  mypy clean.
- **Problems / regressions:** none. Still open:
  - a directed broadcast sent by a user process is still kept. It is rare, and it would need
    the interfaces' broadcast addresses (`psutil.net_if_addrs`);
  - a `.systemextension` gets no bundle id.
- **Next steps:** wire it into `Supervisor` and the CLI; check that a Meet call raises the
  alert end to end; measure CPU.

## [2026-10-27 08:30 +0100] - pktap source, phase 1: parser, flow tracker, tcpdump wrapper (Mac, not root)

- **Environment:** macOS 27.0.1, arm64 Apple M4, branch `main` at 90957d4 plus uncommitted
  changes. Run as the user, not as root.
- **Goal:** the first part of the pktap egress source from the **Now** task: the data model,
  the tcpdump subprocess and the line parser, all tested offline on the recorded captures.
- **Raw data used:** 5 pktap captures recorded by the user on 2026-10-26 15:57-16:01 and
  2026-10-27 08:13-08:16. The exact commands are not recorded. Their stderr shows
  `listening on pktap,all`, a metadata filter (`drops by metadata filter`), and only `out`
  UDP packets:
  | file | packets | span | outbound flows (proc, destination) |
  |---|---|---|---|
  | `pktap-idle.txt` | 2 | 0 s | WhatsApp:19122 → 57.144.249.32:443 |
  | `pktap-meet.txt` | 5986 | 62.0 s | Brave Browser He:16112 → 74.125.250.240:3478 |
  | `pktap-meet-pid.txt` | 2182 | 22.0 s | Brave Browser He:16112 → 74.125.250.252:3478 (another network) |
  | `pktap-youtube.txt` | 68 | 45.7 s | amsaccountsd:808 → 17.253.122.199:443; replicatord:737 → 4 fe80:: peers on awdl0 |
  | `pktap-youtube-buf.txt` | 299 | 6.0 s | replicatord:737 → fe80::3811:10ff:fedb:ad8a on awdl0 |

  A Meet call is about 97 packets/s on a single flow. The YouTube captures have no Brave
  packets at all. That is not explained yet: the filter used may have excluded Brave, or
  the video was not using UDP at that moment.
- **Code changes:**
  - `models.py`: `Direction`, `PktapEvent` (with `flow_key` and `to_connection`) and
    `PKTAP_STATUS`.
  - New `safemaxxing/pktap.py`:
    - `pktap_command()` builds `/usr/sbin/tcpdump -k -n -q -tt -l -i pktap,all -Q dir=out udp`;
    - `parse_pktap_line()`;
    - `is_relevant_destination()`;
    - `PktapFlowTracker`;
    - `PktapCapture`, with `lines()`, `events()` and `connections()`.
  - New `tests/test_pktap.py` (47 tests). New `tests/fixtures/pktap/*.txt`: verbatim
    excerpts (idle and youtube complete, the first 40 lines of the others).
- **Commands run:**
  ```sh
  uv run ruff check src tests && uv run ruff format src tests
  uv run mypy --strict
  uv run pytest -q
  /usr/sbin/tcpdump -k -n -q -tt -l -i pktap,all -Q dir=out -c 1 udp   # not root
  ```
- **Result and raw data:**
  ```text
  All checks passed!
  Success: no issues found in 24 source files
  207 passed, 7 skipped in 4.34s
  tcpdump: ioctl(SIOCIFCREATE): Operation not permitted
  ```
  tcpdump accepted every option and stopped only when it tried to create the pktap
  interface, which needs root. Offline replay of the fixtures through `PktapFlowTracker`:
  - Meet: 1 connection, `Brave Browser Helper` → 74.125.250.240:3478 (UDP, status `PKTAP`);
  - idle: 1 connection, WhatsApp;
  - youtube and youtube-buf: 0 connections. amsaccountsd is dropped as a SIP binary,
    replicatord's packets as link-local.

  A mic event from Brave's main process (pid 6254) 1.1 s before the Meet flow gives the
  alert `com.brave.Browser used microphone then connected to 74.125.250.240:3478 after
  1100 ms`. The match is by bundle-id prefix, `com.brave.Browser.helper`.
- **Problems / regressions:** one bug found and fixed while writing the tests. Leaving
  `events()` early did not close the inner `lines()` generator, so tcpdump kept running.
  `contextlib.aclosing` now closes it. Tests cover both cases: a child that ignores SIGTERM
  is killed after `stop_timeout_s`, and a cancelled consumer still reaps the child.
- **Next steps:**
  - run `PktapCapture` as root during a Meet call and check that the real output matches
    the fixtures (`-q` and `-Q dir=out` have not been seen on a live capture yet);
  - wire it into `Supervisor` as a second connection source, with a CLI switch and a
    `doctor` check;
  - measure CPU.

## [2026-10-26 14:04 +0100] - Unconnected UDP during a Meet call: `nettop` no, pktap yes (Mac)

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, branch `main` at 796a8ea
  (v0.1.1). Brave restarted, so the NetworkService helper is now pid 16112.
- **Goal:** TODO P2 in **Now**. Find a per-process flow source that sees the destinations
  of UDP sockets that are never `connect()`ed. This is investigation only.
- **Code changes:** none.
- **Commands run:** during a Meet call in Brave with camera and mic on:
  - a psutil `Process.net_connections(kind="inet")` dump for Brave, without root;
  - `nettop -L 3 -s 1 -m udp -n -x`, without root;
  - by the user, `sudo tcpdump -k -n -i pktap,en0 -c 30 udp and not port 5353`;
  - `man tcpdump` for the metadata filter.
- **Result and raw data:**
  - **Socket table (psutil):** pid 16112 has UDP on `0.0.0.0:53266` and `[::]:50822`, both
    with no remote address, plus mDNS on 5353 and 53 TCP connections to :443.
  - **`nettop`: no.** It runs without root and counts bytes per socket. The call socket
    showed `udp4 *:53266<->*:*` on en0, with bytes_out going 783040 → 849105 in 1 s (about
    66 KB/s, the call's media), but still no remote address. Connected UDP shows its peer
    (`cloudd` `10.243.5.87:57807<->17.248.209.46:443`); unconnected UDP never does.
  - **pktap (`tcpdump -k`): yes.** Each packet carries the interface, process name and pid,
    and direction, plus the real addresses. 30 packets in 0.2 s, all from the same flow:
    ```text
    14:04:51.457222 (en0, proc Brave Browser He:16112, svc BE, in, so) IP 74.125.250.240.3478 > 10.243.5.87.51784: UDP, length 68
    14:04:51.457746 (en0, proc Brave Browser He:16112, svc BE, out, so) IP 10.243.5.87.51784 > 74.125.250.240.3478: UDP, length 722
    ...
    30 packets captured, 55 packets received by filter, 0 packets dropped by kernel
    ```
    That is Brave's NetworkService talking to Google's media relay 74.125.250.240:3478 (the
    STUN/TURN port). The local port was 51784, a new socket for this call: ports change from
    call to call. The process name is cut to 16 characters ("Brave Browser He"), so the pid
    is the key to use.
  - The tcpdump on macOS can filter on metadata with `-Q`, for example `-Q "pid = 16112"` or
    `-Q "proc = 'Some App'"` (fields `proc`, `pid`, `eproc`, `epid`, `dir`, `if`). So a
    capture can be limited to one process.
- **Problems / regressions:** none (no code change).
- **Next steps:** design a pktap egress source. Open questions:
  - always on (about 150 packets/s for one video call) or started for a few seconds after a
    sensor event, with `-Q "pid = N"`;
  - parse tcpdump's text output or read BPF directly;
  - the first `out` packet of each (pid, destination) counts as the "connection";
  - cost in CPU;
  - overlap with the SNI capture item in the Backlog, which needs packets too.

## [2026-10-26 13:54 +0100] - 0.1.1 parser fixes: coreaudiod preflights, indicator flicker, cmio backtraces (Mac)

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, branch `main` at 5fd92d0. The
  fixes are 1eb829f and 7c7260c.
- **Goal:** the three P3 parser items for 0.1.1, each fixed against the real samples.
- **Code changes:** `sensors.py`.
  - **coreaudiod preflights (1eb829f).** `SensorEventParser` links every line of a TCC request
    through its `activityIdentifier`. One request's lines are coreaudiod's SEND, the
    REQUEST_MSG in both tccds (system and user), FORWARD, Handling and Auth. coreaudiod's SEND
    is held back. The whole request is dropped once tccd's REQUEST_MSG says `preflight=true`.
    Lines with no activity id are judged one by one, as before.
  - **Indicator flicker and cmio backtraces (7c7260c).**
    - An indicator attribution that comes back within `INDICATOR_MERGE_S` = 2.0 s of going off
      is not a new event. Short spans are kept: a blinking share is still detected.
    - cmio lines containing `backtrace` no longer count as camera starts.
- **Tests:** in `test_sensors.py`:
  - three complete coreaudiod requests, rebuilt byte for byte from the samples (2026-10-24
    screencapture preflight, 2026-10-26 Brave preflight, 2026-10-23 Voice Memos
    `preflight=false`), plus the no-activity-id fallback and back-to-back requests;
  - real indicator timelines with timestamps (Cmd+Shift+5 flicker, the 20-line Brave share,
    the Voice Memos `loc:` 18 ms flap, two captures 11 s apart);
  - Brave's cmio start line and two of its backtrace lines.

  Two older indicator tests now carry their real timestamps. All new tests fail on the parser
  before the fix.
- **Commands run:** `ruff check .`, `ruff format --check .`, `mypy`, `pytest`, and a replay
  of every raw `.jsonl` in `testlogs/` through `SensorEventParser` before and after each fix.
- **Result and raw data:** ruff 0, mypy 0, 160 passed / 7 skipped. Replay, before → after:
  ```text
  coreaudiod preflights (1eb829f)
    screen-recording   microphone 7 -> 0   (screencapture 3506 x4, systemuiserver 743, replayd 791 x2)
    meet-brave         microphone 6 -> 1   (Brave 1761 x5 gone; the mic: indicator stays)
    20261023-1424      microphone 42 -> 24, tcc 53 -> 43 (AudioCapture preflights); Photo Booth,
                       Voice Memos, ring light still have TCC mic events
    20261022-wide      microphone 33 -> 20, tcc 116 -> 111
  indicator merge + cmio (7c7260c)
    meet-brave         camera 55 -> 5, scr: indicator 13 -> 1
    meet-brave-2       scr: indicator 10 -> 2   (two shares, 15 s apart)
    screen-recording   scr: indicator 2 -> 1
    20261023-1424      camera 40 -> 10, loc: indicator 2 -> 1 (18 ms flap)
    20261022-wide      camera 42 -> 12
  ```
- **Problems / regressions:** none found. The re-add gaps in all samples are either at most
  0.884 s (flicker) or at least 3.363 s (separate uses), so the 2 s merge window leaves
  margin on both sides. The cost: two real uses of the same app and sensor less than 2 s
  apart now give one indicator event.
- **Next steps:** release 0.1.1.

## [2026-10-26 13:27 +0100] - No Brave alert: Meet's traffic is on unconnected UDP (Mac)

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, sudo, branch `main` at b771031.
  Brave 156.1.98.60, main process pid 6254.
- **Goal:** TODO P2 in **Now**: get a live alert for Brave from a Meet share.
- **Code changes:** none.
- **Commands run:** `sudo uv run safemaxxing watch --events` while sharing in Meet. Then,
  without root, during the call, a psutil `Process.net_connections(kind="inet")` count for
  every Brave process, and `ps -o command= -p 6266` for the helper type.
- **Result and raw data:** `watch` printed events only, no alert:
  ```text
  screen_capture com.brave.Browser pid=6254 (ScreenCapture)
  camera         com.brave.Browser pid=None (indicator:cam)
  screen_capture com.brave.Browser pid=None (indicator:scr)   ×5
  ```
  Brave's sockets during the call all belong to one helper process:
  ```text
  6266 Brave Browser Helper  utility-sub-type=network.mojom.NetworkService
       tcp :443 with remote address  ×22
       udp with NO remote address    ×12
  ```
  - Meet's media (WebRTC) and QUIC go over UDP sockets that are never `connect()`ed, so the
    socket table has no remote address for them. `outbound_only` drops them by design: it
    keeps only connected UDP. These flows cannot be seen, so nothing can be correlated.
  - The TCP connections to Google were already open before the share and are reused.
    Joining, sharing or turning on the camera opens no new TCP connection within the 2 s
    window.
  - So the attribution side is right (Brave pid 6254, `com.brave.Browser`). The alert cannot
    happen with a socket-table egress source.
- **Problems / regressions:** a known limit, not a bug. A browser-based call (WebRTC) does
  not produce correlatable egress.
- **Next steps:** the alert task leaves **Now**. Find out whether a per-process flow source
  can see unconnected-UDP destinations, starting with `nettop` (NetworkStatistics), then pf
  logging. Check this before designing anything.

## [2026-10-26 13:20 +0100] - Live `watch --events` during a Meet share in Brave (Mac)

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, sudo, branch `main` at 5040508,
  which includes the fix ff1c9f7. Brave 156.1.98.60, main process pid 6254.
- **Goal:** TODO P2 in **Now**. Check live that the screen-capture event names Brave and
  stays visible without `--include-system`.
- **Code changes:** none.
- **Commands run:** first `sudo uv run safemaxxing watch`, then
  `sudo uv run safemaxxing watch --events`. During each run, in a Meet call already in
  progress: "Present → A window", then camera on, then mic on. The time is approximate: the
  terminal output has no timestamps. The helper pids were read afterwards with
  `ps -o command= -p 6298,6299`.
- **Result and raw data:** the first run printed one alert and nothing for Brave:
  `ALERT #1 [medium] com.anthropic.claude-code used tcc then connected to
  160.79.104.10:443 after 692 ms`. This is the Claude Code session itself: a TCC check, then
  HTTPS to the Anthropic API. The `--events` run printed:
  ```text
  screen_capture com.brave.Browser pid=6254 (ScreenCapture)      <- replayd's request, now Brave's
  screen_capture com.brave.Browser pid=None (indicator:scr)      ×4
  tcc            com.avast.Antivirus.EndpointSecurity pid=1165 (SystemPolicyAllFiles)
  camera         com.brave.Browser pid=6299 (Camera)             ×2  VideoCaptureService helper
  camera         com.brave.Browser pid=6254 (Camera)             ×2
  camera         com.brave.Browser pid=None (indicator:cam)      ×2
  microphone     com.brave.Browser pid=6298 (Microphone)         ×3  AudioService helper
  microphone     com.brave.Browser pid=6254 (Microphone)         ×3
  microphone     com.brave.Browser pid=None (indicator:mic)      ×2
  ```
  - **The fix works live.** The share shows up as one `ScreenCapture` TCC event for Brave
    pid 6254, visible without `--include-system`. Before ff1c9f7 it would have been
    `replayd` and hidden. The listener's 1 s cooldown collapses replayd's ~30 requests/s into
    one event.
  - The `scr:` indicator gives 4 events for one share, because it flickers once per second
    (TESTLOG 10:30).
  - Camera and mic are attributed both to the main process and to Brave's helper for that
    sensor: 6299 is `video_capture.mojom.VideoCaptureService`, 6298 is
    `audio.mojom.AudioService`. All of them carry `com.brave.Browser`, so the bundle match in
    `same_actor` correlates them with the sockets of any Brave helper.
- **Problems / regressions:** none. There was no Brave alert, as expected: in a call already
  in progress, starting a share, the camera or the mic opens no new outbound connection
  within the 2 s window. So the correlation with Brave's sockets is not verified live yet.
- **Next steps:** to get a Brave alert, open "Present" or turn the camera on *before*
  joining the call, then join. The connections of the join come right after the event.

## [2026-10-26 10:41 +0100] - replayd's ScreenCapture requests go to the audit-token subject (Mac)

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, branch `main` at 240eff1; the
  fix is ff1c9f7.
- **Goal:** TODO P2 in **Now**. Attribute replayd's ScreenCapture requests to the client
  that tccd names in `TCCD_MSG_CREDENTIAL_AUTHENTICATOR_AUDIT_TOKEN_KEY={pid:N}`.
- **Code changes:** `sensors.py`. `replayd` is added to `BROKER_PROCESSES`. A ScreenCapture
  line that carries a subject audit token is attributed to that pid and is exempt from the
  rule that the logging process must be the one that captures. Other services that carry
  audit tokens (contactsd, sandboxd, calaccessd) are unchanged. Tests in `test_sensors.py`:
  - five REQUEST_MSGs rebuilt byte for byte from the four real samples (709.1440, 709.2,
    398.149, 791.2, 733.14);
  - replayd's SEND and mic preflight;
  - a listener test checking that Brave shows up and the WindowServer check of replayd is
    hidden;
  - an AddressBook audit-token guard.

  All 6 new screen-capture tests fail on the parser at 240eff1.
- **Commands run:** `ruff check .`, `ruff format --check .`, `mypy`, `pytest`. Each raw
  `.jsonl` in `testlogs/` was also replayed through `SensorEventParser`, before and after
  the fix.
- **Result and raw data:** ruff 0, mypy 0, 151 passed / 7 skipped. Replay, before → after:
  ```text
  meet-brave-sample-2   screen_capture replayd 709 ×244      -> Brave 6254 ×244
  meet-brave-sample     screen_capture replayd 709 ×540      -> Brave 1761 ×540, replayd 709 ×1 (WindowServer check)
                        tcc 2463 -> 2461 (replayd's own SystemPolicyAllFiles check, now a broker line)
  screen-recording      screen_capture replayd 791 ×4        -> screencapture 3506 ×4, replayd 791 ×1 (WindowServer check)
                        microphone replayd 791 ×7            -> ×2 (coreaudiod's preflight for replayd, the P3 item)
  screen-sample         screen_capture replayd 733 ×4        -> 37712 ×2, 37854 ×2 (the two Cmd+Shift+5 clients)
  ```
  Photo Booth / Voice Memos samples: unchanged.
- **Problems / regressions:** none. The 2 events attributed to replayd come from
  WindowServer checking replayd. replayd is a SIP binary, so the listener's enricher marks
  them system and hides them, as the new listener test shows.
- **Next steps:** live `watch` during a Meet share in Brave: the alert should name Brave.
  The TCC event has a pid now, so it can correlate with Brave's sockets.

## [2026-10-26 10:30 +0100] - Google Meet in Brave: working window share after a restart (Mac)

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, sudo, branch `main` at 62a07f4.
- **Goal:** TODO P2 in **Now**. With the Screen Recording grant already on, does replayd's
  REQUEST_MSG still carry Brave's pid during a share that actually works?
- **Code changes:** none.
- **Commands run:** Screen Recording grant for Brave checked in System Settings, Brave
  quit with Cmd+Q and reopened, `sudo uv run safemaxxing sample --seconds 40 --out
  testlogs/meet-brave-sample-2.jsonl`. During the sample, in Meet: "Present → A window".
  The other side of the call saw the window. Camera and mic were off: no `cam:`/`mic:`
  indicator appeared. `watch` was not run. The raw `.jsonl` (3078 entries) is not committed.
- **Result and raw data:** TCC had 1464 entries, 244 parsed (`screen_capture`×244, all
  `replayd` pid 709). Control Center had 20 (10 parsed `screen_capture`). locationd had 25
  `location`. tccd logged no denial and no prompt.
  ```text
  10:30:55.745 tccd  REQUEST_MSG msgID=709.1440 ... AUDIT_TOKEN_KEY={pid:6254, ...}   (no preflight)
  10:30:55.767 tccd  Handling access request to kTCCServiceScreenCapture, from Sub:{com.brave.Browser}Resp:{... pid=6254 ...}
  10:30:56.146 ControlCenter ["scr:com.brave.Browser"]
  10:30:56.293 ControlCenter []                         <- 147 ms
  10:30:57.148 ControlCenter ["scr:com.brave.Browser"]   ... once per second until 10:30:59.288
  10:31:14.467 ControlCenter ["scr:com.brave.Browser"]   ... once per second until 10:31:18.652
  10:31:18.626 replayd 709   last ScreenCapture SEND (116 in the first burst, 128 in the second)
  ```
  - **replayd carries the client's pid even when the share works.** All 244
    REQUEST_MSGs from replayd have `AUDIT_TOKEN_KEY={pid:6254}`, the restarted Brave, and
    none is a preflight. The first run (10:23) showed the same thing with the grant denied.
    The parser still gives every event to `replayd` pid 709, so a working third-party share
    is hidden as system. Only the `scr:com.brave.Browser` indicator names Brave.
  - **A live share does not keep `scr:` on.** The indicator came on 10 times, for 101–147
    ms each time (the last one 28 ms), about once per second, in two bursts of about 4 s:
    10:30:56–59 and 10:31:14–18. replayd's requests come in the same two bursts, with
    nothing in between.
- **Problems / regressions:** none in the code. The attribution gap from 10:23 is
  confirmed. For the planned `scr:` flicker fix: dropping short spans would also drop this
  real share, because every span here is 150 ms or shorter.
- **Next steps:** attribute replayd's requests to the audit-token pid, then check with
  `watch` on a Meet share. Fix the `scr:` flicker by merging spans less than about 1 s
  apart, not by dropping short spans.

## [2026-10-26 10:23 +0100] - Google Meet in Brave: camera, mic, window share denied by TCC (Mac)

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, sudo, branch `main` at 27a5cbf.
- **Goal:** the two items in **Now** in TODO.md. When a third-party app shares the screen
  through ScreenCaptureKit, which pid is logged? Are coreaudiod's mic preflights real mic
  use?
- **Code changes:** none.
- **Commands run:** `sudo -v`, then
  `sudo uv run safemaxxing sample --seconds 40 --out testlogs/meet-brave-sample.jsonl`.
  During the sample, in a Meet call in Brave: camera on, mic on, then "Present → A window".
  `watch` was not run. The raw `.jsonl` (14499 entries, 18 MB) is not committed. The
  numbers below come from running `SensorEventParser` over it.
- **Result and raw data:** TCC had 8319 entries (`tcc`×2463, `screen_capture`×545,
  `microphone`×5, `camera`×2). cmio had 52 `camera`. Control Center had 15
  (`screen_capture`×13, `camera`×1, `microphone`×1). locationd had 44 `location`.
  ```text
  10:23:40.000 Brave Browser Helper 2526  SEND camera msgID=2526.7 (preflight=true, target_token={NULL})
  10:23:40.043 Brave Browser Helper 2526  CMIODeviceStartStream (35 36)
  10:23:40.067 ControlCenter              ["mic:com.brave.Browser", "cam:com.brave.Browser"]
  10:23:42.712 Brave Browser 1761         SEND ScreenCapture msgID=1761.5 (preflight=true)
  10:23:42.728 tccd  REQUEST_MSG msgID=709.2 (replayd) ... AUDIT_TOKEN_KEY={pid:1761, auid:501, euid:501}
  10:23:42.764 tccd  Notifying for access kTCCServiceScreenCapture for target PID[709], responsiblePID[1761]
  10:23:42.764 tccd  Service kTCCServiceScreenCapture does not allow prompting; returning denied.
  10:23:42.932 tccd  Update Access Record: kTCCServiceScreenCapture for com.brave.Browser to Denied (System Set)
  10:23:57.289 tccd  Update Access Record: ... com.brave.Browser to Allowed (System Set)   <- toggled in Settings
  10:23:57.416 coreaudiod 554  SEND kTCCServiceMicrophone target_token={pid:1761} (preflight=true)
  10:23:59.089 ControlCenter   [scr:com.brave.Browser, ...]   then 12 more on/off flips until 10:24:09.728
  10:24:09.850 replayd 709     last of 540 ScreenCapture SENDs (709.2 … 709.541)
  ```
  - **Screen sharing failed.** Brave had no Screen Recording grant, and tccd does not prompt
    for it. The grant was turned on in System Settings at 10:23:57, but Brave was not
    restarted. After that Brave kept retrying: the `scr:` indicator flipped on/off, staying
    on for 0.2–1.2 s each time, and replayd sent about 20 requests per second.
  - **Third-party screen sharing (TODO P2): replayd's pid wins.** replayd sends the
    ScreenCapture requests on Brave's behalf. Brave's pid is in tccd's REQUEST_MSG
    (`TCCD_MSG_CREDENTIAL_AUTHENTICATOR_AUDIT_TOKEN_KEY={pid:1761}`) and in "Notifying …
    responsiblePID[1761]", but not in replayd's SEND line. The parser gave all 540
    `screen_capture` events to `replayd` pid 709, a SIP binary, so `watch` would hide them
    without `--include-system`. Only the 13 `scr:com.brave.Browser` indicator events point
    at Brave.
  - **coreaudiod mic preflights (TODO P3): again not real mic use.** Brave produced 4 TCC
    `microphone` events (10:23:57.416–.458), all from coreaudiod's `preflight=true` request
    for `{pid:1761}`. They came 127 ms after the Screen Recording grant. The real mic start at
    10:23:40.067 had no TCC request at all, because Meet's mic was already granted; only the
    `mic:` indicator caught it.
  - **Inflated counts, as feared:** one camera start (10:23:40.043) gave 52 cmio `camera`
    events because the `backtrace N` lines are counted, plus 13 `scr:` events in 10 s.
- **Problems / regressions:** none in the code. Brave's screen capture is attributed to
  replayd and hidden as a system event. This is an attribution gap, not a parser crash.
- **Next steps:** run again after Cmd+Q on Brave, with the Screen Recording grant already
  on, to see whether a working share still carries `{pid:Brave}` in replayd's REQUEST_MSG.
  Then attribute replayd's requests to the audit-token pid, drop coreaudiod mic preflights,
  and fix the `scr:` flicker together with the cmio backtrace lines.

## [2026-10-24 20:42 +0200] - Live screen *recording* with Cmd+Shift+5 (Mac)

- **Environment:** macOS 27.0.1, arm64 Apple M4, sudo, branch `main` at 93417be.
- **Goal:** TODO P1 in **Now**. A video recording must start inside the sample window: the
  QuickTime run on 2026-10-23 produced no ScreenCapture line at all.
- **Code changes:** none.
- **Commands run:** `sudo -v`, then
  `sudo uv run safemaxxing sample --seconds 25 --out testlogs/screen-recording-sample.jsonl`.
  During the sample: Cmd+Shift+5, "Record Entire Screen", Record, about 8 s, then stop from
  the menu bar. Timestamps were read from the raw `.jsonl`, which is not committed.
- **Result and raw data:** 290 entries. TCC 116 (47 parsed: `tcc`×30, `microphone`×12,
  `screen_capture`×5). Control Center 4 (2 parsed `screen_capture`).
  ```text
  20:42:19.341 screencapture 3506  kTCCServiceListenEvent (toolbar open, entitled)
  20:42:23.228 replayd 791         SEND msgID=791.2 service=kTCCServiceScreenCapture   (also .3 .4 .5)
  20:42:23.252 ControlCenter       ["scr:com.apple.systemuiserver"]
  20:42:23.276 ControlCenter       []                                 <- 24 ms flicker
  20:42:23.506 coreaudiod 591      kTCCServiceMicrophone target_token={pid:3506} preflight=true
  20:42:23.640 ControlCenter       ["scr:com.apple.systemuiserver"]
  20:42:31.037 ControlCenter       []                                 <- 7.4 s = the recording
  ```
  - The recording is detected the same way as screenshots: replayd's own ScreenCapture
    requests count, and the `scr:` indicator stays on for exactly as long as the recording.
  - Attribution goes to system processes (replayd, `com.apple.systemuiserver`), not to the
    `screencapture` tool. Both are SIP binaries, so they stay hidden without
    `--include-system`. That is right for the built-in recorder.
- **Problems / regressions:** none in the code. Two cosmetic findings:
  - A 24 ms `scr:` flicker comes before the real start, so one recording yields 2
    screen-capture events.
  - coreaudiod's microphone *preflight* for `screencapture` (pid 3506) was parsed as a
    `microphone` event, although no `mic:` indicator ever appeared. The recording had no mic
    input selected. The SEND line does not carry `preflight`; only tccd's REQUEST_MSG does.
- **Next steps:** tag `v0.1.0`. The two findings are added to **Next Up** in TODO.md.

## [2026-10-24 20:38 +0200] - Blocks across a real reboot with `boot install` (Mac)

- **Environment:** macOS 27.0.1, arm64 Apple M4, sudo, branch `main` at e146bc2.
- **Goal:** TODO P1. Check that the launchd job from 9b0af93 reapplies the saved blocks
  after a real restart.
- **Code changes:** none.
- **Commands run:** `sudo uv run safemaxxing block 1.1.1.1`, `sudo uv run safemaxxing boot
  install`, reboot, `sudo uv run safemaxxing boot status`, `curl -m 3 https://1.1.1.1`,
  `cat /var/log/safemaxxing-boot.log`.
- **Result and raw data:**
  ```text
  job ...restore.plist: installed=True loaded=True
  saved /Library/Application Support/safemaxxing/blocklist: 1  live table: 1
  curl: (28) Connection timed out after 3003 milliseconds
  boot log, run 1 (install, live system): 0/1 addresses added. / pf enabled / Token : 8348…
  boot log, run 2 (after reboot):         1 table created. / 1/1 addresses added. / pf enabled / Token : 6268…
  ```
  - Run 1 is the one-off run triggered by `launchctl bootstrap`: the IP was already in the
    table, so `-T add` added 0 and removed nothing, as intended.
  - Run 2 is the boot. `1 table created` shows that the table was gone after the restart and
    the job rebuilt it. pf came back enabled and 1.1.1.1 stayed blocked.
  - The wait loop let the job load only after `com.apple.pfctl` had loaded `/etc/pf.conf`,
    and the anchor rule was still in effect afterwards (curl timed out).
- **Problems / regressions:** none.
  - The log fills with benign pfctl chatter (`-f` warning, ALTQ) and is appended on every
    boot.
  - Each run takes a new `pfctl -E` reference (one per boot, plus one per `boot install`).
    The Inbox item about releasing the token covers this.
- **Next steps:** tag `v0.1.0` once the screen-recording check is done.

## [2026-10-23 16:58 +0200] - System flag for Control Center indicator events (Mac)

- **Environment:** macOS 27.0.1, arm64 Apple M4, uid 501 (no sudo), branch `main`,
  CPython 3.13.14 (3.12.13 in a scratch venv). There were 845 processes, and 844 of them had a
  readable exe.
- **Goal:** TODO P2. Indicator events (`cam:`/`mic:`/`scr:`) carry only a bundle id, so
  until now they were always shown, even for Apple apps.
- **Code changes:**
  - `sensors.py`: added `possible_exes_for_bundle`. A running process qualifies if any
    enclosing .app declares the id, or if it sits outside SIP paths in an .app with an
    unusable Info.plist. `SensorListener` sets `system=True` only if that list is non-empty
    and all of its paths are SIP paths. The lookup runs in a thread and stops after 1 s;
    if it times out, the event stays visible.
  - `correlation.py` / `models.py`: added `Event.from_indicator`. Indicator events are always
    correlated, so their flag only hides them from display.
  - `network.py`: added `_read_plist`, which opens the file with O_NONBLOCK, accepts regular
    files only, reads at most 1 MiB and treats any parse error as None. Also added
    `enclosing_apps` and `bundle_id_for_app`.
  - 6 new tests: SIP vs non-SIP, a copy claiming an Apple id, hostile plists, timeout,
    correlation of spoofs, and nested/moved claimants.
- **Commands run:** gates; `possible_exes_for_bundle` on the live process table; two
  change-tester passes with compiled test bundles (Bad.app with malformed XML, Fifo.app,
  a Copy.app claiming `com.apple.finder`, a moved Info.plist, a nested Inner.app); 6 code
  mutations in a scratch copy.
- **Result and raw data:**
  ```text
  133 passed, 7 skipped (3.12 and 3.13); ruff 0, mypy 0
  com.apple.systemuiserver 52.7 ms system=True | finder 8.1 ms True | Terminal 7.9 ms True
  com.brave.Browser 7.4 ms False (18 procs) | PhotoBooth (not running) False
  mutations: no O_NONBLOCK / narrow except / ignore unreadable plists / outermost app only /
             drop exes guard / drop from_indicator -> 1 failed each (O_NONBLOCK in 2 s, no hang)
  ```
  - The first version crashed `watch` (`ExpatError`) as soon as any running app had a
    malformed Info.plist, and it hung on a FIFO plist. Both are fixed: with Bad.app and
    Fifo.app running, `events()` and `watch --events` exit 0 and the events arrive after
    about 0.1 s.
  - Copy.app claiming `com.apple.finder` stays visible and raises ALERT #1. Before the
    rework, a moved plist or a nested app let the event be hidden. Now both keep it visible.
- **Problems / regressions:** none in the suite.
  - Known limit: a moved plist or a nested app also defeats bundle-id matching for the
    connection, so no alert is raised. That limit predates this change.
  - Without root, lsof gives no exe path, so indicator events cannot match any connection.
  - A lookup that truly blocks (for example a stuck network mount) leaves its worker thread
    behind. The event stays visible.
  - The real Control Center source was not exercised here; it needs a camera/mic grant.
- **Next steps:** confirm live that Photo Booth / Voice Memos disappear from `watch --events`
  without `--include-system` and come back with it (TODO P2).

## [2026-10-23 16:33 +0200] - coreaudio and calaccessd in the raw captures (Mac)

- **Environment:** macOS 27.0.1, arm64 Apple M4, uid 501, branch `main`, CPython 3.13.14.
  Offline analysis only: no sudo, nothing native re-run.
- **Goal:** close the two Inbox questions that need the raw JSON, which exists only on the Mac.
- **Data:** `testlogs/20261023-1424-sample.jsonl` (14:25, Photo Booth + Voice Memos),
  `testlogs/20261022-stash-wide.jsonl` (13:16-13:17) and `testlogs/20261022-stash-sensors.jsonl`
  (13:13). The last two were recovered from a local stash; all three are git-ignored.
- **Commands run:** Python scripts calling `safemaxxing.sensors.parse_entry` on every line,
  grouped by (subsystem, category, process, message template), with times measured relative to
  the `mic:` indicator.
- **Result and raw data:**
  - **calaccessd is a broker.** It has 63 lines at 13:17:00, and they cover 7 requests (4 Calendar,
    3 Reminders). It logs `SEND: ... function=TCCAccessRequest, service=kTCCServiceCalendar`
    with no other actor. tccd then logs `requestor: ... calaccessd, pid=710 ... is checking
    access for accessor ... com.apple.routined, pid=665` and the `tcc.manager.check-by-audit-token`
    entitlement. The parser turned the 7 SEND lines into Calendar/Reminders events for
    calaccessd, so all 7 were attributed to the wrong process.
    **Fix:** `calaccessd` was added to `BROKER_PROCESSES`. Over the three captures, the parsed
    events went from 371 to 364, and the only change is `calaccessd` going from 7 to 0.
  - **coreaudio adds nothing.** The 14:24 sample has 389 lines, 254 templates and 0 parsed.
    - The lines that match the start hints (`_StartIO(80) succeeded`, `starting IO`) never
      say input/mic/record.
    - The input lines (`client starting: ...:input`, `"input_running":true`) never match a
      start hint.
    - Start lines do line up with `mic:` on both days, 116-10 ms before it. Example:
      audiomxd `"update_running_state" ... "name":"VoiceMemos(34399)" ... "input_running":true`.
    - But tccd's microphone request for VoiceMemos already has an exact pid 50-75 ms before
      the indicator.
    - Every template also fires for corespeechd, and neither capture holds a stop line.
- **Problems / regressions:** none. Tradeoff: an app that reads Calendar/Reminders through
  EventKit now produces no TCC event. Before, it produced a wrong one. The real accessor appears
  only in tccd lines without `kTCCService*`, which would need a msgID join.
- **Next steps:** none for coreaudio unless a mic *stop*/duration is wanted. That would first
  need a capture that includes the end of a recording.

## [2026-10-23 15:15 +0200] - Live screen capture: QuickTime and Cmd+Shift+5 (Mac + Linux container)

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, uid 501 + sudo, HEAD 741aa5b
  (`git pull --ff-only`: already up to date).
- **Goal:** check that a real screen capture is still detected after the logging-pid rule.
- **Commands run (Mac), twice:**
  ```sh
  sudo uv run safemaxxing sample --seconds 15 --out testlogs/screen-sample.jsonl
  ```
- **Result and raw data:**
  - **Run 1 (QuickTime):** 180 entries. TCC 106 (64 parsed: `tcc`×57, `microphone`×7, incl.
    `microphone QuickTime Player pid=36030` from its own `SEND ... msgID=36030.3`). **No
    `screen_capture`, no controlcenter line.** coreaudio: `Voice isolation DSP is available
    for client with bundle id com.apple.QuickTimePlayerX`. The recording probably was not
    started within the window: not conclusive.
  - **Run 2 (Cmd+Shift+5, two captures):** 699 entries.
    - TCC 68 (32 parsed: `tcc`×28, `screen_capture`×4):
      `screen_capture replayd pid=733 [Info] SEND: 0/7 synchronous to com.apple.tccd.system:
      request: msgID=733.14, function=TCCAccessRequest, service=kTCCServiceScreenCapture,`.
      replayd's own request counts ✓. `screencapture` pid 37712 (`/usr/sbin/screencapture`):
      `kTCCServiceListenEvent` (entitled), parsed as generic tcc.
    - **Indicator:** `[scr:com.apple.systemuiserver]` → `[]` → `[scr:com.apple.systemuiserver]`
      → `[]`: **first real `scr:`**, 2 screen_capture events.
    - coreaudio `[sss] clientPID 37712(screencapture) ... SystemSounds/system/Screen
      Capture.aif`: shutter sound, so they were screenshots.
    - No WindowServer/coreaudiod ScreenCapture preflight among the parsed lines.
- **Code changes (container):** `src/safemaxxing/sensors.py`: comment updated (all four
  indicator kinds observed). `tests/test_sensors.py`: verbatim `scr:` sequence → 2 events;
  replayd's SEND → `screen_capture` pid 733.
- **Commands run (container):** `uv run ruff check && uv run mypy --strict && uv run pytest -q`
  → `All checks passed!` · `Success: no issues found in 20 source files` · `125 passed, 7 skipped in 2.96s`
- **Problems / regressions:** the attribution is to system processes (systemuiserver,
  replayd), not to the screencapture tool. replayd (path `/usr/libexec`) is marked system and
  hidden. **Indicator events are not:** they're created with `system=False` (no pid, no
  path), so `scr:com.apple.systemuiserver` shows up among the events. No alert results only
  because SystemUIServer's sockets are discarded as system on the network side
  (`correlation.py:179`). The same applies to `cam:com.apple.PhotoBooth` and
  `mic:com.apple.VoiceMemos`. Not covered yet: video recording, and screen sharing from a
  third-party app.
- **Next steps:** recording started inside the window; Meet screen sharing in Brave.

## [2026-10-23 15:00 +0200] - Every ScreenCapture line in the 14:24 sample (Mac + Linux container)

- **Environment:** Mac (macOS 27.0.1, arm64, uid 501) for the dump; Linux container for the
  fix and the checks.
- **Goal:** check whether tccd's lines for the `msgID=525.x` requests still become
  `screen_capture`.
- **Commands run (Mac):** a Python script over `testlogs/20261023-1424-sample.jsonl` that
  prints `processID process | eventMessage[:220]` for every line containing `ScreenCapture`,
  then `sort | uniq -c`.
- **Result and raw data (counts, processes):**
  ```text
  5 407 tccd | <TCCDProcess: identifier=com.apple.WindowServer, pid=406> has the ...tcc.manager... kTCCServiceScreenCapture
  5 407 tccd | <TCCDProcess: identifier=com.apple.audio.coreaudiod, pid=525> has the ...tcc.manager... kTCCServiceScreenCapture
  2 407 tccd | system tccd handled entitlements check for: kTCCServiceScreenCapture
  2 407 tccd | Handling access request to kTCCServiceScreenCapture, from Sub:{com.apple.VoiceMemos}... pid=34399
  2 407 tccd | Handling access request to kTCCServiceScreenCapture, from Sub:{com.apple.PhotoBooth}... pid=34389
  2 407 tccd | Auth:Allowed (Entitled) to kTCCServiceScreenCapture because accessing process ...ringlighthelper, pid=34393
  2 407 tccd | <TCCDProcess: identifier=com.apple.controlcenter, pid=689> has the com.apple.private.tcc.allow entitlement ...
  3 525 coreaudiod   | SEND ... msgID=525.369/372/374 ... ScreenCapture, target_token={pid:34389|34393|34399}
  3 406 WindowServer | SEND ... msgID=406.215/216/218 ... ScreenCapture, target_token={pid:34389|34393|34399}
  6 407 tccd | REQUEST_MSG msgID=525.x / 406.x ... preflight=true target_token={pid:...}
  4 407 tccd | AUTHREQ_CTX msgID=525.x / 406.x ... preflight=yes
  ```
  Every request is a **preflight** made by WindowServer or coreaudiod for the apps that had
  just started. No line comes from an app capturing the screen. Before the fix, `REQUEST_MSG`,
  `Handling access request`, `Auth:Allowed` and the WindowServer `SEND` still produced
  `screen_capture`.
- **Code changes:** `src/safemaxxing/sensors.py`: a single rule replaces the coreaudiod
  special case. A `screen_capture` event requires the logging pid to equal the accessing
  pid. `tests/test_sensors.py`: one fixture per line kind (expected None); an app's own SEND
  (constructed) still counts; coreaudiod's mic request (constructed) is still attributed to
  the client. The old WindowServer attribution test moves to the Camera service so it keeps
  testing the generic rule.
- **Commands run (container):** `uv run ruff check && uv run ruff format --check src tests && uv run mypy --strict && uv run pytest -q`
  → `All checks passed!` · `20 files already formatted` · `Success: no issues found in 20 source files` · `124 passed, 7 skipped in 2.81s`
- **Problems / regressions:** known limit: a real capture is detected only from the app's
  own client-side line (Info level) or from an `scr:` indicator (never observed yet).
  Not validated live.
- **Next steps:** test a real screen capture during `sample`.

## [2026-10-23 14:50 +0200] - pid 525 identified: coreaudiod (Mac + Linux container)

- **Environment:** Mac (macOS 27.0.1, arm64, uid 501) for the lookup; Linux container for
  the fix and the static checks.
- **Goal:** explain the 20 `screen_capture` events for Photo Booth (pid 34389) in the 14:24 run.
- **Commands run (Mac):**
  ```sh
  python3 -I -c '
  import json, sys
  for line in open(sys.argv[1]):
      e = json.loads(line)
      if e.get("processID") == 525:
          print("pid 525 =", e.get("processImagePath")); break
  ' testlogs/20261023-1424-sample.jsonl
  ```
- **Result and raw data:** `pid 525 = /usr/sbin/coreaudiod`. coreaudiod is a broker: its
  `SEND ... service=kTCCServiceScreenCapture, target_token={pid:34389}` asks on behalf of
  Photo Booth, which only used camera and mic. These are not screen captures.
- **Code changes:** `src/safemaxxing/sensors.py`: TCC lines logged by `coreaudiod` with
  service ScreenCapture are dropped. `tests/test_sensors.py`: verbatim fixture (the
  ScreenCapture line) plus a constructed mic counter-example, which is still attributed to
  the client.
- **Commands run (container):** `uv run ruff check && uv run mypy --strict && uv run pytest -q`
  → `All checks passed!` · `Success: no issues found in 20 source files` ·
  `122 passed, 7 skipped in 3.06s`
- **Problems / regressions:** only the lines logged by coreaudiod are covered. If tccd logs
  its own lines for the same `msgID=525.x`, they can still become `screen_capture`
  (not verified).
- **Next steps:** dump every ScreenCapture line from the JSON sample.

## [2026-10-23 14:40 +0200] - Indicator test from the 14:24 run (Linux container)

- **Environment:** Linux x86_64 cloud container, CPython 3.13.16, uid=0. Static checks only.
- **Goal:** pin the real camera/location/mic indicator sequence.
- **Code changes:** `tests/test_sensors.py` gets
  `test_real_indicator_sequence_with_camera_location_and_microphone` (5 verbatim lines →
  cam, loc, loc, mic). `src/safemaxxing/sensors.py`: comment updated, since `mic` has now
  been observed.
- **Commands run:** `uv run ruff check && uv run ruff format --check src tests && uv run mypy --strict && uv run pytest -q`
- **Result and raw data:** `All checks passed!` · `Success: no issues found in 20 source
  files` · `121 passed, 7 skipped in 2.88s`
- **Problems / regressions:** none.
- **Next steps:** identify pid 525 (screen capture for Photo Booth); reboot persistence.

## [2026-10-23 14:30 +0200] - Diverged branches merged (Linux container)

- **Environment:** Linux x86_64 cloud container, CPython 3.13.16, uid=0. Static checks only.
- **Goal:** unblock the Mac. `git pull origin claude/gifted-pascal-tp5iot` failed with
  "divergent branches". The plain `git pull` fast-forwarded the local branch to
  `origin/claude/amazing-pasteur-hj7ek5` (b7f39ba), which has no `scripts/` folder:
  `zsh: no such file or directory: scripts/macos_validate.sh`.
- **Cause:** after 32c1b74 another session pushed c6cdc44 and b7f39ba to
  `claude/amazing-pasteur-hj7ek5`, while this session pushed 7 commits to
  `claude/gifted-pascal-tp5iot`. The two lines had no commit in common after 32c1b74.
- **Code changes:** merge c9155e4 (its message reads "Log the branch divergence..." because the first `git commit` stopped on the unstaged resolution and the next commit completed the merge). The only conflict was `tests/test_sensors.py` (both sides
  appended tests), resolved by keeping both. `sensors.py` merged automatically: sandboxd /
  TCC-manager filter plus the other session's `system` flag and 5-tuple `_classify_tcc`.
- **Commands run:**
  ```sh
  git merge --no-ff origin/claude/amazing-pasteur-hj7ek5
  uv run ruff check && uv run mypy --strict && uv run pytest -q
  ```
- **Result and raw data:**
  ```text
  All checks passed!
  Success: no issues found in 20 source files
  120 passed, 7 skipped in 2.94s
  ```
- **Problems / regressions:** none in the tests. Note: the new default correlation window is
  2 s (was 0.5 s), and system-binary events are now hidden unless `--include-system`.
- **Next steps:** on the Mac,
  `git pull --ff-only origin claude/gifted-pascal-tp5iot && scripts/macos_validate.sh`.

## [2026-10-23 14:24 +0200] - Fourth Mac run: camera + mic live, pf cold start after reboot

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, uid=501 + sudo. Local branch
  `claude/amazing-pasteur-hj7ek5` fast-forwarded to **65370e5** (merged code). Raw log and
  JSON on the Mac: `testlogs/20261023-1424-macos.log`, `testlogs/20261023-1424-sample.jsonl`.
- **Goal:** Task 3 with Photo Booth and Voice Memos opened *during* a 15 s sample; full run
  on the merged code.
- **Code changes:** none (run of 65370e5).
- **Commands run:** `git pull --ff-only origin claude/gifted-pascal-tp5iot`, then
  `scripts/macos_validate.sh`.
- **Result and raw data:**
  - Static: ruff 0, mypy 0, pytest `120 passed, 7 skipped` (cache warning gone).
  - **Task 1:** non-root shows the 3 pf checks as `needs root`. Root: exit 0; after the
    reboot `! pf status: Disabled (enabled automatically on first block)` and
    `anchor com.apple/safemaxxing: not created yet (loads on first block)`.
  - **Task 2c (cold start):**
    ```text
    pfctl -s info                     -> Status: Disabled
    pfctl -a com.apple/safemaxxing -s rules            -> pfctl: DIOCGETRULES: Invalid argument (exit 0)
    pfctl -a ... -t safemaxxing_block -T show          -> pfctl: Table does not exist. (exit 255)
    curl 1.1.1.1 -> 301 (0.109s)
    safemaxxing block 1.1.1.1         -> ok 1 table created.; 1/1 addresses added.
    pfctl -s info                     -> Status: Enabled for 0 days 00:00:00
    curl -> 000 (timeout 3.003s); unblock -> ok 1/1 addresses deleted.; curl -> 301 (0.084s)
    ```
  - **Task 3, sample 15 s, 3755 entries:**
    | subsystem | entries | `<private>` | parsed | w/ pid | sensors |
    |---|---|---|---|---|---|
    | com.apple.TCC | 210 | 21 | 121 | 121 | tcc 53, microphone 41, screen_capture 20, camera 7 |
    | com.apple.cmio | 2436 | 2303 | 32 | 32 | camera 32 (Photo Booth `CMIODeviceStartStream`) |
    | com.apple.controlcenter | 5 | 0 | 4 | 0 | location 2, camera 1, microphone 1 |
    | com.apple.coreaudio | 389 | 0 | 0 | 0 | — |
    | com.apple.locationd | 715 | 371 | 24 | 14 | location 24 |

    PID and processImagePath arrived in clear on every subsystem (`no image path` = `no pid` = 0).
    - TCC: `microphone Photo Booth pid=34389` and `camera Photo Booth pid=34389` from Photo
      Booth's own `SEND` lines. Also `screen_capture pid:34389` from
      `msgID=525.369 ... service=kTCCServiceScreenCapture, target_token={pid:34389}`: process
      525 asks on behalf of Photo Booth, **to be checked**. `photolibraryd`'s `tcc.manager`
      self check was dropped (generic rule ✓). `com.apple.campo` pid 729 `has the
      com.apple.private.tcc.allow entitlement for service kTCCServicePhotos` was parsed as
      tcc (a pre-granted access by a system agent).
    - cmio: `CMIOHardware.cpp:741:CMIODeviceStartStream (35 36)` with Photo Booth's pid ✓,
      plus the `... backtrace N` lines of the same call.
    - Indicator timeline: `[cam:PhotoBooth]` → `[cam, loc:VoiceMemos]` → `[cam]` →
      `[cam, loc:VoiceMemos]` → `[cam, loc:VoiceMemos, mic:VoiceMemos]`. **First real
      `mic:`**; Voice Memos uses location to tag recordings.
    - coreaudio: 389 lines (corespeech, VoiceMemos, coreaudiod), none matches the
      start-IO + input hints, e.g. `[AMCP] ... Voice isolation DSP is available for client
      with bundle id com.apple.PhotoBooth`.
    - locationd: new stop line `{"msg":"stopped receiving location information",
      "client":"root:p\/System\/...CoreParsec.framework:"}`, correctly not an access.
  - **Live suite 7/7 PASSED** (12.97 s). Live sample: indicator
    `[cam:com.apple.PhotoBooth, mic:com.apple.VoiceMemos]` → camera + microphone events.
    Wide predicate 522 entries/s with audio active.
  - **Task 4:** 21 / 35 / 42 ms (cold cache after the reboot); `17.253.144.10: None in 101 ms`
    (cap; < 150 ms).
- **Problems / regressions:** (1) after a reboot pf is disabled and the anchor/table are
  gone, so **blocks don't persist** (expected with the current design, never written
  down); (2) 20 `screen_capture` events for Photo Booth via pid 525 need checking; (3)
  `backtrace` lines inflate the cmio count. No regression vs the previous runs.
- **Next steps:** identify pid 525; decide on reboot persistence.

## [2026-10-22 13:55 +0200] - Fixes from the third Mac run (Linux container)

- **Environment:** Linux 6.18.44 x86_64 cloud container, CPython 3.13.16, uid=0. Static
  checks only.
- **Goal:** act on the 13:51 run.
- **Code changes:**
  - `src/safemaxxing/sensors.py`: `sandboxd` added to `BROKER_PROCESSES`; any TCC line with
    `com.apple.private.tcc.manager` (a daemon's own right to query for others) is dropped.
  - `src/safemaxxing/diagnostics.py`, `cli.py`: `sample` prints each Control Center
    indicator update as `indicator <subsystem>: [kind:bundle, ...]`. A `[]` removal is no
    longer listed as unparsed. Each sensor kind keeps at least one parsed example.
  - `tests/live/test_live_macos.py`: also prints sensors, levels, indicators, parsed examples.
  - `scripts/macos_validate.sh`: Enter first, then open the apps within a 15 s sample; raw
    entries go to `testlogs/<stamp>-sample.jsonl`.
  - Tests: verbatim sandboxd lines, a generic manager line, CoreRoutine "Background
    Session" still attributed, indicator timeline.
- **Commands run:** `uv run ruff check && uv run mypy --strict && uv run pytest -q`
- **Result and raw data:**
  ```text
  All checks passed!
  Success: no issues found in 20 source files
  108 passed, 7 skipped in 2.34s
  ```
- **Problems / regressions:** none.
- **Next steps:** `git pull` then `scripts/macos_validate.sh` (PF_DISABLED_TEST not needed).

## [2026-10-22 13:51 +0200] - Third Mac run: pf auto-enable, non-root doctor, sensors in use

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, uid=501 + sudo, HEAD 5b18f0f
  (pull OK after removing the colliding testlog). Pasted from "Task 1" onward.
- **Goal:** validate the non-root doctor fix and pf Disabled → auto-enable; sample with
  Photo Booth (camera) and Voice Memos (mic).
- **Code changes:** none (run of 5b18f0f).
- **Commands run:** `PF_DISABLED_TEST=1 scripts/macos_validate.sh`; raw log in
  `testlogs/20261022-1351-macos.log` (committed from the Mac on 2026-10-23).
- **Result and raw data:**
  - **Task 1 non-root:** `! pf status / pf parent anchor / anchor com.apple/safemaxxing:
    needs root (/dev/pf: Permission denied)` → **fix confirmed**. Root: exit 0, 31 pids
    incl. `_mdnsresponder`, `_netbios`.
  - **Task 2b:**
    ```text
    $ sudo pfctl -d                       -> pf disabled; Status: Disabled for 0 days 00:00:00
    $ sudo safemaxxing block 1.1.1.1      -> block_ip 1.1.1.1: ok 1/1 addresses added.
    $ sudo pfctl -s info                  -> Status: Enabled for 0 days 00:00:00
    curl 301 (0.042s) -> 000 (timeout 3.001s) -> unblock -> 301 (0.044s)
    ```
    **Automatic re-enable confirmed.**
  - **Task 3 `sample` 8 s** (216 entries):
    - `com.apple.TCC` 65 entries, 9 `<private>`, 41 parsed, all `tcc` (no camera/mic).
      Mostly `sandboxd` pid 401 checking `kTCCServiceSystemPolicyAllFiles` for others →
      **false attribution, fixed in 70fbd74**. `CoreRoutine.helperservice` pid 36094
      correctly attributed.
    - `com.apple.cmio` 8 entries, all from `cameracaptured`, all
      `CMIOExtensionStream _initWithLocalizedName...<private>`: not start events.
    - `com.apple.locationd` 143 entries, 8 parsed (client CoreParsec).
    - **No `com.apple.coreaudio` entries and no indicator lines.** The apps were opened
      *before* Enter, so their start lines were logged before the stream began (script
      flaw, fixed in 70fbd74).
  - **Live sample 5 s** (500 entries, apps open):
    - cmio 344 entries (`registerassistantservice` 207, `Photo Booth` 82,
      `cameracaptured` 23), 252 with `<private>`, **2 parsed with pid** (sensor not
      printed by the old test).
    - TCC 4 entries, 3 parsed (incl. `voicememod`).
    - controlcenter: `[sensor-indicators] Active activity attributions changed to []`, the
      apps being closed. Handled correctly (no new attribution), but listed as "unparsed".
  - **Task 4:** DNS 1-3 ms (warm cache); `17.253.144.10` → `www.brkgls.com` in 90 ms
    (< 100 ms cap).
  - Live suite **7/7 PASSED** in 12.75 s.
- **Redaction (Task 3):** on every subsystem `no image path` = 0 and `no pid` = 0, so PID
  and processImagePath arrive in clear. `<private>` appears only inside messages: cmio
  73% (252/344), locationd ~25%, TCC 14% (9/65). Bundle IDs in TCC `TCCDProcess` blocks
  are in clear.
- **Problems / regressions vs Linux:** (1) sandboxd false positives (fixed); (2) camera/mic
  start not captured, a procedure problem (fixed); (3) no coreaudio lines while recording:
  the mic depends on the `mic:` indicator, still to be observed.
- **Next steps:** re-run the sample with the apps opened *during* the 15 s.

## [2026-10-22 13:50 +0200] - Second Mac run: STALE code (pull aborted)

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4, uid=501 + sudo. Local branch
  `claude/amazing-pasteur-hj7ek5` still at **c895276**.
- **Goal:** validate 34c9f53 (non-root doctor), pf Disabled → auto-enable
  (`PF_DISABLED_TEST=1`), and the sample with camera and mic active.
- **Code changes:** none (the pull did not apply).
- **Commands run:**
  ```sh
  git pull origin claude/gifted-pascal-tp5iot
  PF_DISABLED_TEST=1 scripts/macos_validate.sh
  ```
- **Result and raw data:**
  ```text
  error: The following untracked working tree files would be overwritten by merge:
          testlogs/20261022-1345-macos.log
  Aborting
  ```
  The script ran anyway at c895276, the old version: no pause before the sample, no
  `PF_DISABLED_TEST`, doctor still says "parent anchor missing" without sudo, and the
  `.pytest_cache` warning is still there. The results repeat the 13:45 run:
  - doctor (root) exit 0, 30 pids incl. `_mdnsresponder`, `_netbios`; snapshot 8-9 ms.
  - Block of 1.1.1.1: `301` → `000` (timeout 3.007 s) → `301`. pf was already Enabled
    (for 37 min).
  - Sample 8 s: 111 locationd entries, 33 with `<private>`, 0 without image path or pid.
    New client parsed correctly: `CoreParsec`
    (`root:com.apple.locationd.bundle-/System/Library/PrivateFrameworks/CoreParsec.framework`).
    No camera or mic activity.
  - DNS: every answer in 1-3 ms (mDNSResponder cache, warm after the previous run;
    9.9.9.9 now resolves to `dns9.quad9.net`).
  - Live suite 7/7 PASSED in 12.51 s.
  - Raw log: `testlogs/20261022-1350-macos.log` (committed from the Mac on 2026-10-23).
- **Problems / regressions:** no code regression. Process problem: committing from the
  container a log that the script also creates on the Mac makes `git pull` fail. From now on
  `testlogs/` is committed **only from the Mac**.
- **Next steps:** on the Mac:
  ```sh
  rm testlogs/20261022-1345-macos.log   # identical copy is already in the repo
  git pull origin claude/gifted-pascal-tp5iot
  git log --oneline -1                  # must show 44b98e0 or later
  PF_DISABLED_TEST=1 scripts/macos_validate.sh
  ```

## [2026-10-22 13:50 +0200] - Fixes from the first Mac run (Linux container)

- **Environment:** Linux 6.18.44 x86_64 cloud container, CPython 3.13.16, uid=0. Static
  checks only; nothing native was re-run.
- **Goal:** fix the anomalies seen in the 13:45 Mac run.
- **Code changes:**
  - `src/safemaxxing/diagnostics.py`: when `pfctl` returns `/dev/pf: Permission denied`,
    `pf status`, `pf parent anchor` and `anchor com.apple/safemaxxing` are now WARN
    "needs root". Before, the parent check wrongly said the anchor was missing and told the
    user to run `pfctl -f /etc/pf.conf`. The exit code stays 1 because root still FAILs.
  - `tests/test_diagnostics.py`: test with the real non-root output.
  - `tests/test_sensors.py`: the two new verbatim noise lines (cmio `setting <private> :
    <private>`, Geotagging `near-owner`) must not become events.
  - `scripts/macos_validate.sh`: `chown` an existing root-owned `.pytest_cache`;
    `-p no:cacheprovider` for `sudo pytest`; waits for Enter so camera/mic can be opened
    before the sample; opt-in `PF_DISABLED_TEST=1` for the Disabled → Enabled path.
  - `testlogs/20261022-1345-macos.log`: raw log of the Mac run, verbatim.
- **Commands run:**
  ```sh
  uv run ruff check && uv run mypy --strict && uv run pytest -q
  ```
- **Result and raw data:**
  ```text
  All checks passed!
  Success: no issues found in 20 source files
  104 passed, 7 skipped in 2.41s
  ```
- **Problems / regressions:** none.
- **Next steps:** on the Mac, `git pull`, then `PF_DISABLED_TEST=1 scripts/macos_validate.sh`.
  Open Photo Booth and Voice Memos at the prompt.

## [2026-10-22 13:45 +0200] - First real Mac run: Tasks 1-4 (macOS 27.0.1, Apple M4)

- **Environment:** macOS 27.0.1 (26A434), arm64 Apple M4 (Apple Silicon), user `carlo`
  uid=501 (admin), root steps via sudo; Python 3.13.14, uv from Homebrew. Local branch
  `claude/amazing-pasteur-hj7ek5` at c895276.
- **Goal:** validate native calls: doctor, pf block in the kernel, `log stream` redaction,
  real reverse DNS.
- **Code changes:** none (run of c895276).
- **Commands run:** `scripts/macos_validate.sh` (full list and output in
  `testlogs/20261022-1345-macos.log`).
- **Result and raw data:**
  - Static: ruff 0, mypy 0 (20 files), pytest `103 passed, 7 skipped, 1 warning`.
  - **Task 1** `sudo safemaxxing doctor`: exit 0, every check OK except
    `Full Disk Access: not granted` (WARN). pf `Enabled`; anchor holds
    `block drop out quick from any to <safemaxxing_block>`; `foreign sockets: 32 pids visible
    incl. daemons _mdnsresponder, _netbios, _trustd`; `socket snapshot: 8 ms per poll`.
  - **Task 2** live block of 1.1.1.1:
    ```text
    before   curl https://1.1.1.1/  -> 301 in 0.057s
    block    block_ip 1.1.1.1: ok 1/1 addresses added.   (-T show: 1.1.1.1)
    blocked  curl -> curl: (28) Connection timed out after 3006 ms -> 000
    unblock  unblock_ip 1.1.1.1: ok 1/1 addresses deleted. (-T show: empty)
    after    curl -> 301 in 0.044s
    ```
    `pfctl -a com.apple/safemaxxing -s rules` and `-T show` print only the usual ALTQ notice.
    The live tests for new and already-open connections PASSED.
  - **Task 3** sample 8 s: 146 entries (cmio 2, locationd 144). `no image path` = 0 and
    `no pid` = 0, so **PID and processImagePath arrive in clear**. `<private>` affects only
    message fields (cmio 2/2, locationd 44/144: Geotagging `address`, `data`, `rssi`...).
    Parsed: 2 locationd events `markReceivingLocationInformation` for the client FindMyDevice
    (`root:com.apple.locationd.bundle-/System/Library/PrivateFrameworks/FindMyDevice.framework`).
    The unparsed lines are noise (cmio RegisterAssistantService, Geotagging BLE), so dropping
    them is correct. Wide predicate: 0 entries in 1 s (accepted by `log`).
  - **Task 4** reverse DNS with a 100 ms timeout:
    ```text
    1.1.1.1: 'one.one.one.one' in 74 ms    8.8.8.8: 'dns.google' in 10 ms
    9.9.9.9: None in 100 ms (cap hit)      17.253.144.10: 'icloud.com' in 83 ms
    192.0.2.1 / 203.0.113.7: None in 0 ms (non-global, never sent)
    ```
  - Live suite: **7 passed** in 12.80 s.
- **Problems / regressions vs Linux:**
  1. Non-root `doctor` printed `✘ pf parent anchor: ... missing ... sudo pfctl -f /etc/pf.conf`.
     That is false: the real cause is `/dev/pf: Permission denied`. Fixed in 34c9f53.
  2. `PytestCacheWarning: Permission denied .pytest_cache`: an earlier `sudo pytest` left
     the cache owned by root. One-off fix: `sudo chown -R "$USER" .pytest_cache`; the script
     now avoids it.
  3. No camera or mic was in use during the sample, so the TCC, cmio and coreaudio parsers
     were **not** exercised with real accesses.
  4. pf was already Enabled (for 32 min), so the automatic `pfctl -E` path was not
     exercised.
- **Next steps:** re-run with the camera and mic active, and with `PF_DISABLED_TEST=1`.

## [2026-10-22 11:43 UTC] - Baseline + Task 1-4 preparation (Linux container, NOT the Mac)

- **Environment:** Linux 6.18.44 x86_64 (Claude Code cloud container), CPython 3.13.16,
  uv 0.11.32, uid=0 (root). **Not Darwin:** no `pfctl`, `log`, real `lsof` or TCC, so nothing
  here validates native macOS calls. The live suite is skipped automatically.
- **Goal:** record the static baseline on branch `claude/gifted-pascal-tp5iot` @32c1b74, close
  the gaps found in Tasks 1-4, and prepare a one-shot script for the real Mac.
  (The branch `claude/amazing-pasteur-hj7ek5` named in the brief does not exist on the remote;
  its history is in this branch.)
- **Code changes:**
  - `src/safemaxxing/diagnostics.py`: `check_socket_visibility` FAILs if lsof is missing or
    prints nothing, accepts lsof exit 1 with output (unreadable fds), and is OK only when
    `root`/`_daemon` sockets are visible. Visibility depends on root, not Full Disk Access;
    FDA keeps its own probe (reading the system `TCC.db`).
  - `tests/test_diagnostics.py`: new test for daemons, users-only and lsof-missing cases.
  - `tests/live/test_live_macos.py`: `test_reverse_dns_never_exceeds_timeout_on_real_resolver`
    (each `resolve()` < 150 ms with a 100 ms timeout).
  - `scripts/macos_validate.sh`: collects all evidence for Tasks 1-4 into `testlogs/`.
- **Audit of existing code against the brief (no change needed):**
  - Task 1: `doctor` already checks euid 0, `pfctl -s info` Enabled/Disabled, parent anchor,
    our anchor, FDA, snapshot latency and the `log` predicate.
  - Task 2: `PfFirewall._enable` already runs `pfctl -E`, then `-e`; a missing anchor/table
    is treated as empty; the anchor has no `table` definition, so reloads don't reset it.
  - Task 4: `HostnameResolver` uses a dedicated 4-thread pool with a 100 ms timeout, and the
    poll loop only calls `prefetch`. Covered by `test_poller_not_blocked_by_hung_dns`.
- **Commands run:**
  ```sh
  uv run ruff check
  uv run mypy --strict
  uv run pytest -q
  ```
- **Result and raw data:**
  ```text
  # baseline @32c1b74
  All checks passed!
  Success: no issues found in 20 source files
  102 passed, 6 skipped in 2.81s

  # after changes @9421e63
  All checks passed!
  Success: no issues found in 20 source files
  103 passed, 7 skipped in 2.09s
  ```
  The 7 skipped tests are the `live` suite (`needs macOS, root and SAFEMAXXING_LIVE=1`).
- **Problems / regressions:** none on Linux. The brief expects 41 tests; the suite has 103.
  Tasks 2 (kernel block), 3 (`<private>` on the current macOS) and 4 (real resolver) are
  **not yet validated**: they need the Mac.
- **Next steps:** on the Mac, from the repo root:
  ```sh
  git pull origin claude/gifted-pascal-tp5iot
  scripts/macos_validate.sh          # optional: SAFEMAXXING_LIVE_IP=9.9.9.9 SAMPLE_S=10
  ```
  Paste the key parts of `testlogs/<stamp>-macos.log` into a new section above. Add any
  unparsed log lines to `tests/test_sensors.py` as verbatim fixtures before changing parsers.
