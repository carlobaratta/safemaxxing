# Architecture

safemaxxing watches two things macOS already reports and asks whether one caused the other: a
process accessed a sensor (camera, microphone, screen, location) and then, within a short
window, opened an outbound connection. The sensor side is read from the unified log; the egress
side from the socket table and, for connection-less UDP, from per-packet metadata. A
correlation engine links them and raises an alert that the TUI, the headless `watch` command or
the automatic responses act on.

The core is pure and OS-agnostic; everything that touches macOS is reached through an injected
seam, so the whole pipeline is driven by fixtures on Linux CI and by real subprocesses on a Mac.

## Modules

| Module | Role |
| --- | --- |
| `sensors.py` | `SensorListener`: runs `log stream --style json`, parses TCC / Control Center / CoreAudio / CoreMediaIO / locationd entries into `Event`s. |
| `network.py` | `NetworkMonitor`: polls the socket table (psutil, falling back to `lsof`) and yields each new outbound `NetworkConnection`. |
| `pktap.py` | `PktapCapture`: runs `tcpdump -k` on a pktap interface and turns the first outbound packet of a UDP flow into a `NetworkConnection`. |
| `correlation.py` | `CorrelationEngine`: buffers events and connections and matches them by actor and time window. |
| `supervisor.py` | `Supervisor`: merges the sources into one `stream()` of events, connections and alerts. |
| `firewall.py` | `PfFirewall` (pf block table) and `ProcessController` (SIGSTOP / SIGCONT / SIGKILL). |
| `models.py` | The immutable `Event`, `NetworkConnection`, `Finding`, `Alert` and the `Severity` scale. |
| `tui/` | The Textual dashboard. |

## A Meet call in Brave, intercepted via pktap

Google Meet in Brave sends its media over UDP that is never `connect()`-ed, so the socket table
shows no peer and only pktap sees where it goes. The sensor access is logged first; the media
flow follows within the correlation window (default 2000 ms; observed deltas are tens to a few
hundred milliseconds — the timings below are illustrative).

```mermaid
sequenceDiagram
    autonumber
    participant App as Brave (app + helpers)
    participant Log as log stream (SensorListener)
    participant Pk as pktap/tcpdump (PktapCapture)
    participant Eng as CorrelationEngine
    participant Out as TUI / watch

    Note over App: user joins a Meet call
    App->>Log: camera & microphone access<br/>(TCC + Control Center), t = 0 ms
    Log->>Eng: ingest_event(camera)
    Log->>Eng: ingest_event(microphone)
    Note over Eng: events buffered,<br/>awaiting egress within the window
    App->>Pk: first outbound UDP media packet<br/>(no peer in the socket table)
    Pk->>Eng: ingest_connection(flow), t ~ +188 ms
    Eng->>Eng: same actor? within window?<br/>sensors = {camera, microphone}
    Eng->>Out: Alert #1 [critical]<br/>camera+microphone to peer:port
    Note over Out: b to block the IP (pfctl),<br/>s to SIGSTOP the process
```

## Dependency injection: Linux CI vs. macOS live

Each source and action takes its macOS-specific backend as a constructor argument. In production
those default to real subprocesses and syscalls; in tests they are replaced with deterministic
fakes, so the same engine and supervisor run unchanged on a Linux runner.

```mermaid
flowchart TB
    subgraph core["Core — pure, OS-agnostic"]
        sup["Supervisor.stream()"]
        eng["CorrelationEngine (clock, window)"]
    end
    subgraph sources["Observation sources — injected seams"]
        sl["SensorListener (command, process_lookup)"]
        nm["NetworkMonitor (snapshot)"]
        pk["PktapCapture (command, tracker)"]
    end
    subgraph actions["Actions — injected seams"]
        pf["PfFirewall (runner)"]
        pc["ProcessController (kill)"]
    end

    sl --> sup
    nm --> sup
    pk --> sup
    sup --> eng
    eng --> pf
    eng --> pc

    subgraph live["macOS live (defaults)"]
        l1["log stream subprocess"]
        l2["psutil / lsof"]
        l3["tcpdump -k (pktap)"]
        l4["pfctl / os.kill"]
    end
    subgraph ci["Linux CI (fakes)"]
        c1["fixture log lines"]
        c2["fake Snapshot callable"]
        c3["fixture pktap lines"]
        c4["fake runner / kill"]
    end

    l1 -. default .-> sl
    c1 -. test .-> sl
    l2 -. default .-> nm
    c2 -. test .-> nm
    l3 -. default .-> pk
    c3 -. test .-> pk
    l4 -. default .-> pf
    l4 -. default .-> pc
    c4 -. test .-> pf
    c4 -. test .-> pc
```

## Severity escalation

An alert's severity starts from the base level of the sensor behind it — medium for a generic
TCC service, high for camera, microphone, screen capture or location — and rises one step, up to
critical, when a second distinct sensor is attributed to the same connection. Each further
sensor re-emits the same alert (same id) at the new, higher level, capped at critical.

```mermaid
stateDiagram-v2
    [*] --> buffered: sensor event ingested
    buffered --> [*]: no egress within the window
    buffered --> medium: egress correlated — single<br/>generic-TCC access
    buffered --> high: egress correlated — single camera /<br/>microphone / screen / location access
    medium --> critical: another distinct sensor<br/>matches the same connection
    high --> critical: another distinct sensor<br/>matches the same connection
    critical --> critical: further sensors (capped at critical)
```

## Why the core stays pure

The `CorrelationEngine` takes a `clock` and holds only immutable `Event` / `NetworkConnection`
values, so a test drives it to the millisecond with a fixed clock and hand-built inputs. The
sources normalise their platform-specific input into those same values before the engine sees
them, which is why the engine never imports `psutil`, `subprocess` or anything macOS-specific —
and why the heuristics can be tested without a Mac.
