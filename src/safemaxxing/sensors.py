"""Unified-log sensors: turn `log stream --style json` output into `Event`s."""

from __future__ import annotations

import asyncio
import codecs
import contextlib
import dataclasses
import json
import re
import time
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from datetime import datetime
from pathlib import PurePosixPath

import psutil

from safemaxxing.models import Event, SensorType, is_system_path
from safemaxxing.network import bundle_id_for_app, bundle_id_for_exe, enclosing_apps

ProcessInfo = Callable[[int], tuple[str, str | None] | None]
BundleExes = Callable[[str], list[str]]

LOG_BINARY = "/usr/bin/log"

SUBSYSTEM_TCC = "com.apple.TCC"
SUBSYSTEM_LOCATION = "com.apple.locationd"
SUBSYSTEM_AUDIO = "com.apple.coreaudio"
SUBSYSTEM_CMIO = "com.apple.cmio"
SUBSYSTEM_CONTROLCENTER = "com.apple.controlcenter"
INDICATOR_CATEGORY = "sensor-indicators"
INDICATOR_PREFIX = "Active activity attributions changed to"

# Daemons that log on behalf of clients: their own PID is never the culprit.
BROKER_PROCESSES = frozenset(
    {
        "tccd",
        "locationd",
        "coreaudiod",
        "VDCAssistant",
        "AppleCameraAssistant",
        "appleh13camerad",
        "UVCAssistant",
        "cameracaptured",
        "avconferenced",
        "audiomxd",
        "com.apple.cmio.registerassistantservice",
        "ControlCenter",
        # Checks TCC for sandboxed processes (seen on macOS 27.0.1 with kTCCServiceSystemPolicy*).
        "sandboxd",
        # Checks Calendar/Reminders TCC for EventKit clients (macOS 27.0.1: for routined).
        "calaccessd",
        # Checks ScreenCapture for ScreenCaptureKit clients (macOS 27.0.1: Brave, screencapture).
        "replayd",
    }
)

TCC_SERVICE_MAP: Mapping[str, SensorType] = {
    "Camera": SensorType.CAMERA,
    "Microphone": SensorType.MICROPHONE,
    "ScreenCapture": SensorType.SCREEN_CAPTURE,
}

CAMERA_HINTS = ("startstream", "start stream", "isrunningsomewhere", "startrunning", "camera on")
AUDIO_START_HINTS = ("startio", "start io", "starting io", "isrunningsomewhere", "startrunning")
AUDIO_INPUT_HINTS = ("input", "mic", "record")
LOCATION_HINTS = (
    "startupdatinglocation",
    "requestlocation",
    "location sent",
    "didupdatelocations",
    "client authorized",
    "markreceivinglocationinformation",
)

# Unified logging redacts dynamic strings unless private data is enabled on the host.
REDACTED_RE = re.compile(r"<private>|<mask\.[^>]*>")
_REDACTABLE = r"(<private>|<mask\.[^>]*>|[\w.\-]+)"


def _mentions_any(hints: Sequence[str]) -> str:
    return "(" + " OR ".join(f'eventMessage CONTAINS[c] "{h}"' for h in hints) + ")"


_TCC_CLAUSE = f'(subsystem == "{SUBSYSTEM_TCC}" AND eventMessage CONTAINS "kTCCService")'
# The menu-bar privacy indicator's own attribution list (macOS 27: Default level).
_INDICATOR_CLAUSE = (
    f'(subsystem == "{SUBSYSTEM_CONTROLCENTER}" AND category == "{INDICATOR_CATEGORY}"'
    f' AND eventMessage BEGINSWITH "{INDICATOR_PREFIX}")'
)

# Runtime predicate: `log` drops the bulk of locationd/cmio chatter before it reaches Python.
PREDICATE = (
    f"{_TCC_CLAUSE} OR {_INDICATOR_CLAUSE}"
    f' OR (subsystem BEGINSWITH "{SUBSYSTEM_LOCATION}" AND {_mentions_any(LOCATION_HINTS)})'
    f' OR (subsystem BEGINSWITH "{SUBSYSTEM_AUDIO}" AND {_mentions_any(AUDIO_START_HINTS)})'
    f' OR (subsystem BEGINSWITH "{SUBSYSTEM_CMIO}" AND {_mentions_any(CAMERA_HINTS)})'
)

# Everything from the watched subsystems, for `safemaxxing sample` format discovery.
DISCOVERY_PREDICATE = (
    f"{_TCC_CLAUSE} OR {_INDICATOR_CLAUSE}"
    f' OR subsystem BEGINSWITH "{SUBSYSTEM_LOCATION}"'
    f' OR subsystem BEGINSWITH "{SUBSYSTEM_AUDIO}"'
    f' OR subsystem BEGINSWITH "{SUBSYSTEM_CMIO}"'
)

# Keyword search across *all* subsystems, to find where a macOS release logs sensor use.
# locationd is excluded: it is located already and floods the sample (~100 lines/s).
WIDE_DISCOVERY_PREDICATE = (
    '(process == "tccd" OR subsystem CONTAINS[c] "tcc" OR subsystem CONTAINS[c] "cmio"'
    ' OR subsystem CONTAINS[c] "audio" OR subsystem CONTAINS[c] "camera"'
    ' OR subsystem CONTAINS[c] "avfoundation" OR subsystem CONTAINS[c] "controlcenter"'
    ' OR process == "ControlCenter" OR eventMessage CONTAINS[c] "kTCCService"'
    ' OR eventMessage CONTAINS[c] "camera" OR eventMessage CONTAINS[c] "microphone")'
    f' AND NOT subsystem BEGINSWITH "{SUBSYSTEM_LOCATION}"'
)

_TCC_SERVICE_RE = re.compile(r"kTCCService(\w+)")
# "<TCCDProcess: identifier=X, pid=N> has the com.apple.private.tcc.manager... entitlement": a
# daemon (coreaudiod, sandboxd, ...) checking its right to query TCC for others, never an access.
_TCC_MANAGER_ENTITLEMENT = "com.apple.private.tcc.manager"
_ACCESSING_RE = re.compile(r"accessing=\{([^}]*)\}")
_TCC_IDENTITY_RES = (
    re.compile(rf"\bsubject={_REDACTABLE}"),
    re.compile(rf"Sub:\{{{_REDACTABLE}\}}"),
)
# One process description, e.g. "<TCCDProcess: identifier=com.apple.VoiceMemos, pid=34661>".
# identifier and pid are always read from the same block so they cannot describe two processes.
# Redaction tokens (<private>, <mask.hash: ...>) are consumed whole so their ">" does not end
# the block early.
_TCCD_PROCESS_RE = re.compile(r"TCCDProcess:\s*((?:<[^>]*>|[^}>])*)")
_BLOCK_IDENTIFIER_RE = re.compile(rf"\bidentifier={_REDACTABLE}")
_BLOCK_PID_RE = re.compile(r"\bpid=(\d+)")
_BLOCK_BINARY_RE = re.compile(r"\bbinary_path=([^,}>]+)")
# Requests a broker makes on behalf of a client name the client here. (msgID is deliberately
# not used: its prefix is the *sender*, i.e. the broker for coreaudiod/cameracaptured requests.)
_TCC_PID_RES = (
    re.compile(r"\btarget_token=\{pid:(\d+)"),
    re.compile(r"\bsender_pid=(\d+)"),
)
# replayd's ScreenCapture requests name the client only here, in tccd's REQUEST_MSG.
_SUBJECT_AUDIT_PID_RE = re.compile(
    r"\bTCCD_MSG_CREDENTIAL_AUTHENTICATOR_AUDIT_TOKEN_KEY=\{pid:(\d+)"
)
_PID_RE = re.compile(r"\bpid[\s:=]+(\d+)", re.IGNORECASE)
_BUNDLE_RE = re.compile(
    r"(?:bundle_?id|client(?:key)?)[\"'\s:=]+\"?([A-Za-z0-9][\w\-]*(?:\.[\w\-]+)+)", re.IGNORECASE
)


class JsonStreamDecoder:
    """Incrementally extracts top-level objects from a (possibly unterminated) JSON array."""

    def __init__(self, max_buffer: int = 4 * 1024 * 1024) -> None:
        self._buffer = ""
        self._decoder = json.JSONDecoder()
        self._max_buffer = max_buffer

    def feed(self, chunk: str) -> list[dict[str, object]]:
        self._buffer += chunk
        out: list[dict[str, object]] = []
        # Walk a read offset and slice the buffer once at the end, rather than re-slicing (and
        # re-scanning from zero) per object: under a burst of thousands of entries that keeps
        # the pass linear instead of quadratic in the buffer length.
        pos = 0
        while True:
            start = self._buffer.find("{", pos)
            if start < 0:
                pos = len(self._buffer)
                break
            try:
                value, end = self._decoder.raw_decode(self._buffer, start)
            except json.JSONDecodeError:
                # A partial object at the tail: keep it for the next chunk. If it has grown past
                # the cap it is not valid JSON we will ever complete, so skip one char to resync.
                if len(self._buffer) - start > self._max_buffer:
                    pos = start + 1
                    continue
                pos = start
                break
            pos = end
            if isinstance(value, dict):
                out.append(value)
        self._buffer = self._buffer[pos:]
        return out


def _str(entry: Mapping[str, object], key: str) -> str:
    value = entry.get(key)
    return value if isinstance(value, str) else ""


def _int(entry: Mapping[str, object], key: str) -> int | None:
    value = entry.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def parse_timestamp(raw: str) -> float:
    for fmt in ("%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z"):
        try:
            return datetime.strptime(raw, fmt).timestamp()
        except ValueError:
            continue
    return time.time()


def unredacted(value: str | None) -> str | None:
    if not value or value == "(null)" or REDACTED_RE.fullmatch(value):
        return None
    return value


def _first(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return unredacted(match.group(1)) if match else None


_LOCATION_CLIENT_RE = re.compile(r'"Client"\s*:\s*"(?:[\w\-]+:)?([^"]+)"')
_LOCATION_BUNDLE_PATH_PREFIX = "com.apple.locationd.bundle-"


def _location_client(message: str) -> tuple[str | None, str, bool] | None:
    """Parse locationd's `"Client"` into (bundle id, name, is system).

    Seen on macOS 27: "<user>:<bundle id>", "i<bundle id>:", "e<executable>:",
    "p<plugin path>[:p<path>...]" and "<user>:com.apple.locationd.bundle-<path>".
    """
    match = _LOCATION_CLIENT_RE.search(message)
    value = unredacted(match.group(1)) if match else None
    if value is None:
        return None
    value = value.replace("\\/", "/")
    if value.startswith(_LOCATION_BUNDLE_PATH_PREFIX):
        path = value.removeprefix(_LOCATION_BUNDLE_PATH_PREFIX)
    elif value[0] in "ep" and value[1:2] == "/":
        path = value[1:].split(":", 1)[0]
    elif value[0] == "i" and value.endswith(":") and len(value) > 2:
        return value[1:-1], "", False
    else:
        return value, "", False
    return None, PurePosixPath(path).stem, is_system_path(path)


def _contains_any(text: str, hints: Sequence[str]) -> bool:
    return any(h in text for h in hints)


def _attribute(
    message: str, log_pid: int | None, process_name: str
) -> tuple[int | None, str | None]:
    pid_match = _PID_RE.search(message)
    bundle_match = _BUNDLE_RE.search(message)
    pid = int(pid_match.group(1)) if pid_match else None
    bundle = bundle_match.group(1) if bundle_match else None
    if pid is None and process_name not in BROKER_PROCESSES:
        pid = log_pid
    return pid, bundle


def _tcc_actor(message: str, client_pid: int | None) -> tuple[int | None, str | None, str | None]:
    """Return (pid, bundle id, binary path) of the process using the resource."""
    # The `accessing` process is the one using the resource; prefer it over requester/sender.
    accessing = _ACCESSING_RE.search(message)
    if block := _TCCD_PROCESS_RE.search(accessing.group(1) if accessing else message):
        text = block.group(1)
        raw_pid = _first(_BLOCK_PID_RE, text)
        binary = _first(_BLOCK_BINARY_RE, text)
        return (int(raw_pid) if raw_pid else None), _first(_BLOCK_IDENTIFIER_RE, text), binary
    pid = next((int(p) for r in _TCC_PID_RES if (p := _first(r, message))), None)
    bundle = next((b for r in _TCC_IDENTITY_RES if (b := _first(r, message))), None)
    if pid is None and bundle is None:
        # Client-side libTCC lines ("SEND: ... service=kTCCServiceCamera") are logged by the
        # requesting app itself, so the entry's own PID identifies it.
        pid = client_pid
    return pid, bundle, None


def _screen_capture_subject(message: str) -> int | None:
    """Pid of the client a ScreenCapture request is made for, from its subject audit token.

    replayd sends these for ScreenCaptureKit clients (Brave sharing a window, `screencapture`
    recording); WindowServer sends one when it checks replayd itself (macOS 27.0.1).
    """
    if "kTCCServiceScreenCapture" not in message:
        return None
    subject = _first(_SUBJECT_AUDIT_PID_RE, message)
    return int(subject) if subject else None


def _classify_tcc(
    message: str, client_pid: int | None
) -> tuple[SensorType, str, int | None, str | None, bool] | None:
    service_match = _TCC_SERVICE_RE.search(message)
    if not service_match or _TCC_MANAGER_ENTITLEMENT in message:
        return None
    service = service_match.group(1)
    sensor = TCC_SERVICE_MAP.get(service, SensorType.TCC)
    if sensor is SensorType.SCREEN_CAPTURE and (subject := _screen_capture_subject(message)):
        return sensor, service, subject, None, False
    pid, bundle, binary = _tcc_actor(message, client_pid)
    # e.g. "identifier=com.apple.audio.coreaudiod ... entitlement for service kTCCServiceMicrophone"
    # is the daemon's own check on behalf of a client, reported separately via target_token.
    if bundle is not None and bundle.rsplit(".", 1)[-1] in BROKER_PROCESSES:
        return None
    if pid is None and bundle is None:
        return None
    return sensor, service, pid, bundle, is_system_path(binary)


def parse_entry(entry: Mapping[str, object]) -> Event | None:
    """Classify a single unified-log entry; returns None when it is not a sensor access."""
    subsystem = _str(entry, "subsystem")
    message = _str(entry, "eventMessage")
    if not subsystem or not message:
        return None
    image_path = unredacted(_str(entry, "processImagePath"))
    process_name = PurePosixPath(image_path).name if image_path else ""
    log_pid = _int(entry, "processID")
    timestamp = parse_timestamp(_str(entry, "timestamp"))
    lowered = message.lower()

    sensor: SensorType
    service: str | None = None
    system = False
    if subsystem == SUBSYSTEM_TCC:
        client_pid = None if process_name in BROKER_PROCESSES else log_pid
        classified = _classify_tcc(message, client_pid)
        if classified is None:
            return None
        sensor, service, pid, bundle, system = classified
        # WindowServer and coreaudiod preflight ScreenCapture for every app that opens a window or
        # audio, and tccd echoes each request (macOS 27.0.1: Photo Booth, Voice Memos, ring light).
        # Only a request logged by the capturing process itself counts as a screen capture, or
        # one whose subject audit token names it (replayd asking for a ScreenCaptureKit client).
        if (
            sensor is SensorType.SCREEN_CAPTURE
            and (pid is None or pid != log_pid)
            and _screen_capture_subject(message) is None
        ):
            return None
        # A request is a permission check, not use: apps send them for the camera, microphone
        # and screen while they start (Spotify and Claude at login, macOS 27). Use is what the
        # privacy indicator (or a cmio stream start) shows, 50-400 ms after the request.
        sensor = SensorType.TCC
    elif subsystem.startswith(SUBSYSTEM_CMIO):
        # "CMIODeviceStartStream backtrace N ..." dumps the stack of the start line before it:
        # 30-50 lines per camera start on macOS 27.0.1, none of them a new start.
        if not _contains_any(lowered, CAMERA_HINTS) or "backtrace" in lowered:
            return None
        sensor = SensorType.CAMERA
        pid, bundle = _attribute(message, log_pid, process_name)
    elif subsystem.startswith(SUBSYSTEM_AUDIO):
        if not (
            _contains_any(lowered, AUDIO_START_HINTS) and _contains_any(lowered, AUDIO_INPUT_HINTS)
        ):
            return None
        sensor = SensorType.MICROPHONE
        pid, bundle = _attribute(message, log_pid, process_name)
    elif subsystem.startswith(SUBSYSTEM_LOCATION):
        if not _contains_any(lowered, LOCATION_HINTS):
            return None
        sensor = SensorType.LOCATION
        pid, bundle = _attribute(message, log_pid, process_name)
        if client := _location_client(message):
            bundle, process_name, system = client
    else:
        return None

    if pid is not None and pid == log_pid and is_system_path(image_path):
        system = True
    # The logging process is not the actor when the message names a different pid.
    if process_name in BROKER_PROCESSES or (pid is not None and log_pid not in (None, pid)):
        process_name = ""
    if pid is None and bundle is None and not process_name:
        return None
    return Event(
        timestamp=timestamp,
        sensor=sensor,
        pid=pid,
        process_name=process_name,
        bundle_id=bundle,
        subsystem=subsystem,
        message=message,
        service=service,
        system=system,
    )


class SensorError(RuntimeError):
    pass


async def _drain_tail(stream: asyncio.StreamReader, keep: int = 4096) -> bytes:
    """Read a pipe to EOF so the child never blocks on it, keeping only the tail."""
    tail = b""
    while chunk := await stream.read(65536):
        tail = (tail + chunk)[-keep:]
    return tail


# All four observed on macOS 27.0.1: Photo Booth, Voice Memos, Cmd+Shift+5 (scr:systemuiserver).
INDICATOR_SENSORS: Mapping[str, SensorType] = {
    "cam": SensorType.CAMERA,
    "mic": SensorType.MICROPHONE,
    "loc": SensorType.LOCATION,
    "scr": SensorType.SCREEN_CAPTURE,
}
_ATTRIBUTION_RE = re.compile(r'"(\w+):([^"]+)"')
# An attribution back within this long after going off is the same use flickering (macOS 27.0.1:
# a 24 ms gap before a Cmd+Shift+5 recording, gaps up to 0.884 s while Brave shares a window).
INDICATOR_MERGE_S = 2.0


def parse_attributions(message: str) -> frozenset[tuple[str, str]] | None:
    """`Active activity attributions changed to ["cam:com.apple.PhotoBooth"]` -> {(cam, id)}."""
    if not message.startswith(INDICATOR_PREFIX):
        return None
    return frozenset(_ATTRIBUTION_RE.findall(message[len(INDICATOR_PREFIX) :]))


class SensorEventParser:
    """Stateful wrapper around `parse_entry`: indicator lines carry the full active set, so an
    event is emitted only for attributions that were not active in the previous update.

    It also drops coreaudiod's TCC *preflights*. Only tccd's REQUEST_MSG says `preflight=true`,
    but every line of one request shares its activityIdentifier (macOS 27.0.1)."""

    def __init__(self, max_requests: int = 1024, merge_s: float = INDICATOR_MERGE_S) -> None:
        self._active: frozenset[tuple[str, str]] = frozenset()
        # Attributions that went off, and when: one coming back within `merge_s` is not new.
        self._off_since: dict[tuple[str, str], float] = {}
        self._merge_s = merge_s
        # activityIdentifier of a coreaudiod request -> whether tccd said it is a preflight.
        self._requests: dict[int, bool] = {}
        self._max_requests = max_requests

    def parse(self, entry: Mapping[str, object]) -> list[Event]:
        subsystem = _str(entry, "subsystem")
        if subsystem == SUBSYSTEM_CONTROLCENTER:
            return self._indicator(entry)
        if subsystem == SUBSYSTEM_TCC and self._in_broker_preflight(entry):
            return []
        event = parse_entry(entry)
        return [] if event is None else [event]

    def _in_broker_preflight(self, entry: Mapping[str, object]) -> bool:
        """Whether `entry` belongs to a coreaudiod request that is only a preflight, i.e. a
        check made when an app opens audio, not mic use (2026-10-24 screencapture, 2026-10-26
        Brave: no `mic:` indicator). coreaudiod's own SEND is held back until tccd decides."""
        activity = _int(entry, "activityIdentifier")
        if not activity:
            return False
        message = _str(entry, "eventMessage")
        if PurePosixPath(_str(entry, "processImagePath")).name == "coreaudiod":
            if message.startswith("SEND:"):
                if len(self._requests) >= self._max_requests:
                    del self._requests[next(iter(self._requests))]
                self._requests[activity] = False
                return True
            return False
        preflight = self._requests.get(activity)
        if preflight is None:
            return False
        if message.startswith("REQUEST_MSG:") and "preflight=true" in message:
            self._requests[activity] = preflight = True
        return preflight

    def _indicator(self, entry: Mapping[str, object]) -> list[Event]:
        message = _str(entry, "eventMessage")
        current = parse_attributions(message)
        if current is None:
            return []
        timestamp = parse_timestamp(_str(entry, "timestamp"))
        for gone in self._active - current:
            self._off_since[gone] = timestamp
        horizon = timestamp - self._merge_s
        added = [a for a in current - self._active if self._off_since.pop(a, horizon) <= horizon]
        self._active = current
        self._off_since = {k: t for k, t in self._off_since.items() if t > horizon}
        return [
            Event(
                timestamp=timestamp,
                sensor=INDICATOR_SENSORS.get(kind, SensorType.TCC),
                pid=None,
                process_name="",
                bundle_id=bundle,
                subsystem=SUBSYSTEM_CONTROLCENTER,
                message=message,
                service=f"indicator:{kind}",
            )
            for kind, bundle in sorted(added)
        ]


class _Cooldown:
    """Collapses the burst of log lines a single access produces into one event."""

    def __init__(self, cooldown_s: float) -> None:
        self._cooldown_s = cooldown_s
        self._last: dict[tuple[SensorType, int | str], float] = {}

    def accept(self, event: Event) -> bool:
        # The pid is the strongest identity; lines of one access disagree on name/bundle.
        actor = event.pid if event.pid is not None else event.bundle_id or event.process_name
        key = (event.sensor, actor)
        last = self._last.get(key)
        self._last[key] = event.timestamp
        if len(self._last) > 4096:
            horizon = event.timestamp - self._cooldown_s
            self._last = {k: v for k, v in self._last.items() if v >= horizon}
        return last is None or event.timestamp - last >= self._cooldown_s


def log_stream_command(predicate: str = PREDICATE, level: str = "info") -> list[str]:
    return [LOG_BINARY, "stream", "--style", "json", "--level", level, "--predicate", predicate]


def process_info(pid: int) -> tuple[str, str | None] | None:
    """(name, executable path) of a live process, or None if it is gone or inaccessible."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        try:
            exe: str | None = proc.exe() or None
        except (psutil.AccessDenied, psutil.ZombieProcess):
            exe = None
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
    return name, exe


def possible_exes_for_bundle(bundle_id: str) -> list[str]:
    """Executable paths of running processes that may carry `bundle_id`.

    A process qualifies if any .app enclosing it declares the id (a nested app counts), or if
    it is outside SIP paths inside an .app whose Info.plist is unusable: it may have been
    moved or broken after launch. Processes whose path is unreadable are skipped.
    """
    exes: list[str] = []
    for proc in psutil.process_iter(["exe"]):
        exe = proc.info.get("exe")
        if not exe:
            continue
        ids = [bundle_id_for_app(app) for app in enclosing_apps(exe)]
        if bundle_id in ids or (None in ids and not is_system_path(exe)):
            exes.append(exe)
    return exes


class _ProcessEnricher:
    """Fills name / bundle id / system flag of events that only carry a pid (e.g. TCC lines
    naming a client via target_token), so they display and correlate like the others."""

    def __init__(self, lookup: ProcessInfo, max_entries: int = 2048) -> None:
        self._lookup = lookup
        self._max_entries = max_entries
        self._cache: dict[int, tuple[str, str | None]] = {}

    def __call__(self, event: Event) -> Event:
        if event.pid is None or (event.process_name and event.bundle_id):
            return event
        info = self._cache.get(event.pid)
        if info is None:
            info = self._lookup(event.pid)
            if info is None:
                return event
            if len(self._cache) >= self._max_entries:
                self._cache.clear()
            self._cache[event.pid] = info
        name, exe = info
        return dataclasses.replace(
            event,
            process_name=event.process_name or name,
            bundle_id=event.bundle_id or (bundle_id_for_exe(exe) if exe else None),
            system=event.system or is_system_path(exe),
        )


# Subsystems the parser can turn into events. A cheap gate on each decoded entry drops anything
# else before the stateful parse and the Control Center process-table walk, so a wide predicate
# or a log flood cannot bury the sensor entries. It is a prefix superset of what `parse` accepts
# (which matches `com.apple.TCC` and `com.apple.controlcenter` exactly and the rest by prefix),
# so it can never discard a real sensor event.
_CANDIDATE_SUBSYSTEMS = (
    SUBSYSTEM_TCC,
    SUBSYSTEM_CONTROLCENTER,
    SUBSYSTEM_LOCATION,
    SUBSYSTEM_AUDIO,
    SUBSYSTEM_CMIO,
)


def is_candidate_subsystem(subsystem: str) -> bool:
    """Whether an entry from `subsystem` could classify, so is worth parsing."""
    return subsystem.startswith(_CANDIDATE_SUBSYSTEMS)


class SensorListener:
    """Async wrapper around `log stream` yielding classified sensor events."""

    def __init__(
        self,
        command: Sequence[str] | None = None,
        cooldown_s: float = 1.0,
        process_lookup: ProcessInfo = process_info,
        bundle_exes: BundleExes = possible_exes_for_bundle,
        bundle_lookup_timeout_s: float = 1.0,
        buffer_entries: int = 1024,
    ) -> None:
        self._command = list(command) if command is not None else log_stream_command()
        self._cooldown = _Cooldown(cooldown_s)
        self._enrich = _ProcessEnricher(process_lookup)
        self._bundle_exes = bundle_exes
        self._bundle_lookup_timeout_s = bundle_lookup_timeout_s
        self._buffer_entries = buffer_entries
        # Observability counters: entries skipped before parse by the subsystem gate, and entries
        # lost to a full buffer under flood. Public so a caller can report load-shedding.
        self.filtered = 0
        self.dropped = 0

    async def entries(self) -> AsyncIterator[dict[str, object]]:
        """Raw unified-log entries; raises `SensorError` if `log` exits with an error."""
        proc = await asyncio.create_subprocess_exec(
            *self._command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdout is not None and proc.stderr is not None
        stderr_task = asyncio.create_task(_drain_tail(proc.stderr))
        decoder = JsonStreamDecoder()
        utf8 = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            while chunk := await proc.stdout.read(65536):
                for entry in decoder.feed(utf8.decode(chunk)):
                    yield entry
            returncode = await proc.wait()
            if returncode != 0:
                stderr = (await stderr_task).decode(errors="replace").strip()
                raise SensorError(f"{self._command[0]} exited with {returncode}: {stderr}")
        finally:
            if proc.returncode is None:
                proc.terminate()
                await proc.wait()
            stderr_task.cancel()

    def _mark_indicator_system(self, event: Event) -> Event:
        """Indicator events carry only a bundle id, which any app can claim. They count as system
        (hidden from display; still correlated) only if every process that may carry that id
        runs from a SIP-protected path."""
        if (
            event.subsystem != SUBSYSTEM_CONTROLCENTER
            or event.pid is not None
            or not event.bundle_id
        ):
            return event
        exes = self._bundle_exes(event.bundle_id)
        if exes and all(is_system_path(exe) for exe in exes):
            return dataclasses.replace(event, system=True)
        return event

    async def _read_into(self, queue: asyncio.Queue[dict[str, object] | None]) -> None:
        """Drain stdout into `queue`, dropping the oldest entry when it is full.

        Reading is decoupled from the classification below so a burst never blocks the reader:
        if the consumer cannot keep up, the bounded queue sheds its oldest entries (counted)
        rather than letting the `log` pipe back up and age out the correlation clock. The
        subsystem gate keeps irrelevant entries from taking a slot at all. A `None` is always
        queued last so the consumer can stop; an error from `entries()` is raised there.
        """
        try:
            async for entry in self.entries():
                if not is_candidate_subsystem(_str(entry, "subsystem")):
                    self.filtered += 1
                    continue
                try:
                    queue.put_nowait(entry)
                except asyncio.QueueFull:
                    with contextlib.suppress(asyncio.QueueEmpty):
                        queue.get_nowait()
                        self.dropped += 1
                    queue.put_nowait(entry)
        finally:
            # A helper, not an inline loop: a `return`/`break` in a `finally` would swallow a
            # `SensorError` raised by `entries()`, which the consumer re-raises after draining.
            self._enqueue_done(queue)

    @staticmethod
    def _enqueue_done(queue: asyncio.Queue[dict[str, object] | None]) -> None:
        """Queue the `None` stop marker, making room by dropping an entry if the queue is full."""
        while True:
            try:
                queue.put_nowait(None)
                return
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    return

    async def events(self) -> AsyncIterator[Event]:
        queue: asyncio.Queue[dict[str, object] | None] = asyncio.Queue(maxsize=self._buffer_entries)
        reader = asyncio.create_task(self._read_into(queue))
        parser = SensorEventParser()
        try:
            while True:
                entry = await queue.get()
                if entry is None:
                    break
                for event in parser.parse(entry):
                    if not self._cooldown.accept(event):
                        continue
                    if event.subsystem == SUBSYSTEM_CONTROLCENTER:
                        # Walks the process table (~60-100 ms cold): keep it off the event loop,
                        # and leave the event visible if it takes too long.
                        with contextlib.suppress(TimeoutError):
                            event = await asyncio.wait_for(
                                asyncio.to_thread(self._mark_indicator_system, event),
                                self._bundle_lookup_timeout_s,
                            )
                    yield self._enrich(event)
            await reader  # propagate a SensorError from `log` once the queue has drained
        finally:
            reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reader
