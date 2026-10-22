"""Unified-log sensors: turn `log stream --style json` output into `Event`s."""

from __future__ import annotations

import asyncio
import codecs
import json
import re
import time
from collections.abc import AsyncIterator, Mapping, Sequence
from datetime import datetime
from pathlib import PurePosixPath

from safemaxxing.models import Event, SensorType

LOG_BINARY = "/usr/bin/log"

SUBSYSTEM_TCC = "com.apple.TCC"
SUBSYSTEM_LOCATION = "com.apple.locationd"
SUBSYSTEM_AUDIO = "com.apple.coreaudio"
SUBSYSTEM_CMIO = "com.apple.cmio"

PREDICATE = (
    f'(subsystem == "{SUBSYSTEM_TCC}" AND eventMessage CONTAINS "kTCCService")'
    f' OR subsystem BEGINSWITH "{SUBSYSTEM_LOCATION}"'
    f' OR subsystem BEGINSWITH "{SUBSYSTEM_AUDIO}"'
    f' OR subsystem BEGINSWITH "{SUBSYSTEM_CMIO}"'
)

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
)

_TCC_SERVICE_RE = re.compile(r"kTCCService(\w+)")
_ACCESSING_RE = re.compile(r"accessing=\{[^}]*?identifier=([\w.\-]+),\s*pid=(\d+)")
_SENDER_PID_RE = re.compile(r"\bsender_pid=(\d+)")
_IDENTIFIER_RE = re.compile(r"\bidentifier=([\w.\-]+)|Sub:\{([\w.\-]+)\}")
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
        while True:
            start = self._buffer.find("{")
            if start < 0:
                self._buffer = ""
                break
            try:
                value, end = self._decoder.raw_decode(self._buffer, start)
            except json.JSONDecodeError:
                if len(self._buffer) - start > self._max_buffer:
                    self._buffer = self._buffer[start + 1 :]
                    continue
                self._buffer = self._buffer[start:]
                break
            self._buffer = self._buffer[end:]
            if isinstance(value, dict):
                out.append(value)
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


def _classify_tcc(message: str) -> tuple[SensorType, str, int | None, str | None] | None:
    service_match = _TCC_SERVICE_RE.search(message)
    if not service_match:
        return None
    service = service_match.group(1)
    sensor = TCC_SERVICE_MAP.get(service, SensorType.TCC)
    pid: int | None = None
    bundle: str | None = None
    if accessing := _ACCESSING_RE.search(message):
        bundle, pid = accessing.group(1), int(accessing.group(2))
    else:
        if sender := _SENDER_PID_RE.search(message):
            pid = int(sender.group(1))
        if ident := _IDENTIFIER_RE.search(message):
            bundle = ident.group(1) or ident.group(2)
    if pid is None and bundle is None:
        return None
    return sensor, service, pid, bundle


def parse_entry(entry: Mapping[str, object]) -> Event | None:
    """Classify a single unified-log entry; returns None when it is not a sensor access."""
    subsystem = _str(entry, "subsystem")
    message = _str(entry, "eventMessage")
    if not subsystem or not message:
        return None
    image_path = _str(entry, "processImagePath")
    process_name = PurePosixPath(image_path).name if image_path else ""
    log_pid = _int(entry, "processID")
    timestamp = parse_timestamp(_str(entry, "timestamp"))
    lowered = message.lower()

    sensor: SensorType
    service: str | None = None
    if subsystem == SUBSYSTEM_TCC:
        classified = _classify_tcc(message)
        if classified is None:
            return None
        sensor, service, pid, bundle = classified
    elif subsystem.startswith(SUBSYSTEM_CMIO):
        if not _contains_any(lowered, CAMERA_HINTS):
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
    else:
        return None

    if pid is None and bundle is None:
        return None
    if process_name in BROKER_PROCESSES:
        process_name = ""
    return Event(
        timestamp=timestamp,
        sensor=sensor,
        pid=pid,
        process_name=process_name,
        bundle_id=bundle,
        subsystem=subsystem,
        message=message,
        service=service,
    )


class _Cooldown:
    """Collapses the burst of log lines a single access produces into one event."""

    def __init__(self, cooldown_s: float) -> None:
        self._cooldown_s = cooldown_s
        self._last: dict[tuple[SensorType, int | None, str | None], float] = {}

    def accept(self, event: Event) -> bool:
        key = (event.sensor, event.pid, event.bundle_id)
        last = self._last.get(key)
        self._last[key] = event.timestamp
        if len(self._last) > 4096:
            horizon = event.timestamp - self._cooldown_s
            self._last = {k: v for k, v in self._last.items() if v >= horizon}
        return last is None or event.timestamp - last >= self._cooldown_s


def log_stream_command(predicate: str = PREDICATE) -> list[str]:
    return [LOG_BINARY, "stream", "--style", "json", "--level", "info", "--predicate", predicate]


class SensorListener:
    """Async wrapper around `log stream` yielding classified sensor events."""

    def __init__(self, command: Sequence[str] | None = None, cooldown_s: float = 1.0) -> None:
        self._command = list(command) if command is not None else log_stream_command()
        self._cooldown = _Cooldown(cooldown_s)

    async def events(self) -> AsyncIterator[Event]:
        proc = await asyncio.create_subprocess_exec(
            *self._command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        assert proc.stdout is not None
        decoder = JsonStreamDecoder()
        utf8 = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            while chunk := await proc.stdout.read(65536):
                for entry in decoder.feed(utf8.decode(chunk)):
                    event = parse_entry(entry)
                    if event is not None and self._cooldown.accept(event):
                        yield event
        finally:
            if proc.returncode is None:
                proc.terminate()
                await proc.wait()
