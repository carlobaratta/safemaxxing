"""Synthetic `log stream --style json` entries in the exact shape the real parser accepts.

Each builder returns one unified-log entry (the dict the JSON decoder yields), with a message
copied from what macOS 27.0.1 actually logs for that access, so `SensorEventParser` classifies
it for real. `render` serialises a list of them as the JSON array `log stream --style json`
prints, for feeding through `JsonStreamDecoder` end to end. The noise builders produce entries
the parser must drop, so a scenario can prove the signal survives realistic background chatter.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

TCCD = "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd"
TCCD_PID = 180
COREAUDIOD = "/usr/sbin/coreaudiod"
COREAUDIOD_PID = 211
CONTROLCENTER = "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"
CONTROLCENTER_PID = 644

Entry = dict[str, object]


def log_timestamp(ts: float) -> str:
    """Format an epoch time as `log stream` does, e.g. `2026-10-22 10:00:00.250000+0000`."""
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M:%S.%f%z")


def _entry(ts: float, subsystem: str, message: str, image: str, pid: int, **extra: object) -> Entry:
    entry: Entry = {
        "timestamp": log_timestamp(ts),
        "subsystem": subsystem,
        "eventMessage": message,
        "processImagePath": image,
        "processID": pid,
    }
    entry.update(extra)
    return entry


def tcc_access(ts: float, service: str, pid: int, bundle: str | None, binary: str) -> Entry:
    """A tccd AUTHREQ_ATTRIBUTION line naming the accessing process, as for a direct Camera,
    Microphone or ScreenCapture grant. `service` is the bare name, e.g. `Camera`."""
    identifier = f"identifier={bundle}, " if bundle else ""
    block = f"TCCDProcess: {identifier}pid={pid}, auid=501, euid=501, binary_path={binary}"
    message = (
        f"AUTHREQ_ATTRIBUTION: msgID={TCCD_PID}.42, "
        f"attribution={{responsible={{{block}}}, accessing={{{block}}}}}, "
        f"service=kTCCService{service}"
    )
    return _entry(ts, "com.apple.TCC", message, TCCD, TCCD_PID)


def screencapture(ts: float, pid: int, binary: str = "/usr/sbin/screencapture") -> Entry:
    """A ScreenCapture request logged by the capturing process itself (pid == the entry's pid),
    the only ScreenCapture TCC line the parser keeps (as a `tcc` request, not a capture)."""
    block = f"TCCDProcess: pid={pid}, auid=501, euid=501, binary_path={binary}"
    message = (
        f"AUTHREQ_ATTRIBUTION: msgID={TCCD_PID}.9, "
        f"attribution={{accessing={{{block}}}}}, service=kTCCServiceScreenCapture"
    )
    return _entry(ts, "com.apple.TCC", message, binary, pid)


def cmio_camera(ts: float, pid: int, binary: str) -> Entry:
    """A CoreMediaIO camera start, logged by the capturing app."""
    message = "CMIOExtensionProvider: startStream for device 0x1234"
    return _entry(ts, "com.apple.cmio", message, binary, pid)


def coreaudio_mic(ts: float, client_pid: int) -> Entry:
    """coreaudiod starting input IO for a client (the client's pid is named in the message)."""
    message = f"HALS_IOContext: Starting IO for input device, client pid: {client_pid}"
    return _entry(ts, "com.apple.coreaudio", message, COREAUDIOD, COREAUDIOD_PID)


def indicator(ts: float, attributions: list[str]) -> Entry:
    """A Control Center privacy-indicator update carrying the full active set, e.g.
    `["cam:com.apple.PhotoBooth", "mic:com.apple.PhotoBooth"]`."""
    quoted = ", ".join(f'"{a}"' for a in attributions)
    message = f"Active activity attributions changed to [{quoted}]"
    return _entry(
        ts,
        "com.apple.controlcenter",
        message,
        CONTROLCENTER,
        CONTROLCENTER_PID,
        category="sensor-indicators",
    )


# --- background noise: entries the parser must drop ----------------------------------------


def tcc_manager_check(ts: float) -> Entry:
    """A daemon checking its own right to query TCC for others -- never a real access."""
    message = (
        "<TCCDProcess: identifier=com.apple.audio.coreaudiod, pid=211> has the "
        "com.apple.private.tcc.manager.access.read entitlement, service=kTCCServiceMicrophone"
    )
    return _entry(ts, "com.apple.TCC", message, TCCD, TCCD_PID)


def coreaudio_preflight(ts: float, activity: int, client_pid: int) -> list[Entry]:
    """coreaudiod's held-back SEND plus tccd's REQUEST_MSG marking it a preflight (opening audio,
    not microphone use): both share one activityIdentifier and are dropped."""
    # coreaudiod logs its TCC request under the TCC subsystem (a libTCC client line), which is
    # how the parser recognises and holds back the SEND.
    send = _entry(
        ts,
        "com.apple.TCC",
        "SEND: TCCAccessRequest for kTCCServiceMicrophone",
        COREAUDIOD,
        COREAUDIOD_PID,
        activityIdentifier=activity,
    )
    request = _entry(
        ts + 0.001,
        "com.apple.TCC",
        f"REQUEST_MSG: msgID=1.1, preflight=true, target_token={{pid:{client_pid}}}, "
        "service=kTCCServiceMicrophone",
        TCCD,
        TCCD_PID,
        activityIdentifier=activity,
    )
    return [send, request]


def cmio_backtrace(ts: float, pid: int, binary: str) -> Entry:
    """The stack dump cmio prints after a camera start; carries `startstream` but `backtrace`."""
    message = "CMIODeviceStartStream backtrace 0x1 0x2 0x3"
    return _entry(ts, "com.apple.cmio", message, binary, pid)


def render(entries: list[Entry]) -> str:
    """Serialise entries as the JSON array `log stream --style json` prints."""
    return json.dumps(entries, indent=2)
