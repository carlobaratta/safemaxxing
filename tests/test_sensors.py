from __future__ import annotations

import json
import sys
from pathlib import Path

from safemaxxing.models import SensorType
from safemaxxing.sensors import (
    JsonStreamDecoder,
    SensorListener,
    log_stream_command,
    parse_entry,
    parse_timestamp,
)

TCC_ATTRIBUTION = {
    "timestamp": "2026-10-22 10:00:00.250000+0000",
    "subsystem": "com.apple.TCC",
    "processID": 180,
    "processImagePath": "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
    "eventMessage": (
        "AUTHREQ_ATTRIBUTION: msgID=180.42, attribution={responsible={TCCDProcess: "
        "identifier=com.example.spy, pid=4242, auid=501, euid=501, binary_path=/Applications/"
        "Spy.app/Contents/MacOS/Spy}, accessing={TCCDProcess: identifier=com.example.spy, "
        "pid=4242, auid=501, euid=501, binary_path=/Applications/Spy.app/Contents/MacOS/Spy}}, "
        "service=kTCCServiceCamera"
    ),
}


def test_parse_tcc_camera_attributes_client_not_tccd() -> None:
    event = parse_entry(TCC_ATTRIBUTION)
    assert event is not None
    assert event.sensor is SensorType.CAMERA
    assert event.pid == 4242
    assert event.bundle_id == "com.example.spy"
    assert event.process_name == ""
    assert event.service == "Camera"
    assert event.timestamp == parse_timestamp("2026-10-22 10:00:00.250000+0000")


def test_parse_tcc_request_with_sender_pid() -> None:
    entry = {
        **TCC_ATTRIBUTION,
        "eventMessage": "REQUEST: tccd_uid=501, sender_pid=777, function=TCCAccessRequest, "
        "service=kTCCServiceMicrophone",
    }
    event = parse_entry(entry)
    assert event is not None
    assert event.sensor is SensorType.MICROPHONE
    assert event.pid == 777


def test_parse_tcc_other_service_maps_to_generic_tcc() -> None:
    entry = {**TCC_ATTRIBUTION, "eventMessage": "sender_pid=9 service=kTCCServiceAddressBook"}
    event = parse_entry(entry)
    assert event is not None
    assert event.sensor is SensorType.TCC
    assert event.service == "AddressBook"


def test_parse_tcc_without_actor_is_dropped() -> None:
    entry = {**TCC_ATTRIBUTION, "eventMessage": "Refreshing kTCCServiceCamera cache"}
    assert parse_entry(entry) is None


def test_parse_cmio_in_client_process() -> None:
    entry = {
        "timestamp": "2026-10-22 10:00:00.000000+0000",
        "subsystem": "com.apple.cmio",
        "processID": 4242,
        "processImagePath": "/Applications/Spy.app/Contents/MacOS/Spy",
        "eventMessage": "CMIOExtensionProvider: startStream for device 0x1234",
    }
    event = parse_entry(entry)
    assert event is not None
    assert event.sensor is SensorType.CAMERA
    assert event.pid == 4242
    assert event.process_name == "Spy"


def test_parse_coreaudio_broker_uses_message_pid() -> None:
    entry = {
        "timestamp": "2026-10-22 10:00:00.000000+0000",
        "subsystem": "com.apple.coreaudio",
        "processID": 300,
        "processImagePath": "/usr/sbin/coreaudiod",
        "eventMessage": "HALS_IOContext: Starting IO for input device, client pid: 5151",
    }
    event = parse_entry(entry)
    assert event is not None
    assert event.sensor is SensorType.MICROPHONE
    assert event.pid == 5151
    assert event.process_name == ""


def test_parse_coreaudio_output_only_ignored() -> None:
    entry = {
        "timestamp": "2026-10-22 10:00:00.000000+0000",
        "subsystem": "com.apple.coreaudio",
        "processID": 300,
        "processImagePath": "/usr/sbin/coreaudiod",
        "eventMessage": "Starting IO for output device, pid: 5151",
    }
    assert parse_entry(entry) is None


def test_parse_locationd_extracts_bundle() -> None:
    entry = {
        "timestamp": "2026-10-22 10:00:00.000000+0000",
        "subsystem": "com.apple.locationd.Core",
        "processID": 200,
        "processImagePath": "/usr/libexec/locationd",
        "eventMessage": '{"msg":"startUpdatingLocation", "Client":"com.example.maps"}',
    }
    event = parse_entry(entry)
    assert event is not None
    assert event.sensor is SensorType.LOCATION
    assert event.bundle_id == "com.example.maps"
    assert event.pid is None


def test_parse_unrelated_subsystem() -> None:
    assert parse_entry({"subsystem": "com.apple.foo", "eventMessage": "pid=1"}) is None


def test_decoder_handles_chunked_json_array_and_header() -> None:
    entries = [TCC_ATTRIBUTION, {**TCC_ATTRIBUTION, "processID": 181}]
    payload = 'Filtering the log data using "..."\n[' + ",\n".join(map(json.dumps, entries))
    decoder = JsonStreamDecoder()
    out = []
    for i in range(0, len(payload), 37):
        out.extend(decoder.feed(payload[i : i + 37]))
    assert [e["processID"] for e in out] == [180, 181]


def test_decoder_handles_ndjson() -> None:
    decoder = JsonStreamDecoder()
    assert len(decoder.feed('{"a": 1}\n{"b": {"c": 2}}\n')) == 2


def test_log_stream_command_targets_sensitive_subsystems() -> None:
    cmd = log_stream_command()
    assert cmd[:4] == ["/usr/bin/log", "stream", "--style", "json"]
    predicate = cmd[-1]
    for subsystem in (
        "com.apple.TCC",
        "com.apple.locationd",
        "com.apple.coreaudio",
        "com.apple.cmio",
    ):
        assert subsystem in predicate


async def test_listener_streams_and_collapses_bursts(tmp_path: Path) -> None:
    second = {**TCC_ATTRIBUTION, "timestamp": "2026-10-22 10:00:00.400000+0000"}
    later = {**TCC_ATTRIBUTION, "timestamp": "2026-10-22 10:00:05.000000+0000"}
    data = tmp_path / "log.json"
    data.write_text("[" + ",".join(json.dumps(e) for e in (TCC_ATTRIBUTION, second, later)) + "]")
    script = f"import sys; sys.stdout.write(open({str(data)!r}).read())"
    listener = SensorListener(command=[sys.executable, "-c", script], cooldown_s=1.0)
    events = [e async for e in listener.events()]
    assert len(events) == 2
