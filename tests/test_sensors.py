from __future__ import annotations

import asyncio
import json
import plistlib
import sys
import time
from collections.abc import AsyncIterator
from pathlib import Path

import psutil
import pytest

from safemaxxing.models import SensorType
from safemaxxing.sensors import (
    AUDIO_START_HINTS,
    CAMERA_HINTS,
    DISCOVERY_PREDICATE,
    LOCATION_HINTS,
    PREDICATE,
    WIDE_DISCOVERY_PREDICATE,
    JsonStreamDecoder,
    SensorError,
    SensorEventParser,
    SensorListener,
    is_candidate_subsystem,
    log_stream_command,
    parse_entry,
    parse_timestamp,
    possible_exes_for_bundle,
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


def test_tcc_accessing_block_order_independent_and_preferred() -> None:
    entry = {
        **TCC_ATTRIBUTION,
        "eventMessage": (
            "AUTHREQ_ATTRIBUTION: msgID=1.2, attribution={requesting={TCCDProcess: "
            "identifier=com.apple.WebKit.GPU, pid=900}, accessing={TCCDProcess: pid=4242, "
            "auid=501, binary_path=/x, identifier=com.example.spy}}, service=kTCCServiceCamera"
        ),
    }
    event = parse_entry(entry)
    assert event is not None
    assert (event.pid, event.bundle_id) == (4242, "com.example.spy")


def test_tcc_redacted_identifier_falls_back_to_pid() -> None:
    entry = {
        **TCC_ATTRIBUTION,
        "eventMessage": (
            "AUTHREQ_ATTRIBUTION: attribution={accessing={TCCDProcess: identifier=<private>, "
            "pid=4242, auid=501}}, service=kTCCServiceMicrophone"
        ),
    }
    event = parse_entry(entry)
    assert event is not None
    assert event.pid == 4242 and event.bundle_id is None


def test_tcc_mask_hash_redaction_is_not_a_bundle_id() -> None:
    entry = {
        **TCC_ATTRIBUTION,
        "eventMessage": "AUTHREQ_SUBJECT: subject=<mask.hash: 'AbC=='>, service=kTCCServiceCamera",
    }
    assert parse_entry(entry) is None


def test_tcc_subject_and_target_token_formats() -> None:
    entry = {
        **TCC_ATTRIBUTION,
        "eventMessage": (
            "AUTHREQ_CTX: msgID=1.3, function=TCCAccessRequest, service=kTCCServiceCamera, "
            "subject=com.example.spy, target_token={pid:4242, auid:501, euid:501}"
        ),
    }
    event = parse_entry(entry)
    assert event is not None
    assert (event.pid, event.bundle_id) == (4242, "com.example.spy")


def test_fully_redacted_entry_dropped_and_private_image_path_ignored() -> None:
    entry = {
        "timestamp": "2026-10-22 10:00:00.000000+0000",
        "subsystem": "com.apple.cmio",
        "processID": 4242,
        "processImagePath": "<private>",
        "eventMessage": "startStream client: <private> pid: <private>",
    }
    event = parse_entry(entry)
    assert event is not None
    assert event.pid == 4242 and event.process_name == ""


async def test_listener_raises_on_log_error() -> None:
    script = "import sys; sys.stderr.write('log: Must be admin to run stream'); sys.exit(64)"
    listener = SensorListener(command=[sys.executable, "-c", script])
    try:
        async for _ in listener.events():
            pass
    except SensorError as exc:
        assert "Must be admin" in str(exc) and "64" in str(exc)
        return
    raise AssertionError("expected SensorError")


def test_runtime_predicate_filters_chatter_at_source() -> None:
    assert 'eventMessage CONTAINS[c] "startupdatinglocation"' in PREDICATE
    assert 'eventMessage CONTAINS[c] "startstream"' in PREDICATE
    assert PREDICATE.count("(") == PREDICATE.count(")")
    assert '"' not in "".join(CAMERA_HINTS + AUDIO_START_HINTS + LOCATION_HINTS)
    assert "CONTAINS[c]" not in DISCOVERY_PREDICATE


def test_real_macos_27_locationd_and_cmio_noise_is_not_an_event() -> None:
    noise = [
        (
            "com.apple.locationd.Core",
            "locationd",
            '{"msg":"onAvengerAdvertisementDetected: got avenger advertisement", '
            '"geotaggingEngine":"CLGeotaggingEngine"}',
        ),
        (
            "com.apple.locationd.Core",
            "locationd",
            '{"msg":"convertToSPAdvertisement", "address":<private>, '
            '"data":<private>, "rssi":<private>}',
        ),
        (
            "com.apple.locationd.Core",
            "locationd",
            '{"msg":"onAvengerAdvertisementDetected: advertisement is near-owner from other '
            'people and do not process it", "geotaggingEngine":"CLGeotaggingEngine"}',
        ),
        (
            "com.apple.cmio",
            "com.apple.cmio.registerassistantservice",
            "RegisterAssistantService.m:2156:-[RegisterAssistantServer "
            "addRegisterExtensionConnection:]_block_invoke [<private>] setting <private> : <private>",
        ),
        (
            "com.apple.locationd.Motion",
            "locationd",
            "Type,<private>,motionStateUpdate:Motion,1,conf,2,isMoving,<private>",
        ),
        (
            "com.apple.locationd.Core",
            "locationd",
            '{"msg":"received AOP log", "log":{"flags":1,"seq":5225}}',
        ),
        (
            "com.apple.cmio",
            "com.apple.cmio.registerassistantservice",
            "RegisterAssistantService.m:2118:-[RegisterAssistantServer "
            "addRegisterExtensionConnection:]_block_invoke [<private>] set Preference",
        ),
    ]
    for subsystem, process, message in noise:
        entry = {
            "timestamp": "2026-10-22 12:30:00.000000+0200",
            "subsystem": subsystem,
            "processID": 321,
            "processImagePath": f"/usr/libexec/{process}",
            "eventMessage": message,
        }
        assert parse_entry(entry) is None, message


def _locationd(message: str) -> dict[str, object]:
    return {
        "timestamp": "2026-10-22 12:40:00.000000+0200",
        "subsystem": "com.apple.locationd.Core",
        "processID": 321,
        "processImagePath": "/usr/libexec/locationd",
        "eventMessage": message,
    }


def test_locationd_mark_receiving_with_framework_client() -> None:
    # Verbatim from macOS 27.0.1 (the inner JSON keeps its escaped slashes).
    message = (
        '{"msg":"markReceivingLocationInformation", "Client":"root:com.apple.locationd.bundle-'
        '\\/System\\/Library\\/PrivateFrameworks\\/CoreParsec.framework"}'
    )
    event = parse_entry(_locationd(message))
    assert event is not None
    assert event.sensor is SensorType.LOCATION
    assert (event.pid, event.bundle_id, event.process_name) == (None, None, "CoreParsec")


def test_locationd_mark_receiving_with_app_client() -> None:
    message = '{"msg":"markReceivingLocationInformation", "Client":"carlo:com.apple.Maps"}'
    event = parse_entry(_locationd(message))
    assert event is not None
    assert event.bundle_id == "com.apple.Maps" and event.identity == "com.apple.Maps"


def test_locationd_redacted_client_dropped() -> None:
    message = '{"msg":"markReceivingLocationInformation", "Client":<private>}'
    assert parse_entry(_locationd(message)) is None


def test_locationd_client_name_lookup_is_not_an_access() -> None:
    message = (
        '{"msg":"client getting effective client name", "bundleId":"", '
        '"bundlePath":"\\/System\\/Library\\/PrivateFrameworks\\/CoreParsec.framework"}'
    )
    assert parse_entry(_locationd(message)) is None


def test_log_stream_command_level() -> None:
    assert log_stream_command(level="debug")[4:6] == ["--level", "debug"]


def test_wide_discovery_predicate_shape() -> None:
    assert WIDE_DISCOVERY_PREDICATE.count("(") == WIDE_DISCOVERY_PREDICATE.count(")")
    assert 'process == "tccd"' in WIDE_DISCOVERY_PREDICATE
    assert 'AND NOT subsystem BEGINSWITH "com.apple.locationd"' in WIDE_DISCOVERY_PREDICATE


def test_tcc_client_side_send_line_uses_msgid_pid() -> None:
    # Verbatim shape from macOS 27.0.1, logged by the requesting app (Photo Booth).
    entry = {
        "timestamp": "2026-10-22 12:50:00.000000+0200",
        "subsystem": "com.apple.TCC",
        "category": "access",
        "processID": 34654,
        "processImagePath": "/System/Applications/Photo Booth.app/Contents/MacOS/Photo Booth",
        "eventMessage": "SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=34654.1, "
        "function=TCCAccessRequest, service=kTCCServiceCamera,",
    }
    event = parse_entry(entry)
    assert event is not None
    assert (event.sensor, event.pid, event.process_name) == (
        SensorType.CAMERA,
        34654,
        "Photo Booth",
    )


def test_tcc_client_side_line_without_msgid_falls_back_to_log_pid() -> None:
    entry = {
        "timestamp": "2026-10-22 12:50:00.000000+0200",
        "subsystem": "com.apple.TCC",
        "processID": 777,
        "processImagePath": "/Applications/Spy.app/Contents/MacOS/Spy",
        "eventMessage": "preflight check service=kTCCServiceMicrophone",
    }
    event = parse_entry(entry)
    assert event is not None and event.pid == 777


def test_tccd_line_without_actor_still_dropped() -> None:
    entry = {**TCC_ATTRIBUTION, "eventMessage": "Refreshing cache for kTCCServiceCamera"}
    assert parse_entry(entry) is None


# ---- Verbatim lines from the macOS 27.0.1 wide sample (Photo Booth + Voice Memos) ----


def _entry(
    subsystem: str, process: str, message: str, pid: int = 1, **extra: object
) -> dict[str, object]:
    return {
        "timestamp": "2026-10-22 13:00:00.000000+0200",
        "subsystem": subsystem,
        "processID": pid,
        "processImagePath": f"/usr/libexec/{process}",
        "eventMessage": message,
        **extra,
    }


def _indicator(message: str, timestamp: str | None = None) -> dict[str, object]:
    return _entry(
        "com.apple.controlcenter",
        "ControlCenter",
        message,
        pid=500,
        category="sensor-indicators",
        messageType="Default",
        **({} if timestamp is None else {"timestamp": timestamp}),
    )


def _indicator_timeline(timeline: list[tuple[str, str]]) -> list[tuple[SensorType, str | None]]:
    """(timestamp, attribution list) pairs through one parser -> (sensor, bundle) emitted."""
    parser = SensorEventParser()
    return [
        (event.sensor, event.bundle_id)
        for timestamp, attributions in timeline
        for event in parser.parse(
            _indicator(f"Active activity attributions changed to {attributions}", timestamp)
        )
    ]


def test_control_center_indicator_emits_only_new_attributions() -> None:
    parser = SensorEventParser()
    (cam,) = parser.parse(
        _indicator('Active activity attributions changed to ["cam:com.apple.PhotoBooth"]')
    )
    assert (cam.sensor, cam.bundle_id, cam.pid) == (SensorType.CAMERA, "com.apple.PhotoBooth", None)
    assert cam.service == "indicator:cam"
    both = 'Active activity attributions changed to ["cam:com.apple.PhotoBooth", "loc:com.apple.VoiceMemos"]'
    (loc,) = parser.parse(_indicator(both))
    assert (loc.sensor, loc.bundle_id) == (SensorType.LOCATION, "com.apple.VoiceMemos")
    assert parser.parse(_indicator("Active activity attributions changed to []")) == []
    (again,) = parser.parse(
        _indicator(
            'Active activity attributions changed to ["cam:com.apple.PhotoBooth"]',
            "2026-10-22 13:00:05.000000+0200",
        )
    )
    assert again.sensor is SensorType.CAMERA


def test_real_indicator_sequence_with_camera_location_and_microphone() -> None:
    # Verbatim, in order, from macOS 27.0.1 (2026-10-23 14:24): Photo Booth opened, then a
    # Voice Memos recording. Location flaps off for 18 ms while it tags the recording: one use.
    emitted = _indicator_timeline(
        [
            ("2026-10-23 14:25:32.641389+0200", '["cam:com.apple.PhotoBooth"]'),
            (
                "2026-10-23 14:25:40.034687+0200",
                '["cam:com.apple.PhotoBooth", "loc:com.apple.VoiceMemos"]',
            ),
            ("2026-10-23 14:25:40.149396+0200", '["cam:com.apple.PhotoBooth"]'),
            (
                "2026-10-23 14:25:40.167351+0200",
                '["cam:com.apple.PhotoBooth", "loc:com.apple.VoiceMemos"]',
            ),
            (
                "2026-10-23 14:25:41.739172+0200",
                '["cam:com.apple.PhotoBooth", "loc:com.apple.VoiceMemos", "mic:com.apple.VoiceMemos"]',
            ),
        ]
    )
    assert emitted == [
        (SensorType.CAMERA, "com.apple.PhotoBooth"),
        (SensorType.LOCATION, "com.apple.VoiceMemos"),
        (SensorType.MICROPHONE, "com.apple.VoiceMemos"),
    ]


def test_cmd_shift_5_recording_flicker_is_one_event() -> None:
    # Verbatim from macOS 27.0.1, 2026-10-24 20:42: a 24 ms flicker, then the 7.4 s recording.
    emitted = _indicator_timeline(
        [
            ("2026-10-24 20:42:23.252423+0200", '["scr:com.apple.systemuiserver"]'),
            ("2026-10-24 20:42:23.276718+0200", "[]"),
            ("2026-10-24 20:42:23.640664+0200", '["scr:com.apple.systemuiserver"]'),
            ("2026-10-24 20:42:31.037433+0200", "[]"),
        ]
    )
    assert emitted == [(SensorType.SCREEN_CAPTURE, "com.apple.systemuiserver")]


def test_brave_window_share_blinking_indicator_is_one_event_per_share() -> None:
    # Verbatim from macOS 27.0.1, 2026-10-26 10:30: one share shows as ~130 ms spans once a
    # second (gaps up to 0.884 s); a second share starts 15 s after the first ends.
    on, off = '["scr:com.brave.Browser"]', "[]"
    times = [
        "10:30:56.146216", "10:30:56.293941", "10:30:57.148602", "10:30:57.279031",
        "10:30:58.152232", "10:30:58.282264", "10:30:59.162421", "10:30:59.288096",
        "10:31:14.467690", "10:31:14.612854", "10:31:15.488936", "10:31:15.612858",
        "10:31:16.497026", "10:31:16.634499", "10:31:17.499273", "10:31:17.622472",
        "10:31:18.484008", "10:31:18.585392", "10:31:18.624089", "10:31:18.652196",
    ]  # fmt: skip
    timeline = [(f"2026-10-26 {t}+0100", on if i % 2 == 0 else off) for i, t in enumerate(times)]
    assert _indicator_timeline(timeline) == [(SensorType.SCREEN_CAPTURE, "com.brave.Browser")] * 2


def test_cmio_start_stream_backtrace_lines_are_not_extra_camera_starts() -> None:
    # Verbatim from macOS 27.0.1, 2026-10-26 10:23:40: Brave's camera start (pid 2526), then
    # the first two of its backtrace lines (52 camera events in all before this fix).
    helper = (
        "/Applications/Brave Browser.app/Contents/Frameworks/Brave Browser Framework.framework/"
        "Versions/155.1.97.59/Helpers/Brave Browser Helper.app/Contents/MacOS/Brave Browser Helper"
    )
    messages = [
        "CMIOHardware.cpp:741:CMIODeviceStartStream (35 36)",
        "CMIOHardware.cpp:747:CMIODeviceStartStream backtrace 0   CoreMediaIO                "
        "         0x000000019f76411c CMIODeviceStartStream + 212    [0x19f6fa000 + 434460]",
        "CMIOHardware.cpp:747:CMIODeviceStartStream backtrace 1   CMIOBaseUnits              "
        "         0x00000001164d3400 CMIOUnitVideoToolboxCompressorEntry + 48672    "
        "[0x116438000 + 635904]",
    ]
    events = [
        parse_entry(_entry("com.apple.cmio", "", m, pid=2526, processImagePath=helper))
        for m in messages
    ]
    start, *backtrace = events
    assert start is not None and (start.sensor, start.pid) == (SensorType.CAMERA, 2526)
    assert backtrace == [None, None]


def test_indicator_flicker_merge_is_per_attribution() -> None:
    # Constructed: Photo Booth's camera going off does not hide Voice Memos' camera coming on.
    emitted = _indicator_timeline(
        [
            ("2026-10-22 13:00:00.000000+0200", '["cam:com.apple.PhotoBooth"]'),
            ("2026-10-22 13:00:00.100000+0200", "[]"),
            ("2026-10-22 13:00:00.200000+0200", '["cam:com.apple.VoiceMemos"]'),
        ]
    )
    assert emitted == [
        (SensorType.CAMERA, "com.apple.PhotoBooth"),
        (SensorType.CAMERA, "com.apple.VoiceMemos"),
    ]


def test_other_control_center_lines_ignored() -> None:
    parser = SensorEventParser()
    for message in (
        'Recent activity attributions changed to ["cam:com.apple.PhotoBooth"]',
        "Sorted active attributions from SystemStatus update: [[cam] Photo Booth (com.apple.PhotoBooth)]",
        "Dependent controller changed: sensor indicators",
    ):
        assert parser.parse(_indicator(message)) == []


def test_parse_attributions_unknown_kind_maps_to_tcc() -> None:
    parser = SensorEventParser()
    (event,) = parser.parse(
        _indicator('Active activity attributions changed to ["xyz:com.example.app"]')
    )
    assert event.sensor is SensorType.TCC


def test_broker_tcc_check_on_behalf_of_client_uses_target_token() -> None:
    send = _entry(
        "com.apple.TCC",
        "coreaudiod",
        "SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=567.177, "
        "function=TCCAccessRequest, service=kTCCServiceMicrophone, target_token={pid:34661, auid:501, euid:",
        pid=567,
    )
    event = parse_entry(send)
    assert event is not None
    assert (event.sensor, event.pid, event.process_name) == (SensorType.MICROPHONE, 34661, "")
    camera = _entry(
        "com.apple.TCC",
        "cameracaptured",
        "SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=563.1, "
        "function=TCCAccessRequest, service=kTCCServiceCamera, target_token={pid:34654, auid:501, euid:501},",
        pid=563,
    )
    event = parse_entry(camera)
    assert event is not None and (event.sensor, event.pid) == (SensorType.CAMERA, 34654)


def test_broker_own_entitlement_check_is_not_attributed_to_broker() -> None:
    entry = _entry(
        "com.apple.TCC",
        "tccd",
        "<TCCDProcess: identifier=com.apple.audio.coreaudiod, pid=567> has the "
        "com.apple.private.tcc.manager.check-by-audit-token entitlement for service kTCCServiceMicrophone (co",
    )
    assert parse_entry(entry) is None


def test_tccd_auth_allowed_line() -> None:
    entry = _entry(
        "com.apple.TCC",
        "tccd",
        "Auth:Allowed (Entitled) to kTCCServiceMicrophone for TCCDProcess: identifier=com.apple.VoiceMemos, "
        "pid=34661, auid=501, euid=501, binary_path=/System/Applications/VoiceMe",
    )
    event = parse_entry(entry)
    assert event is not None
    assert (event.sensor, event.pid, event.bundle_id) == (
        SensorType.MICROPHONE,
        34661,
        "com.apple.VoiceMemos",
    )


def test_runtime_predicate_includes_indicator_clause() -> None:
    assert 'category == "sensor-indicators"' in PREDICATE
    assert 'BEGINSWITH "Active activity attributions changed to"' in PREDICATE


def test_locationd_client_key_format_i_prefix() -> None:
    message = '{"msg":"markReceivingLocationInformation", "Client":"icom.apple.VoiceMemos:"}'
    event = parse_entry(_locationd(message))
    assert event is not None and event.bundle_id == "com.apple.VoiceMemos"


def test_locationd_client_key_format_e_prefix() -> None:
    message = '{"msg":"markReceivingLocationInformation", "Client":"e\\/usr\\/libexec\\/airportd:"}'
    event = parse_entry(_locationd(message))
    assert event is not None and (event.bundle_id, event.process_name) == (None, "airportd")


def test_tccd_msgid_of_broker_request_is_not_an_actor() -> None:
    # msgID=567.x is coreaudiod's own request id; the client is only in coreaudiod's SEND line.
    entry = _entry(
        "com.apple.TCC",
        "tccd",
        "AUTHREQ_CTX: msgID=567.175, function=<private>, service=kTCCServiceScreenCapture, preflight=yes, query=1, client_dict=(null), daemon_dict=<private>",
    )
    assert parse_entry(entry) is None


def test_logging_process_is_not_the_actor_when_message_names_another_pid() -> None:
    # Same shape as the verbatim WindowServer line, with a service that is not filtered.
    entry = _entry(
        "com.apple.TCC",
        "WindowServer",
        "SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=406.9, function=TCCAccessRequest, service=kTCCServiceCamera, target_token={pid:35078, auid:501, euid:501},",
        pid=406,
    )
    event = parse_entry(entry)
    assert event is not None
    assert (event.pid, event.process_name, event.bundle_id) == (35078, "", None)


def test_identifier_and_pid_come_from_the_same_process_block() -> None:
    entry = _entry(
        "com.apple.TCC",
        "tccd",
        "AUTHREQ_ATTRIBUTION: msgID=1.1, attribution={responsible={TCCDProcess: identifier=com.apple.campo, pid=711}, accessing={TCCDProcess: identifier=com.apple.photolibraryd, pid=865}}, service=kTCCServicePhotos",
    )
    event = parse_entry(entry)
    assert event is not None and (event.pid, event.bundle_id) == (865, "com.apple.photolibraryd")


async def test_listener_cooldown_keys_on_pid_across_differing_names(tmp_path: Path) -> None:
    lines = [
        {
            **TCC_ATTRIBUTION,
            "eventMessage": "Auth:Allowed to kTCCServiceMicrophone for TCCDProcess: identifier=com.apple.FaceTime, pid=35075, auid=501",
        },
        {
            "timestamp": "2026-10-22 10:00:00.300000+0000",
            "subsystem": "com.apple.TCC",
            "processID": 35075,
            "processImagePath": "/System/Applications/FaceTime.app/Contents/MacOS/FaceTime",
            "eventMessage": "SEND: 0/7 synchronous to com.apple.tccd: request: msgID=35075.2, function=TCCAccessRequest, service=kTCCServiceMicrophone,",
        },
    ]
    data = tmp_path / "log.json"
    data.write_text("[" + ",".join(json.dumps(e) for e in lines) + "]")
    script = f"import sys; sys.stdout.write(open({str(data)!r}).read())"
    listener = SensorListener(command=[sys.executable, "-c", script], cooldown_s=1.0)
    events = [e async for e in listener.events()]
    assert len(events) == 1 and events[0].pid == 35075


def test_sandboxd_tcc_checks_on_behalf_of_others_are_not_accesses() -> None:
    # Verbatim (truncated by `sample`) from macOS 27.0.1 while Photo Booth was open.
    send = _entry(
        "com.apple.TCC",
        "sandboxd",
        "SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=401.411, "
        "function=TCCAccessRequest, service=kTCCServiceSystemPolicyAllFiles,",
        pid=401,
    )
    manager = _entry(
        "com.apple.TCC",
        "tccd",
        "<TCCDProcess: identifier=com.apple.sandboxd, pid=401> has the "
        "com.apple.private.tcc.manager.check-by-audit-token entitlement for service kTCCServiceAll (compose",
        pid=180,
    )
    assert parse_entry(send) is None
    assert parse_entry(manager) is None


def test_manager_entitlement_line_dropped_for_any_daemon() -> None:
    entry = _entry(
        "com.apple.TCC",
        "tccd",
        "<TCCDProcess: identifier=com.example.helperd, pid=777> has the "
        "com.apple.private.tcc.manager.check-by-audit-token entitlement for service kTCCServiceCamera",
        pid=180,
    )
    assert parse_entry(entry) is None


def test_background_session_full_disk_query_still_attributed() -> None:
    entry = _entry(
        "com.apple.TCC",
        "tccd",
        "Background Session: service kTCCServiceSystemPolicyAllFiles from "
        "Sub:{com.apple.CoreRoutine.helperservice}Resp:{TCCDProcess: "
        "identifier=com.apple.CoreRoutine.helperservice, pid=36094}",
        pid=180,
    )
    event = parse_entry(entry)
    assert event is not None
    assert (event.sensor, event.pid, event.bundle_id) == (
        SensorType.TCC,
        36094,
        "com.apple.CoreRoutine.helperservice",
    )


def test_locationd_system_clients_are_flagged_system() -> None:
    # Verbatim client keys from the macOS 27.0.1 `watch --events` run.
    for client in (
        "root:com.apple.locationd.bundle-\\/System\\/Library\\/LocationBundles\\/FindMyDevice.bundle",
        "p\\/System\\/Library\\/LocationBundles\\/TimeZone.bundle:",
        "p\\/System\\/Library\\/PrivateFrameworks\\/WirelessDiagnostics.framework:p\\/System\\/Library\\/Frameworks\\/CoreWLAN.framework",
    ):
        message = '{"msg":"markReceivingLocationInformation", "Client":"' + client + '"}'
        event = parse_entry(_locationd(message))
        assert event is not None and event.system, client
        assert "\\" not in event.identity and "/" not in event.identity
    app = parse_entry(
        _locationd('{"msg":"markReceivingLocationInformation", "Client":"icom.apple.VoiceMemos:"}')
    )
    assert app is not None and not app.system


def test_tcc_binary_path_marks_system() -> None:
    system = parse_entry(
        _entry(
            "com.apple.TCC",
            "tccd",
            "Auth:Allowed (Entitled) to kTCCServiceMicrophone for TCCDProcess: identifier=com.apple.VoiceMemos, pid=34661, auid=501, euid=501, binary_path=/System/Applications/VoiceMemos.app/Contents/MacOS/VoiceMemos}",
        )
    )
    assert system is not None and system.system
    third_party = parse_entry(
        _entry(
            "com.apple.TCC",
            "tccd",
            "Auth:Allowed to kTCCServiceMicrophone for TCCDProcess: identifier=com.brave.Browser, pid=2051, auid=501, euid=501, binary_path=/Applications/Brave Browser.app/Contents/MacOS/Brave Browser}",
        )
    )
    assert third_party is not None and not third_party.system
    assert third_party.bundle_id == "com.brave.Browser"


def test_in_process_line_from_system_binary_is_system() -> None:
    entry = _locationd('{"msg":"startUpdatingLocation"}')
    entry["processImagePath"] = "/usr/libexec/airportd"
    event = parse_entry(entry)
    assert event is not None and event.system


async def test_listener_names_pid_only_events_from_the_live_process(tmp_path: Path) -> None:
    app = tmp_path / "Brave Browser.app"
    (app / "Contents").mkdir(parents=True)
    with open(app / "Contents" / "Info.plist", "wb") as fh:
        plistlib.dump({"CFBundleIdentifier": "com.brave.Browser"}, fh)
    helper = str(
        app / "Contents/Frameworks/Brave Browser Helper.app/Contents/MacOS/Brave Browser Helper"
    )
    line = {
        "timestamp": "2026-10-23 10:00:00.000000+0200",
        "subsystem": "com.apple.TCC",
        "processID": 567,
        "processImagePath": "/usr/sbin/coreaudiod",
        "eventMessage": "SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=567.177, function=TCCAccessRequest, service=kTCCServiceMicrophone, target_token={pid:2597, auid:501, euid:501},",
    }
    data = tmp_path / "log.json"
    data.write_text("[" + json.dumps(line) + "]")
    script = f"import sys; sys.stdout.write(open({str(data)!r}).read())"
    lookups: list[int] = []

    def lookup(pid: int) -> tuple[str, str | None] | None:
        lookups.append(pid)
        return "Brave Browser Helper", helper

    listener = SensorListener(command=[sys.executable, "-c", script], process_lookup=lookup)
    (event,) = [e async for e in listener.events()]
    assert lookups == [2597]
    assert (event.pid, event.process_name, event.bundle_id) == (
        2597,
        "Brave Browser Helper",
        "com.brave.Browser",
    )
    assert not event.system


async def test_listener_marks_enriched_system_binaries(tmp_path: Path) -> None:
    line = {
        **TCC_ATTRIBUTION,
        "eventMessage": "REQUEST: sender_pid=740, function=TCCAccessRequest, service=kTCCServiceAddressBook",
    }
    data = tmp_path / "log.json"
    data.write_text("[" + json.dumps(line) + "]")
    script = f"import sys; sys.stdout.write(open({str(data)!r}).read())"
    listener = SensorListener(
        command=[sys.executable, "-c", script],
        process_lookup=lambda pid: (
            "cloudd",
            "/System/Library/PrivateFrameworks/CloudKitDaemon.framework/Support/cloudd",
        ),
    )
    (event,) = [e async for e in listener.events()]
    assert event.process_name == "cloudd" and event.system


def test_screen_capture_preflights_for_other_apps_are_not_captures() -> None:
    # One of each ScreenCapture line kind from macOS 27.0.1, 2026-10-23 14:24, truncated at 220
    # chars (REQUEST_MSG newlines were flattened by the dump): WindowServer (406) and coreaudiod
    # (525) preflight Photo Booth (34389), the ring light helper (34393) and Voice Memos
    # (34399); tccd (407) logs each request again. msgID=406.9 is an earlier WindowServer line.
    lines = [
        (
            "WindowServer",
            406,
            "SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=406.215, function=TCCAccessRequest, service=kTCCServiceScreenCapture, target_token={pid:34389, auid:501, euid:501},",
        ),
        (
            "WindowServer",
            406,
            "SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=406.9, function=TCCAccessRequest, service=kTCCServiceScreenCapture, target_token={pid:35078, auid:501, euid:501},",
        ),
        (
            "coreaudiod",
            525,
            "SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=525.369, function=TCCAccessRequest, service=kTCCServiceScreenCapture, target_token={pid:34389, auid:501, euid:501},",
        ),
        (
            "tccd",
            407,
            'REQUEST_MSG: msgID=525.374, msg={ \trequire_purpose=<xpc_null> \tservice="kTCCServiceScreenCapture" \tfunction="TCCAccessRequest" \tpreflight=true \ttarget_token={pid:34399, auid:501, euid:501} \tTCCD_MSG_ID="525.374" \tbackgro',
        ),
        (
            "tccd",
            407,
            "AUTHREQ_CTX: msgID=406.215, function=<private>, service=kTCCServiceScreenCapture, preflight=yes, query=1, client_dict=(null), daemon_dict=<private>",
        ),
        (
            "tccd",
            407,
            "Handling access request to kTCCServiceScreenCapture, from Sub:{com.apple.PhotoBooth}Resp:{TCCDProcess: identifier=com.apple.PhotoBooth, pid=34389, auid=501, euid=501, binary_path=/System/Applications/Photo Booth.app/Cont",
        ),
        (
            "tccd",
            407,
            "Auth:Allowed (Entitled) to kTCCServiceScreenCapture because accessing process TCCDProcess: identifier=com.apple.controlcenter.ringlighthelper, pid=34393, auid=501, euid=501, binary_path=/System/Library/CoreServices/Contr",
        ),
        (
            "tccd",
            407,
            "<TCCDProcess: identifier=com.apple.controlcenter, pid=689> has the com.apple.private.tcc.allow entitlement for service kTCCServiceScreenCapture (composed to parent: (null))",
        ),
        (
            "tccd",
            407,
            "<TCCDProcess: identifier=com.apple.WindowServer, pid=406> has the com.apple.private.tcc.manager.check-by-audit-token entitlement for service kTCCServiceScreenCapture (composed to parent: (null))",
        ),
        ("tccd", 407, "system tccd handled entitlements check for: kTCCServiceScreenCapture"),
    ]
    for process, pid, message in lines:
        assert parse_entry(_entry("com.apple.TCC", process, message, pid=pid)) is None, message


def test_screen_capture_requested_by_the_capturing_app_itself_counts() -> None:
    # Constructed: the client-side libTCC line an app logs for its own request.
    own = _entry(
        "com.apple.TCC",
        "Recorder",
        "SEND: 0/7 synchronous to com.apple.tccd: request: msgID=4242.7, "
        "function=TCCAccessRequest, service=kTCCServiceScreenCapture,",
        pid=4242,
    )
    event = parse_entry(own)
    assert event is not None and (event.sensor, event.pid) == (SensorType.SCREEN_CAPTURE, 4242)


def test_coreaudiod_mic_request_for_a_client_still_counts() -> None:
    # Constructed, same shape as coreaudiod's verbatim ScreenCapture line.
    mic = _entry(
        "com.apple.TCC",
        "coreaudiod",
        "SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=525.368, "
        "function=TCCAccessRequest, service=kTCCServiceMicrophone, target_token={pid:34389, auid:501}",
        pid=525,
    )
    event = parse_entry(mic)
    assert event is not None and (event.sensor, event.pid) == (SensorType.MICROPHONE, 34389)


def _replayd_request(msg_id: str, subject_pid: int, prompt_policy: int = 2) -> str:
    """tccd's REQUEST_MSG for a ScreenCaptureKit request, verbatim from macOS 27.0.1."""
    return (
        f'REQUEST_MSG: msgID={msg_id}, msg={{\n\tservice="kTCCServiceScreenCapture"\n'
        '\tTCCD_MSG_SPI_VERSION=2 (0x2)\n\tfunction="TCCAccessRequest"\n'
        "\tTCCD_MSG_REQUEST_TYPE_KEY=0 (0x0)\n"
        "\tTCC_MSG_REQUEST_AUTHORIZATION_SUBJECT_CREDENTIAL_DICTIONARY_KEY={\n"
        "\t\tTCCD_MSG_CREDENTIAL_AUTHENTICATOR_TYPE_KEY=1 (0x1)\n"
        f"\t\tTCCD_MSG_CREDENTIAL_AUTHENTICATOR_AUDIT_TOKEN_KEY={{pid:{subject_pid}, auid:501, euid:501}}\n"
        "\t}\n\tTCCD_MSG_MESSAGE_OPTION_REQUEST_USAGE_STRING_POLICY_KEY=0 (0x0)\n"
        f"\tTCCD_MSG_MESSAGE_OPTION_REQUEST_PROMPT_POLICY_KEY={prompt_policy} ({prompt_policy:#x})\n"
        f'\tTCCD_MSG_ID="{msg_id}"\n}}'
    )


def test_real_screen_capture_indicator_and_replayd_request_for_client() -> None:
    # Verbatim from macOS 27.0.1, 2026-10-23: two Cmd+Shift+5 captures.
    emitted = _indicator_timeline(
        [
            ("2026-10-23 14:34:56.458282+0200", '["scr:com.apple.systemuiserver"]'),
            ("2026-10-23 14:34:56.465925+0200", "[]"),
            ("2026-10-23 14:35:07.546127+0200", '["scr:com.apple.systemuiserver"]'),
            ("2026-10-23 14:35:07.556026+0200", "[]"),
        ]
    )
    assert emitted == [(SensorType.SCREEN_CAPTURE, "com.apple.systemuiserver")] * 2
    # replayd asks on behalf of the capturing client: tccd names it in the subject audit token.
    request = _entry("com.apple.TCC", "tccd", _replayd_request("733.14", 37712), pid=407)
    event = parse_entry(request)
    assert event is not None and (event.sensor, event.pid) == (SensorType.SCREEN_CAPTURE, 37712)


def test_brave_window_share_is_attributed_to_brave_not_replayd() -> None:
    # Verbatim from macOS 27.0.1, 2026-10-26 10:30: Meet in Brave (pid 6254) sharing a window.
    # replayd (709) logs the SEND; only tccd's REQUEST_MSG names Brave, in the audit token.
    send = _entry(
        "com.apple.TCC",
        "replayd",
        "SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=709.1440, "
        "function=TCCAccessRequest, service=kTCCServiceScreenCapture,",
        pid=709,
    )
    request = _entry("com.apple.TCC", "tccd", _replayd_request("709.1440", 6254), pid=399)
    assert parse_entry(send) is None
    event = parse_entry(request)
    assert event is not None
    assert (event.sensor, event.service, event.pid) == (
        SensorType.SCREEN_CAPTURE,
        "ScreenCapture",
        6254,
    )
    assert (event.process_name, event.bundle_id, event.system) == ("", None, False)


def test_denied_brave_share_is_attributed_to_brave() -> None:
    # Verbatim from macOS 27.0.1, 2026-10-26 10:23: same request while Brave had no grant.
    request = _entry("com.apple.TCC", "tccd", _replayd_request("709.2", 1761), pid=399)
    event = parse_entry(request)
    assert event is not None and (event.sensor, event.pid) == (SensorType.SCREEN_CAPTURE, 1761)


def test_cmd_shift_5_recording_is_attributed_to_screencapture() -> None:
    # Verbatim from macOS 27.0.1, 2026-10-24 20:42: replayd (791) records for screencapture
    # (3506); its own mic preflight for the recording is not a mic access.
    request = _entry("com.apple.TCC", "tccd", _replayd_request("791.2", 3506), pid=399)
    event = parse_entry(request)
    assert event is not None and (event.sensor, event.pid) == (SensorType.SCREEN_CAPTURE, 3506)
    mic_preflight = _entry(
        "com.apple.TCC",
        "replayd",
        "SEND: 0/7 synchronous to com.apple.tccd: request: msgID=791.6, "
        "function=TCCAccessRequest, service=kTCCServiceMicrophone,",
        pid=791,
    )
    assert parse_entry(mic_preflight) is None


def test_window_server_check_of_replayd_names_replayd() -> None:
    # Verbatim from macOS 27.0.1, 2026-10-26 10:23:57: WindowServer (398) checks replayd's
    # own grant. The subject is replayd, a SIP binary the listener's enricher marks system.
    request = _entry(
        "com.apple.TCC", "tccd", _replayd_request("398.149", 709, prompt_policy=1), pid=399
    )
    event = parse_entry(request)
    assert event is not None and (event.sensor, event.pid) == (SensorType.SCREEN_CAPTURE, 709)


async def test_listener_shows_brave_share_and_hides_replayd_check(tmp_path: Path) -> None:
    # The two 2026-10-26 subjects, 2 s apart so the cooldown keeps both.
    brave = _entry("com.apple.TCC", "tccd", _replayd_request("709.1440", 6254), pid=399)
    replayd = {
        **_entry("com.apple.TCC", "tccd", _replayd_request("398.149", 709, 1), pid=399),
        "timestamp": "2026-10-22 13:00:02.000000+0200",
    }
    data = tmp_path / "log.json"
    data.write_text(json.dumps([brave, replayd]))
    script = f"import sys; sys.stdout.write(open({str(data)!r}).read())"
    processes = {
        6254: ("Brave Browser", "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
        709: ("replayd", "/usr/libexec/replayd"),
    }
    listener = SensorListener(command=[sys.executable, "-c", script], process_lookup=processes.get)
    events = [(e.pid, e.process_name, e.system) async for e in listener.events()]
    assert events == [(6254, "Brave Browser", False), (709, "replayd", True)]


def test_audit_token_of_other_services_is_not_a_screen_capture() -> None:
    # Constructed from the ScreenCapture shape: contactsd/sandboxd checks carry audit tokens
    # too (2026-10-26 10:23), but only ScreenCapture requests are attributed this way.
    message = _replayd_request("789.12", 4242).replace("ScreenCapture", "AddressBook")
    assert parse_entry(_entry("com.apple.TCC", "tccd", message, pid=399)) is None


_COREAUDIOD = "/usr/sbin/coreaudiod"
_TCCD = "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd"


def _mic_request(msg_id: str, client: int, preflight: str, forwarded: bool = False) -> str:
    """tccd's REQUEST_MSG for a coreaudiod mic request, verbatim from macOS 27.0.1."""
    forwarder = (
        "\tTCCD_MSG_MESSAGE_OPTION_USAGE_STRING_POLICY_AUTHORIZED_BY_FORWARDER_KEY=false\n"
        if forwarded
        else ""
    )
    return (
        f"REQUEST_MSG: msgID={msg_id}, msg={{\n{forwarder}\trequire_purpose=<xpc_null>\n"
        '\tservice="kTCCServiceMicrophone"\n\tfunction="TCCAccessRequest"\n'
        f"\tpreflight={preflight}\n\ttarget_token={{pid:{client}, auid:501, euid:501}}\n"
        f'\tTCCD_MSG_ID="{msg_id}"\n\tbackground_session=false\n}}'
    )


def _mic_send(msg_id: str, client: int) -> str:
    return (
        f"SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID={msg_id}, "
        "function=TCCAccessRequest, service=kTCCServiceMicrophone, "
        f"target_token={{pid:{client}, auid:501, euid:501}},"
    )


def _manager(daemon_pid: int) -> str:
    return (
        f"<TCCDProcess: identifier=com.apple.audio.coreaudiod, pid={daemon_pid}> has the "
        "com.apple.private.tcc.manager.check-by-audit-token entitlement for service "
        "kTCCServiceMicrophone (composed to parent: (null))"
    )


_HANDLED = "system tccd handled entitlements check for: kTCCServiceMicrophone"

# One coreaudiod mic request each, every line of it, verbatim from macOS 27.0.1. All lines of
# one request share its activityIdentifier (coreaudiod's SEND, both tccds, the forward).
COREAUDIOD_PREFLIGHT_FOR_SCREENCAPTURE = (  # 2026-10-24 20:42, Cmd+Shift+5, no mic input
    167075,
    [
        (_COREAUDIOD, 591, _mic_send("591.81", 3506)),
        (_TCCD, 399, _mic_request("591.81", 3506, "true")),
        (_TCCD, 399, _manager(591)),
        (
            _TCCD,
            399,
            "<TCCDProcess: identifier=com.apple.screencapture, pid=3506> has the "
            "com.apple.private.tcc.check-allow-on-responsible-process entitlement for service "
            "kTCCServiceMicrophone (composed to parent: (null))",
        ),
        (
            _TCCD,
            399,
            "<TCCDProcess: identifier=com.apple.systemuiserver, pid=743> has the "
            "com.apple.private.tcc.allow entitlement for service kTCCServiceMicrophone "
            "(composed to parent: (null))",
        ),
        (
            _TCCD,
            399,
            "Auth:Allowed (Entitled) to kTCCServiceMicrophone because accessing process "
            "TCCDProcess: identifier=com.apple.screencapture, pid=3506, auid=501, euid=501, "
            "binary_path=/usr/sbin/screencapture has the check-allow-on-responsible-process "
            "entitlement and responsible process TCCDProcess: identifier=com.apple.systemuiserver, "
            "pid=743, auid=501, euid=501, responsible_path=/System/Library/CoreServices/"
            "SystemUIServer.app/Contents/MacOS/SystemUIServer, binary_path=/System/Library/"
            "CoreServices/SystemUIServer.app/Contents/MacOS/SystemUIServer has corresponding "
            "allow entitlement",
        ),
        (_TCCD, 399, _HANDLED),
    ],
)
COREAUDIOD_PREFLIGHT_FOR_BRAVE = (  # 2026-10-26 10:23:57, Screen Recording just granted
    191760,
    [
        (_COREAUDIOD, 554, _mic_send("554.126", 1761)),
        (_TCCD, 399, _mic_request("554.126", 1761, "true")),
        (_TCCD, 399, _manager(554)),
        (_TCCD, 399, _manager(554)),
        (
            _TCCD,
            399,
            "FORWARD: to=com.apple.tccd/501, request: "
            + _mic_request("554.126", 1761, "true", forwarded=True).split("msg=", 1)[1],
        ),
        (_TCCD, 654, _mic_request("554.126", 1761, "true", forwarded=True)),
        (
            _TCCD,
            654,
            "AUTHREQ_CTX: msgID=554.126, function=<private>, service=kTCCServiceMicrophone, "
            "preflight=yes, query=1, client_dict=(null), daemon_dict=<private>",
        ),
        (
            _TCCD,
            654,
            "Handling access request to kTCCServiceMicrophone, from Sub:{com.brave.Browser}"
            "Resp:{TCCDProcess: identifier=com.brave.Browser, pid=1761, auid=501, euid=501, "
            "binary_path=/Applications/Brave Browser.app/Contents/MacOS/Brave Browser}, "
            "ReqResult(Auth Right: Allowed (User Consent), promptType: 1,DB Action:None)",
        ),
    ],
)
COREAUDIOD_REQUEST_FOR_VOICE_MEMOS = (  # 2026-10-23 14:25:41, Voice Memos recording
    966506,
    [
        (_COREAUDIOD, 525, _mic_send("525.376", 34399)),
        (_TCCD, 407, _mic_request("525.376", 34399, "false")),
        (_TCCD, 407, _manager(525)),
        (
            _TCCD,
            407,
            "<TCCDProcess: identifier=com.apple.VoiceMemos, pid=34399> has the "
            "com.apple.private.tcc.allow entitlement for service kTCCServiceMicrophone "
            "(composed to parent: (null))",
        ),
        (
            _TCCD,
            407,
            "Auth:Allowed (Entitled) to kTCCServiceMicrophone for TCCDProcess: "
            "identifier=com.apple.VoiceMemos, pid=34399, auid=501, euid=501, "
            "binary_path=/System/Applications/VoiceMemos.app/Contents/MacOS/VoiceMemos; "
            "checked by TCCDProcess: identifier=com.apple.audio.coreaudiod, pid=525, auid=202, "
            "euid=202, binary_path=/usr/sbin/coreaudiod because: IsTCCManager",
        ),
        (_TCCD, 407, _HANDLED),
    ],
)


def _request_entries(
    request: tuple[int, list[tuple[str, int, str]]], activity: int | None = None
) -> list[dict[str, object]]:
    default, lines = request
    return [
        _entry(
            "com.apple.TCC",
            "",
            message,
            pid=pid,
            processImagePath=path,
            activityIdentifier=default if activity is None else activity,
        )
        for path, pid, message in lines
    ]


def _mic_pids(entries: list[dict[str, object]]) -> list[int | None]:
    parser = SensorEventParser()
    return [e.pid for entry in entries for e in parser.parse(entry)]


@pytest.mark.parametrize(
    "request_",
    [COREAUDIOD_PREFLIGHT_FOR_SCREENCAPTURE, COREAUDIOD_PREFLIGHT_FOR_BRAVE],
    ids=["screencapture", "brave"],
)
def test_coreaudiod_mic_preflight_is_not_a_mic_access(
    request_: tuple[int, list[tuple[str, int, str]]],
) -> None:
    # Before: 4-5 microphone events per preflight, with no `mic:` indicator at all.
    assert _mic_pids(_request_entries(request_)) == []


def test_coreaudiod_real_mic_request_still_counts() -> None:
    # preflight=false: Voice Memos recording. coreaudiod's SEND waits for tccd's REQUEST_MSG.
    assert _mic_pids(_request_entries(COREAUDIOD_REQUEST_FOR_VOICE_MEMOS)) == [34399] * 3


def test_coreaudiod_preflight_without_activity_id_falls_back_to_per_line() -> None:
    # activityIdentifier 0 links nothing: every line is judged on its own, as before.
    pids = _mic_pids(_request_entries(COREAUDIOD_PREFLIGHT_FOR_BRAVE, activity=0))
    assert pids and set(pids) == {1761}


def test_preflight_of_one_request_does_not_hide_the_next() -> None:
    entries = _request_entries(COREAUDIOD_PREFLIGHT_FOR_BRAVE) + _request_entries(
        COREAUDIOD_REQUEST_FOR_VOICE_MEMOS
    )
    assert _mic_pids(entries) == [34399] * 3


def test_calaccessd_tcc_checks_on_behalf_of_others_are_not_accesses() -> None:
    # Verbatim from macOS 27.0.1 (2026-10-22 13:17): calaccessd checking Calendar for routined.
    send = _entry(
        "com.apple.TCC",
        "calaccessd",
        "SEND: 0/7 synchronous to com.apple.tccd: request: msgID=710.183, "
        "function=TCCAccessRequest, service=kTCCServiceCalendar,",
        pid=710,
        processImagePath="/System/Library/PrivateFrameworks/CalendarDaemon.framework/Support/calaccessd",
    )
    manager = _entry(
        "com.apple.TCC",
        "tccd",
        "<TCCDProcess: identifier=com.apple.calaccessd, pid=710> has the "
        "com.apple.private.tcc.manager.check-by-audit-token entitlement for service "
        "kTCCServiceCalendar (composed to parent: (null))",
        pid=648,
    )
    assert parse_entry(send) is None
    assert parse_entry(manager) is None


async def _indicator_events(
    tmp_path: Path, attributions: str, exes: dict[str, list[str]]
) -> list[tuple[str | None, bool]]:
    line = _indicator(f"Active activity attributions changed to {attributions}")
    data = tmp_path / "log.json"
    data.write_text("[" + json.dumps(line) + "]")
    script = f"import sys; sys.stdout.write(open({str(data)!r}).read())"
    listener = SensorListener(
        command=[sys.executable, "-c", script], bundle_exes=lambda b: exes.get(b, [])
    )
    return [(e.bundle_id, e.system) async for e in listener.events()]


async def test_indicator_events_for_apps_in_sip_locations_are_system(tmp_path: Path) -> None:
    # Attributions seen on macOS 27.0.1 (2026-10-23), with the apps' real install paths.
    exes = {
        "com.apple.PhotoBooth": ["/System/Applications/Photo Booth.app/Contents/MacOS/Photo Booth"],
        "com.apple.systemuiserver": [
            "/System/Library/CoreServices/SystemUIServer.app/Contents/MacOS/SystemUIServer"
        ],
    }
    events = await _indicator_events(
        tmp_path, '["cam:com.apple.PhotoBooth", "scr:com.apple.systemuiserver"]', exes
    )
    assert events == [("com.apple.PhotoBooth", True), ("com.apple.systemuiserver", True)]


async def test_indicator_bundle_id_alone_never_makes_an_event_system(tmp_path: Path) -> None:
    # A copy outside SIP claiming an Apple bundle id, an Apple id with no running process
    # found, and a third-party app.
    exes = {
        "com.apple.PhotoBooth": [
            "/System/Applications/Photo Booth.app/Contents/MacOS/Photo Booth",
            "/Users/u/Applications/Photo Booth.app/Contents/MacOS/Photo Booth",
        ],
        "com.brave.Browser": ["/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"],
    }
    attributions = (
        '["cam:com.apple.PhotoBooth", "mic:com.apple.VoiceMemos", "mic:com.brave.Browser"]'
    )
    events = await _indicator_events(tmp_path, attributions, exes)
    assert events == [
        ("com.apple.PhotoBooth", False),
        ("com.apple.VoiceMemos", False),
        ("com.brave.Browser", False),
    ]


async def test_slow_indicator_lookup_times_out_and_keeps_the_event_visible(
    tmp_path: Path,
) -> None:
    line = _indicator('Active activity attributions changed to ["cam:com.apple.PhotoBooth"]')
    data = tmp_path / "log.json"
    data.write_text("[" + json.dumps(line) + "]")
    script = f"import sys; sys.stdout.write(open({str(data)!r}).read())"

    def stuck(bundle_id: str) -> list[str]:
        time.sleep(1.0)
        return ["/System/Applications/Photo Booth.app/Contents/MacOS/Photo Booth"]

    listener = SensorListener(
        command=[sys.executable, "-c", script], bundle_exes=stuck, bundle_lookup_timeout_s=0.05
    )
    start = time.monotonic()
    (event,) = [e async for e in listener.events()]
    assert not event.system and time.monotonic() - start < 0.9


def test_possible_exes_for_bundle_counts_every_way_to_claim_an_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def app(path: str, ident: str | None) -> Path:
        contents = tmp_path / path / "Contents"
        contents.mkdir(parents=True)
        if ident is not None:
            with open(contents / "Info.plist", "wb") as fh:
                plistlib.dump({"CFBundleIdentifier": ident}, fh)
        return contents / "MacOS"

    spy = str(app("Spy.app", "com.example.spy") / "Spy")
    other = str(app("Other.app", "com.example.other") / "Other")
    app("Outer.app", "com.example.outer")
    nested = str(app("Outer.app/Contents/Resources/Inner.app", "com.example.spy") / "Inner")
    moved = str(app("Moved.app", None) / "Moved")  # Info.plist moved away after launch
    exes = [spy, other, nested, moved, None]

    class Proc:
        def __init__(self, exe: str | None) -> None:
            self.info = {"exe": exe}

    monkeypatch.setattr(psutil, "process_iter", lambda attrs: map(Proc, exes))
    assert possible_exes_for_bundle("com.example.spy") == [spy, nested, moved]
    assert possible_exes_for_bundle("com.example.missing") == [moved]


# --- M1.5: log-stream backpressure and pre-filtering ----------------------------------------


def test_decoder_handles_a_burst_and_keeps_a_trailing_partial() -> None:
    decoder = JsonStreamDecoder()
    burst = "[" + ",".join(f'{{"subsystem":"com.apple.TCC","i":{i}}}' for i in range(5000))
    entries = decoder.feed(burst)
    assert len(entries) == 5000
    assert entries[0]["i"] == 0 and entries[-1]["i"] == 4999
    # A partial object at the tail is held until the next chunk completes it.
    assert decoder.feed(',{"subsystem":"com.apple.cmio","i":5') == []
    (tail,) = decoder.feed('000}')
    assert tail["i"] == 5000


def test_is_candidate_subsystem_matches_sensor_subsystems_only() -> None:
    assert is_candidate_subsystem("com.apple.TCC")
    assert is_candidate_subsystem("com.apple.cmio.AVCaptureSession")
    assert is_candidate_subsystem("com.apple.controlcenter")
    assert not is_candidate_subsystem("com.apple.WindowServer")
    assert not is_candidate_subsystem("")


class _StubListener(SensorListener):
    """A listener whose `entries` replays a fixed sequence instead of reading `log stream`."""

    def __init__(self, entries: list[dict[str, object]], **kwargs: object) -> None:
        super().__init__(command=["unused"], **kwargs)  # type: ignore[arg-type]
        self._stub = entries

    async def entries(self) -> AsyncIterator[dict[str, object]]:
        for entry in self._stub:
            yield entry


async def test_reader_filters_non_sensor_subsystems() -> None:
    listener = _StubListener(
        [
            {"subsystem": "com.apple.TCC", "eventMessage": "kTCCServiceCamera"},
            {"subsystem": "com.apple.WindowServer", "eventMessage": "noise"},
        ]
    )
    queue: asyncio.Queue[dict[str, object] | None] = asyncio.Queue(maxsize=10)
    await listener._read_into(queue)
    assert listener.filtered == 1
    assert listener.dropped == 0
    first = queue.get_nowait()
    assert first is not None and first["subsystem"] == "com.apple.TCC"
    assert queue.get_nowait() is None


async def test_reader_drops_oldest_under_backpressure_without_blocking() -> None:
    listener = _StubListener(
        [{"subsystem": "com.apple.TCC", "eventMessage": "kTCCServiceCamera", "i": i} for i in range(50)]
    )
    # A tiny queue and no consumer: the reader must still finish (never block), shedding load.
    queue: asyncio.Queue[dict[str, object] | None] = asyncio.Queue(maxsize=4)
    await asyncio.wait_for(listener._read_into(queue), timeout=1.0)
    assert listener.dropped >= 40
    drained = []
    while not queue.empty():
        drained.append(queue.get_nowait())
    assert drained[-1] is None  # the stop marker is always delivered last
