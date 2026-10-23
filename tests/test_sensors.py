from __future__ import annotations

import json
import plistlib
import sys
from pathlib import Path

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


def _indicator(message: str) -> dict[str, object]:
    return _entry(
        "com.apple.controlcenter",
        "ControlCenter",
        message,
        pid=500,
        category="sensor-indicators",
        messageType="Default",
    )


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
        _indicator('Active activity attributions changed to ["cam:com.apple.PhotoBooth"]')
    )
    assert again.sensor is SensorType.CAMERA


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
    entry = _entry(
        "com.apple.TCC",
        "WindowServer",
        "SEND: 0/7 synchronous to com.apple.tccd.system: request: msgID=406.9, function=TCCAccessRequest, service=kTCCServiceScreenCapture, target_token={pid:35078, auid:501, euid:501},",
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
