from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

import pytest

from safemaxxing import tcc_inspector
from safemaxxing.diagnostics import Status, check_tcc_permissions
from safemaxxing.tcc_inspector import ClientType, TccEntry, TccUnavailable

# A small subset of the real `access` schema; the reader must tolerate the extra columns.
_SCHEMA = (
    "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER, "
    "auth_reason INTEGER, auth_version INTEGER, csreq BLOB, policy_id INTEGER, "
    "indirect_object_identifier TEXT, last_modified INTEGER)"
)
_ROWS = [
    # service, client, client_type, auth_value
    ("kTCCServiceCamera", "com.zoom.xos", 0, 2),
    ("kTCCServiceCamera", "/usr/bin/python3", 1, 2),
    ("kTCCServiceMicrophone", "/Users/x/Downloads/sketchy", 1, 2),
    ("kTCCServiceScreenCapture", "/Applications/OBS.app/Contents/MacOS/OBS", 1, 2),
    ("kTCCServiceCamera", "com.denied.app", 0, 0),  # denied -> excluded
    ("kTCCServiceContactsFull", "com.other.app", 0, 2),  # not sensitive -> excluded
]


_INSERT = (
    "INSERT INTO access (service, client, client_type, auth_value, last_modified) "
    "VALUES (?, ?, ?, ?, 1700000000)"
)


def make_db(path: Path, rows: list[tuple[str, str, int, int]] = _ROWS, wal: bool = False) -> str:
    conn = sqlite3.connect(path)
    if wal:
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(_SCHEMA)
    conn.executemany(_INSERT, rows)
    conn.commit()
    conn.close()
    return str(path)


def entry(client: str, client_type: ClientType = ClientType.PATH) -> TccEntry:
    return TccEntry(
        service="kTCCServiceCamera",
        client=client,
        client_type=client_type,
        auth_value=tcc_inspector.AuthValue.ALLOWED,
        auth_reason=2,
        last_modified=1700000000,
        source=tcc_inspector.SYSTEM_TCC_DB,
    )


def test_read_tcc_filters_to_granted_sensitive_services(tmp_path: Path) -> None:
    db = make_db(tmp_path / "TCC.db")
    entries = tcc_inspector.read_tcc(db)
    # Four granted, sensitive rows; the denied and the non-sensitive ones are dropped.
    assert len(entries) == 4
    services = {e.service for e in entries}
    assert "kTCCServiceContactsFull" not in services
    assert all(e.auth_value >= tcc_inspector.AuthValue.ALLOWED for e in entries)


def test_read_tcc_maps_client_type_and_path(tmp_path: Path) -> None:
    db = make_db(tmp_path / "TCC.db")
    by_client = {e.client: e for e in tcc_inspector.read_tcc(db)}
    assert by_client["com.zoom.xos"].client_type is ClientType.BUNDLE_ID
    assert by_client["com.zoom.xos"].path is None
    assert by_client["/usr/bin/python3"].client_type is ClientType.PATH
    assert by_client["/usr/bin/python3"].path == "/usr/bin/python3"


def test_read_tcc_missing_database_raises(tmp_path: Path) -> None:
    with pytest.raises(TccUnavailable, match="not present"):
        tcc_inspector.read_tcc(str(tmp_path / "nope.db"))


def test_read_tcc_opens_read_only(tmp_path: Path) -> None:
    # A read-only connection must refuse to write, proving we cannot disturb the real database.
    db = make_db(tmp_path / "TCC.db")
    conn = sqlite3.connect(tcc_inspector._ro_uri(db), uri=True)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM access")
    conn.close()


def test_inspect_aggregates_and_reports_unavailable(tmp_path: Path) -> None:
    db = make_db(tmp_path / "TCC.db")
    entries, unavailable = tcc_inspector.inspect((db, str(tmp_path / "missing.db")))
    assert len(entries) == 4
    assert len(unavailable) == 1 and "missing.db" in unavailable[0]


def test_risk_interpreter() -> None:
    assert "interpreter (python3)" in tcc_inspector.risk_reasons(entry("/usr/bin/python3"))


def test_risk_outside_applications_and_missing() -> None:
    reasons = tcc_inspector.risk_reasons(entry("/Users/x/Downloads/spy"), exists=False)
    assert "outside /Applications" in reasons
    assert "binary missing on disk" in reasons


def test_risk_unsigned() -> None:
    reasons = tcc_inspector.risk_reasons(
        entry("/Applications/Spy.app/Contents/MacOS/Spy"), exists=True, signing="unsigned"
    )
    assert reasons == ["unsigned"]


def test_risk_clean_app_and_bundle_id_have_no_reasons() -> None:
    clean = entry("/Applications/Zoom.app/Contents/MacOS/zoom.us")
    assert (
        tcc_inspector.risk_reasons(clean, exists=True, signing="Developer ID Application: X") == []
    )
    assert tcc_inspector.risk_reasons(entry("com.zoom.xos", ClientType.BUNDLE_ID)) == []


def test_codesign_identity_uses_injected_runner() -> None:
    def fake(_argv: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            _argv, 0, stdout="", stderr="code object is not signed at all"
        )

    assert tcc_inspector.codesign_identity("/Applications/Spy.app", runner=fake) == "unsigned"


def test_doctor_check_warns_on_high_risk(tmp_path: Path) -> None:
    db = make_db(tmp_path / "TCC.db")
    check = check_tcc_permissions(paths=(db,))
    assert check.status is Status.WARN
    assert "high-risk" in check.detail


def test_doctor_check_warns_when_unreadable(tmp_path: Path) -> None:
    check = check_tcc_permissions(paths=(str(tmp_path / "missing.db"),))
    assert check.status is Status.WARN


def test_read_tcc_sees_a_grant_still_in_the_write_ahead_log(tmp_path: Path) -> None:
    # tccd writes in WAL mode; a grant not yet checkpointed lives only in TCC.db-wal, and an
    # immutable open would skip it -- the newest grant, the one most worth seeing.
    db = make_db(tmp_path / "TCC.db", rows=[], wal=True)
    writer = sqlite3.connect(db)
    try:
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(_INSERT, ("kTCCServiceCamera", "/tmp/fresh", 1, 2))
        writer.commit()
        assert (tmp_path / "TCC.db-wal").stat().st_size > 0
        assert [e.client for e in tcc_inspector.read_tcc(db)] == ["/tmp/fresh"]
    finally:
        writer.close()


def test_read_tcc_falls_back_to_immutable_in_an_unwritable_directory(tmp_path: Path) -> None:
    # A plain read-only open of a WAL database needs to create TCC.db-shm; when the directory
    # refuses that, the immutable open still reads the checkpointed rows.
    folder = tmp_path / "ro"
    folder.mkdir()
    db = make_db(folder / "TCC.db", wal=True)
    folder.chmod(0o555)
    try:
        assert len(tcc_inspector.read_tcc(db)) == 4
    finally:
        folder.chmod(0o755)


def test_read_tcc_rejects_a_file_that_is_not_a_database(tmp_path: Path) -> None:
    bogus = tmp_path / "TCC.db"
    bogus.write_bytes(b"not sqlite at all" * 100)
    with pytest.raises(TccUnavailable):
        tcc_inspector.read_tcc(str(bogus))


def test_doctor_check_warns_when_one_database_is_unread_even_if_the_rest_is_clean(
    tmp_path: Path,
) -> None:
    clean = make_db(tmp_path / "TCC.db", rows=[("kTCCServiceCamera", "com.zoom.xos", 0, 2)])
    check = check_tcc_permissions(paths=(str(tmp_path / "system.db"), clean))
    # Without the system database the screen/accessibility/FDA grants are unknown, so no OK.
    assert check.status is Status.WARN
    assert "none high-risk" in check.detail
    assert "unread" in check.detail and "system.db" in check.detail


def test_doctor_check_is_ok_only_when_every_database_is_read_and_clean(tmp_path: Path) -> None:
    clean = make_db(tmp_path / "TCC.db", rows=[("kTCCServiceCamera", "com.zoom.xos", 0, 2)])
    check = check_tcc_permissions(paths=(clean,))
    assert check.status is Status.OK
    assert check.detail == "1 sensitive grant(s), none high-risk"
