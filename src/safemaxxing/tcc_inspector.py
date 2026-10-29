"""Static audit of the TCC databases: which apps already hold sensitive permissions.

The supervisor watches sensor use as it happens; this reads the standing grants from macOS's
Transparency, Consent and Control store so `doctor` and `safemaxxing permissions` can show, and
flag, what is already allowed. It never writes, and never touches the `tccd` daemon.

## The `access` table

TCC keeps one SQLite database per scope:

* system, at `/Library/Application Support/com.apple.TCC/TCC.db` -- grants that apply to every
  user (ScreenCapture, Accessibility, Full Disk Access, ...); readable only by root *and* only
  with Full Disk Access for the reading tool;
* per user, at `~/Library/Application Support/com.apple.TCC/TCC.db` -- that user's grants
  (Camera, Microphone, ...); reading another process's copy also needs Full Disk Access.

Both store grants in the `access` table. Its columns, on recent macOS (through macOS 27):

| Column | Meaning |
| --- | --- |
| `service` | the TCC service, e.g. `kTCCServiceCamera`, `kTCCServiceScreenCapture`. |
| `client` | who the grant is for: a bundle id or an absolute binary path (see `client_type`). |
| `client_type` | `0` = `client` is a bundle id, `1` = `client` is an absolute path. |
| `auth_value` | `0` denied, `1` unknown (legacy "allowed"), `2` allowed, `3` limited. |
| `auth_reason` | why it holds that value (user set, MDM, system set, ...), as a small integer. |
| `auth_version` | schema/version counter for the row, bumped as the grant is rewritten. |
| `csreq` | the Code Signing Requirement blob (DER): the identity the client must still match. |
| `policy_id` | link to an MDM-delivered policy row, else NULL. |
| `indirect_object_identifier` | the other party of a relationship grant, else `UNUSED`. |
| `last_modified` | Unix time the row was last written. |

Only the stable columns this audit needs are read (`service`, `client`, `client_type`,
`auth_value`, `auth_reason`, `last_modified`), so a schema change to the version-specific
columns above does not break the query.

## What counts as risky

Every grant listed here is a sensitive, standing permission. One is flagged high-risk when the
client is an absolute path and that path is a script interpreter, lives outside `/Applications`,
is missing from disk, or is unsigned / ad-hoc signed -- the shapes malware's own grants tend to
take, as opposed to a normal app bundle in `/Applications` signed by its vendor.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

from safemaxxing.codesign import CODESIGN, parse_codesign
from safemaxxing.models import is_system_path

SYSTEM_TCC_DB = "/Library/Application Support/com.apple.TCC/TCC.db"
USER_TCC_DB = str(Path("~/Library/Application Support/com.apple.TCC/TCC.db").expanduser())

# The sensitive services this audit reports, mapped to a short label for display.
SENSITIVE_SERVICES: Mapping[str, str] = {
    "kTCCServiceCamera": "camera",
    "kTCCServiceMicrophone": "microphone",
    "kTCCServiceScreenCapture": "screen capture",
    "kTCCServiceListenEvent": "input monitoring",
    "kTCCServiceAccessibility": "accessibility",
    "kTCCServiceSystemPolicyAllFiles": "full disk access",
}

# Executables that run arbitrary code handed to them: a grant to one of these is a grant to
# whatever script it is pointed at, so it is treated as high-risk on its own.
INTERPRETERS = frozenset(
    {"python", "python3", "bash", "sh", "zsh", "perl", "ruby", "node", "osascript", "php"}
)


class ClientType(IntEnum):
    """How to read the `client` column."""

    BUNDLE_ID = 0
    PATH = 1


class AuthValue(IntEnum):
    """The grant's state; `ALLOWED` and `LIMITED` mean the client may use the service."""

    DENIED = 0
    UNKNOWN = 1
    ALLOWED = 2
    LIMITED = 3

    @property
    def label(self) -> str:
        return self.name.lower()


# Only states at or above this count as a standing grant worth auditing.
_GRANTED = AuthValue.ALLOWED


class TccUnavailable(RuntimeError):
    """A TCC database could not be read (missing, or Full Disk Access not granted)."""


@dataclass(frozen=True, slots=True)
class TccEntry:
    """One standing grant: a client allowed to use a sensitive service."""

    service: str
    client: str
    client_type: ClientType
    auth_value: AuthValue
    auth_reason: int
    last_modified: int
    source: str  # which database this row came from

    @property
    def service_label(self) -> str:
        """Short name of the service, or the raw id if it is not one we label."""
        return SENSITIVE_SERVICES.get(self.service, self.service)

    @property
    def path(self) -> str | None:
        """The client as an absolute path, or None when it is a bundle id."""
        return self.client if self.client_type is ClientType.PATH else None


def _ro_uri(path: str, immutable: bool = False) -> str:
    """A read-only SQLite URI for `path`; `immutable` also skips locking and the WAL."""
    flags = "mode=ro&immutable=1" if immutable else "mode=ro"
    return f"file:{quote(path)}?{flags}"


def _query_ro(db_path: str, query: str, params: tuple[object, ...]) -> list[tuple[Any, ...]]:
    """Run `query` on a read-only open of `db_path`, falling back to an immutable open.

    The plain read-only open comes first because it reads the write-ahead log: an immutable
    open skips it, so a grant tccd wrote but has not checkpointed yet -- the newest one, the
    one most worth seeing -- would be missed. A WAL database whose directory the reader cannot
    write (so no `-shm` to map) refuses the plain open, and only then is immutable used.
    Neither open can write; a busy database is waited on for at most a second.
    """
    failure: sqlite3.OperationalError | None = None
    for immutable in (False, True):
        try:
            connection = sqlite3.connect(_ro_uri(db_path, immutable), uri=True, timeout=1.0)
        except sqlite3.OperationalError as exc:
            failure = exc
            continue
        try:
            return connection.execute(query, params).fetchall()
        except sqlite3.OperationalError as exc:
            failure = exc
        except sqlite3.DatabaseError as exc:
            # Not a database, or corrupt: an immutable open would fail the same way.
            raise TccUnavailable(f"{db_path}: {exc}") from exc
        finally:
            connection.close()
    raise TccUnavailable(f"{db_path}: {failure} (Full Disk Access may be required)")


def read_tcc(db_path: str, services: Mapping[str, str] = SENSITIVE_SERVICES) -> list[TccEntry]:
    """Read the standing grants for `services` from the TCC database at `db_path`.

    Opens read-only (see `_query_ro`), so it cannot change the database.
    Raises `TccUnavailable` when the file is missing or cannot be opened (typically because the
    reading tool lacks Full Disk Access). Rows whose `auth_value` is not at least `allowed`, and
    services outside `services`, are left out.
    """
    # A TCC-protected path can fail `exists()` with EPERM even when it is there, so this covers
    # both a genuinely missing database and one hidden from a tool without Full Disk Access.
    if not os.path.exists(db_path):
        raise TccUnavailable(f"{db_path}: not present, or not readable without Full Disk Access")
    names = sorted(services)
    placeholders = ",".join("?" * len(names))
    query = (
        "SELECT service, client, client_type, auth_value, auth_reason, last_modified "
        f"FROM access WHERE service IN ({placeholders}) AND auth_value >= ? "
        "ORDER BY service, client"
    )
    rows = _query_ro(db_path, query, (*names, int(_GRANTED)))
    entries: list[TccEntry] = []
    for service, client, client_type, auth_value, auth_reason, last_modified in rows:
        entries.append(
            TccEntry(
                service=service,
                client=client,
                client_type=ClientType(client_type) if client_type in (0, 1) else ClientType.PATH,
                auth_value=AuthValue(auth_value) if auth_value in range(4) else AuthValue.ALLOWED,
                auth_reason=int(auth_reason or 0),
                last_modified=int(last_modified or 0),
                source=db_path,
            )
        )
    return entries


def inspect(
    paths: tuple[str, ...] = (SYSTEM_TCC_DB, USER_TCC_DB),
) -> tuple[list[TccEntry], list[str]]:
    """Read every database in `paths`, returning (grants, reasons the unreadable ones failed)."""
    entries: list[TccEntry] = []
    unavailable: list[str] = []
    for path in paths:
        try:
            entries.extend(read_tcc(path))
        except TccUnavailable as exc:
            unavailable.append(str(exc))
    return entries, unavailable


def codesign_identity(
    path: str, runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None
) -> str:
    """The signing identity of the binary (or its enclosing app) at `path`.

    Returns `unsigned`, `ad-hoc`, an `Authority=` string, or `unknown`; see `parse_codesign`.
    The subprocess call is injectable so tests need not shell out.
    """
    from safemaxxing.codesign import signing_target

    argv = [CODESIGN, "-dv", "--verbose=2", signing_target(path)]
    run = runner or (
        lambda a: subprocess.run(a, capture_output=True, text=True, timeout=3.0, check=False)
    )
    try:
        result = run(argv)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return parse_codesign(result.stderr, result.returncode)


def risk_reasons(
    entry: TccEntry, *, exists: bool | None = None, signing: str | None = None
) -> list[str]:
    """Why `entry` is high-risk, or an empty list when it looks ordinary.

    `exists` (does the client path exist) and `signing` (its codesign identity) are passed in,
    so this function is pure; a bundle-id client, whose path is unknown, yields no reasons here.
    """
    path = entry.path
    if path is None:
        return []
    reasons: list[str] = []
    name = PurePosixPath(path).name
    if name in INTERPRETERS:
        reasons.append(f"interpreter ({name})")
    if not is_system_path(path) and not path.startswith("/Applications/"):
        reasons.append("outside /Applications")
    if exists is False:
        reasons.append("binary missing on disk")
    if signing in ("unsigned", "ad-hoc"):
        reasons.append(str(signing))
    return reasons
