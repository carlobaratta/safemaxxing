"""Filesystem rules for a process that runs as root and keeps its state on disk.

safemaxxing keeps its state in root-owned places (`/Library/Application Support/safemaxxing`,
`/var/run/safemaxxing`, `/Library/LaunchDaemons`, `/var/log`) and acts on what it reads back:
the boot job feeds the block list to pfctl, Paranoia Mode trusts the pinned Team IDs. Three
rules keep another user from steering those writes and reads:

* a directory written into is a real directory (no symlink), owned by this process's user or
  root, and writable by nobody else, so its owner cannot swap a file between write and use;
* a file whose content is acted on is a regular file reached without a symlink, owned by this
  process's user or root, and not writable by its group or by others;
* a file the user names on the command line (`--out`) is created 0600 without following a
  symlink or a second hard link, and handed to the user who ran sudo, never left readable to
  everyone.

"This process's user" is root in production and the test runner's user in the unit tests, so
the same checks run unchanged in both.
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import tempfile
from pathlib import Path
from typing import IO

# Group- or world-writable: someone other than the owner could change it.
_SHARED_WRITE = stat.S_IWGRP | stat.S_IWOTH


class UntrustedPathError(PermissionError):
    """A path another user could have planted or can still change; refused, never followed."""


def _trusted_owner(uid: int) -> bool:
    return uid in (0, os.geteuid())


def _refuse_untrusted(path: Path, st: os.stat_result, kind: str) -> None:
    if not _trusted_owner(st.st_uid):
        raise UntrustedPathError(f"{path}: {kind} owned by uid {st.st_uid}, not root")
    if st.st_mode & _SHARED_WRITE:
        raise UntrustedPathError(f"{path}: {kind} writable by its group or by others")


def ensure_private_dir(path: Path, mode: int = 0o755) -> None:
    """Create `path` (and missing parents) or check the one already there.

    Raises UntrustedPathError if it is a symlink, belongs to another user or is writable by
    its group or others, and NotADirectoryError if it is something else than a directory.
    A directory created here gets exactly `mode`, whatever the umask.
    """
    try:
        path.mkdir(mode=mode, parents=True, exist_ok=False)
    except FileExistsError:
        pass
    else:
        os.chmod(path, mode)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise UntrustedPathError(f"{path}: a symlink, refusing to write through it")
    if not stat.S_ISDIR(st.st_mode):
        raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(path))
    _refuse_untrusted(path, st, "directory")


def read_trusted_text(path: Path, limit: int = 1 << 20) -> str | None:
    """`path`'s text (UTF-8, undecodable bytes replaced), or None when it does not exist.

    Raises UntrustedPathError for a symlink, a non-regular file (a FIFO would block), a file of
    another user or one others can write, and ValueError past `limit` bytes.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UntrustedPathError(f"{path}: a symlink, refusing to follow it") from None
        raise
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise UntrustedPathError(f"{path}: not a regular file")
        _refuse_untrusted(path, st, "file")
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{path}: larger than {limit} bytes")
    return data.decode("utf-8", errors="replace")


def write_atomic(path: Path, data: str | bytes, mode: int = 0o644, durable: bool = True) -> None:
    """Replace `path` with `data` in one step: a reader sees the old file or the new one.

    The parent directory is checked with `ensure_private_dir` first. `durable` flushes the
    file to disk before the rename, for state that must survive a power cut (not the 1 s
    heartbeat). The temporary file is removed on any failure.
    """
    ensure_private_dir(path.parent)
    payload = data.encode() if isinstance(data, str) else data
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), mode)
            fh.write(payload)
            if durable:
                fh.flush()
                os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def invoking_user() -> tuple[int, int] | None:
    """(uid, gid) of the user who ran `sudo`, when running as root under sudo; else None."""
    if os.geteuid() != 0:
        return None
    try:
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    except (KeyError, ValueError):
        return None
    return (uid, gid) if uid > 0 else None


def open_private_output(path: Path) -> IO[str]:
    """Open `path` for writing a report or a raw capture the user asked for, mode 0600.

    Never follows a symlink, never writes through a second hard link (a root process
    truncating a hard link to /etc/sudoers would truncate sudoers), and refuses an existing
    file that belongs neither to root nor to the user running the command. Under sudo the file
    is handed to the invoking user, so they can read what they asked for and nobody else can.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UntrustedPathError(f"{path}: a symlink, refusing to write through it") from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UntrustedPathError(f"{path}: not a regular file")
        if st.st_nlink > 1:
            raise UntrustedPathError(f"{path}: has other hard links, refusing to overwrite it")
        owner = invoking_user()
        allowed = {0, os.geteuid(), *((owner[0],) if owner else ())}
        if st.st_uid not in allowed:
            raise UntrustedPathError(f"{path}: owned by uid {st.st_uid}, refusing to overwrite it")
        os.ftruncate(fd, 0)
        os.fchmod(fd, 0o600)
        if owner is not None:
            os.fchown(fd, *owner)
        return os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise
