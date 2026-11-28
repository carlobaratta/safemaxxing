from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from safemaxxing.secure_fs import (
    UntrustedPathError,
    ensure_private_dir,
    invoking_user,
    open_private_output,
    read_trusted_text,
    write_atomic,
)


def mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_private_dir_gets_its_mode_whatever_the_umask(tmp_path: Path) -> None:
    old = os.umask(0o000)
    try:
        ensure_private_dir(tmp_path / "a" / "state")
    finally:
        os.umask(old)
    assert mode(tmp_path / "a" / "state") == 0o755
    ensure_private_dir(tmp_path / "a" / "state")  # an existing private dir is fine


def test_private_dir_refuses_a_symlink_a_shared_dir_and_a_file(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(UntrustedPathError, match="symlink"):
        ensure_private_dir(tmp_path / "link")
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o775)
    with pytest.raises(UntrustedPathError, match="writable by its group"):
        ensure_private_dir(shared)
    (tmp_path / "file").write_text("")
    with pytest.raises(NotADirectoryError):
        ensure_private_dir(tmp_path / "file")


def test_read_trusted_text_refuses_what_another_user_could_change(tmp_path: Path) -> None:
    assert read_trusted_text(tmp_path / "missing") is None
    good = tmp_path / "good"
    good.write_text("203.0.113.9\n")
    good.chmod(0o644)
    assert read_trusted_text(good) == "203.0.113.9\n"
    good.chmod(0o666)
    with pytest.raises(UntrustedPathError, match="writable"):
        read_trusted_text(good)
    good.chmod(0o644)
    (tmp_path / "link").symlink_to(good)
    with pytest.raises(UntrustedPathError, match="symlink"):
        read_trusted_text(tmp_path / "link")
    os.mkfifo(tmp_path / "fifo")  # opening a FIFO would block a reader for ever
    with pytest.raises(UntrustedPathError, match="regular"):
        read_trusted_text(tmp_path / "fifo")
    with pytest.raises(ValueError, match="larger than 4 bytes"):
        read_trusted_text(good, limit=4)


def test_write_atomic_sets_the_mode_and_leaves_no_temp_file(tmp_path: Path) -> None:
    target = tmp_path / "state" / "pf-reference"
    write_atomic(target, "token=1\n", mode=0o600)
    write_atomic(target, b"token=2\n", mode=0o600, durable=False)
    assert target.read_text() == "token=2\n" and mode(target) == 0o600
    assert [p.name for p in target.parent.iterdir()] == ["pf-reference"]
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    with pytest.raises(UntrustedPathError):
        write_atomic(shared / "blocklist", "203.0.113.9\n")
    assert list(shared.iterdir()) == []


def test_private_output_is_0600_and_never_written_through_a_link(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    with open_private_output(out) as fh:
        fh.write("long text\n")
    with open_private_output(out) as fh:  # an existing file of ours is truncated, then 0600
        fh.write("short\n")
    assert out.read_text() == "short\n" and mode(out) == 0o600
    victim = tmp_path / "sudoers"
    victim.write_text("keep me\n")
    (tmp_path / "symlink").symlink_to(victim)
    with pytest.raises(UntrustedPathError, match="symlink"):
        open_private_output(tmp_path / "symlink")
    os.link(victim, tmp_path / "hardlink")
    with pytest.raises(UntrustedPathError, match="hard links"):
        open_private_output(tmp_path / "hardlink")
    assert victim.read_text() == "keep me\n"


def test_invoking_user_only_under_sudo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert invoking_user() == (501, 20)
    monkeypatch.setenv("SUDO_UID", "not-a-number")
    assert invoking_user() is None
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    assert invoking_user() is None
