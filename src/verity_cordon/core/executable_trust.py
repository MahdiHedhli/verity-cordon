"""Hardened local executable discovery, snapshots, and drift checks.

The functions in this module deliberately avoid ``shutil.which``. Search-path
entries and every ancestor of the selected executable are part of the trust
decision, and the executable is hashed through a no-following file descriptor
whose identity is checked before and after the read.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from verity_cordon.core.errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class PathIdentity:
    """Security-relevant identity captured for one filesystem path."""

    path: Path
    device: int
    inode: int
    owner: int
    mode: int
    size: int
    modified_ns: int
    link_target: str | None


@dataclass(frozen=True, slots=True)
class ExecutableIdentity:
    """Trusted source/target chains and digest for an executable."""

    source_chain: tuple[PathIdentity, ...]
    target_chain: tuple[PathIdentity, ...]
    digest: str


def _path_chain(path: Path) -> list[Path]:
    current = path
    values: list[Path] = []
    while True:
        values.append(current)
        if current.parent == current:
            break
        current = current.parent
    values.reverse()
    return values


def path_identity(path: Path) -> PathIdentity:
    """Capture identity without following a final symbolic link."""

    details = path.lstat()
    link_target: str | None = None
    if stat.S_ISLNK(details.st_mode):
        link_target = os.readlink(path)
        if not _same_file_state(details, path.lstat()):
            raise OSError("path identity changed during inspection")
    return PathIdentity(
        path=path,
        device=details.st_dev,
        inode=details.st_ino,
        owner=details.st_uid,
        mode=stat.S_IMODE(details.st_mode),
        size=details.st_size,
        modified_ns=details.st_mtime_ns,
        link_target=link_target,
    )


def same_path_identity(left: PathIdentity, right: PathIdentity) -> bool:
    """Compare stable identity fields while allowing expected content writes."""

    return (
        left.path == right.path
        and left.device == right.device
        and left.inode == right.inode
        and left.owner == right.owner
        and left.mode == right.mode
        and left.link_target == right.link_target
    )


def same_open_identity(expected: PathIdentity, observed: os.stat_result) -> bool:
    """Compare a path snapshot with an already-open descriptor."""

    return (
        expected.device == observed.st_dev
        and expected.inode == observed.st_ino
        and expected.owner == observed.st_uid
        and expected.mode == stat.S_IMODE(observed.st_mode)
    )


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_uid == right.st_uid
        and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )


def _validate_path(
    path: Path,
    *,
    allow_symlink: bool = False,
    path_label: str,
) -> PathIdentity:
    details = path.lstat()
    if stat.S_ISLNK(details.st_mode):
        if not allow_symlink:
            raise ConfigurationError(f"A {path_label} path must not be a symbolic link.")
    elif not stat.S_ISDIR(details.st_mode) and not stat.S_ISREG(details.st_mode):
        raise ConfigurationError(f"A {path_label} path has an unsupported file type.")
    if os.name != "nt":
        unsafe_mode = not stat.S_ISLNK(details.st_mode) and bool(
            stat.S_IMODE(details.st_mode) & 0o022
        )
        if details.st_uid not in {0, os.geteuid()} or unsafe_mode:
            raise ConfigurationError(f"A {path_label} path has unsafe ownership or mode.")
    return path_identity(path)


def snapshot_trusted_directory(
    path: Path,
    *,
    current_user_only: bool,
    directory_label: str = "trusted directory",
    ancestor_label: str = "trusted directory",
) -> tuple[PathIdentity, ...]:
    """Validate and snapshot a private absolute directory and its ancestors."""

    if not path.is_absolute() or path.is_symlink():
        raise ConfigurationError(f"A {directory_label} is unsafe.")
    try:
        details = path.lstat()
    except OSError as exc:
        raise ConfigurationError(f"A {directory_label} is unavailable.") from exc
    if not stat.S_ISDIR(details.st_mode):
        raise ConfigurationError(f"A {directory_label} path is not a directory.")
    if os.name != "nt":
        if current_user_only and details.st_uid != os.geteuid():
            raise ConfigurationError(f"A {directory_label} has an unsafe owner.")
        unsafe_mode = stat.S_IMODE(details.st_mode) & 0o022
        if details.st_uid not in {0, os.geteuid()} or unsafe_mode:
            raise ConfigurationError(f"A {directory_label} has unsafe permissions.")
    try:
        return tuple(_validate_path(item, path_label=ancestor_label) for item in _path_chain(path))
    except ConfigurationError:
        raise
    except OSError as exc:
        raise ConfigurationError(f"A {directory_label} path is unavailable.") from exc


def _digest_verified_file(
    path: Path,
    expected: PathIdentity,
    *,
    executable_label: str,
) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    digest = sha256()
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not same_open_identity(expected, before):
            raise ConfigurationError(f"The {executable_label} cannot be verified.")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if not _same_file_state(before, after):
            raise ConfigurationError(f"The {executable_label} changed during verification.")
    except ConfigurationError:
        raise
    except OSError as exc:
        raise ConfigurationError(f"The {executable_label} cannot be verified.") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return digest.hexdigest()


def snapshot_trusted_executable(
    source: Path,
    *,
    executable_label: str = "trusted executable",
    ancestor_label: str = "trusted executable",
) -> tuple[Path, ExecutableIdentity]:
    """Resolve and snapshot one absolute executable without trusting a symlink.

    The source chain records the operator-selected path, including a permitted
    final symlink. The target chain records the fully resolved regular file.
    Both chains and the content digest are required for a later recheck.
    """

    if not source.is_absolute():
        raise ConfigurationError(f"The {executable_label} path must be absolute.")
    try:
        source_details = source.lstat()
        source_chain = tuple(
            _validate_path(
                item,
                allow_symlink=item == source,
                path_label=ancestor_label,
            )
            for item in _path_chain(source)
        )
        resolved = source.resolve(strict=True) if stat.S_ISLNK(source_details.st_mode) else source
        target_chain = tuple(
            _validate_path(item, path_label=ancestor_label) for item in _path_chain(resolved)
        )
        target_details = resolved.lstat()
    except ConfigurationError:
        raise
    except OSError as exc:
        raise ConfigurationError(f"The {executable_label} is unavailable.") from exc
    if not stat.S_ISREG(target_details.st_mode) or not os.access(resolved, os.X_OK):
        raise ConfigurationError(f"The {executable_label} must be a regular executable file.")
    if os.name != "nt" and stat.S_IMODE(target_details.st_mode) & 0o022:
        raise ConfigurationError(f"The {executable_label} has unsafe permissions.")
    target_identity = target_chain[-1]
    digest = _digest_verified_file(
        resolved,
        target_identity,
        executable_label=executable_label,
    )
    if not recheck_path_chain(source_chain) or not recheck_path_chain(target_chain):
        raise ConfigurationError(f"The {executable_label} changed during verification.")
    return resolved, ExecutableIdentity(
        source_chain=source_chain,
        target_chain=target_chain,
        digest=digest,
    )


def resolve_trusted_executable(
    executable_name: str,
    explicit_path: Path | None,
    *,
    search_path: str | None = None,
    executable_label: str = "trusted executable",
    ancestor_label: str = "trusted executable",
) -> tuple[Path, ExecutableIdentity]:
    """Resolve an explicit path or search a strictly absolute ``PATH``.

    Empty or relative search entries invalidate the complete search instead of
    being skipped. This prevents an attacker-controlled working directory from
    becoming an implicit executable source.
    """

    if (
        not executable_name
        or executable_name in {".", ".."}
        or "\x00" in executable_name
        or Path(executable_name).name != executable_name
    ):
        raise ConfigurationError("The trusted executable name is invalid.")
    if explicit_path is not None:
        return snapshot_trusted_executable(
            explicit_path,
            executable_label=executable_label,
            ancestor_label=ancestor_label,
        )
    raw_path = os.environ.get("PATH", "") if search_path is None else search_path
    entries = raw_path.split(os.pathsep)
    if not entries or any(not entry or not Path(entry).is_absolute() for entry in entries):
        raise ConfigurationError("PATH must contain only non-empty absolute entries.")
    for entry in entries:
        candidate = Path(entry) / executable_name
        if candidate.exists() or candidate.is_symlink():
            return snapshot_trusted_executable(
                candidate,
                executable_label=executable_label,
                ancestor_label=ancestor_label,
            )
    raise ConfigurationError(f"The {executable_label} is unavailable.")


def recheck_path_chain(snapshot: tuple[PathIdentity, ...]) -> bool:
    """Return whether every path still has its snapshotted identity and mode."""

    try:
        return all(same_path_identity(item, path_identity(item.path)) for item in snapshot)
    except OSError:
        return False


def _chains_match(
    left: tuple[PathIdentity, ...],
    right: tuple[PathIdentity, ...],
) -> bool:
    return len(left) == len(right) and all(
        same_path_identity(left_item, right_item)
        for left_item, right_item in zip(left, right, strict=True)
    )


def recheck_trusted_executable(
    resolved_path: Path,
    expected: ExecutableIdentity,
    *,
    executable_label: str = "trusted executable",
    ancestor_label: str = "trusted executable",
) -> bool:
    """Re-snapshot an executable and verify its original source and target."""

    try:
        _, current = snapshot_trusted_executable(
            resolved_path,
            executable_label=executable_label,
            ancestor_label=ancestor_label,
        )
    except ConfigurationError:
        return False
    return (
        _chains_match(current.target_chain, expected.target_chain)
        and current.digest == expected.digest
        and recheck_path_chain(expected.source_chain)
    )
