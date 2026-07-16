"""Receipt-bound Codex Desktop setup for the synthetic poisoned-docs fixture.

This module is intentionally separate from the normal Codex installer. It
manages one reserved MCP entry, one reviewed local script, and one private
write-ahead receipt. It never changes Verity ledger or memory state.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import OrderedDict
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from datetime import time as datetime_time
from pathlib import Path
from typing import Any, Final, Literal, Protocol, cast

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows remains an unverified target.
    _fcntl = None  # type: ignore[assignment]

import tomlkit
from pydantic import Field, ValidationError, model_validator

from verity_cordon.codex.installer import (
    LEGACY_RECEIPT_VERSION as NORMAL_LEGACY_RECEIPT_VERSION,
)
from verity_cordon.codex.installer import (
    RECEIPT_VERSION as NORMAL_RECEIPT_VERSION,
)
from verity_cordon.codex.installer import (
    CodexDoctorReport,
    CommandResult,
    CommandRunner,
    doctor_codex,
)
from verity_cordon.core.config import validate_loopback_host
from verity_cordon.core.errors import ConfigurationError, VerityError
from verity_cordon.core.executable_trust import (
    ExecutableIdentity,
    recheck_trusted_executable,
    resolve_trusted_executable,
    snapshot_trusted_directory,
)
from verity_cordon.core.models import StrictModel, format_utc, new_id
from verity_cordon.crypto.canonical import canonical_json_bytes, parse_json_strict

MANAGED_NAME: Final = "verity_cordon_poisoned_docs"
DEMO_RECEIPT_FILENAME: Final = "desktop-demo-receipt.json"
NORMAL_RECEIPT_FILENAME: Final = "codex-integration-receipt.json"
DEMO_DIRECTORY: Final = "desktop-demo"
STAGING_DIRECTORY: Final = "fixture"
STAGED_SCRIPT_NAME: Final = "poisoned_docs_server.py"
FIXTURE_SOURCE: Final = Path("examples/poisoned-docs-mcp/src/poisoned_docs_mcp/server.py")
RECEIPT_VERSION: Final = "1.1.0"
LEGACY_RECEIPT_VERSION: Final = "1.0.0"
CANONICALIZATION: Final = "VC-TOML-MANAGED-1"
EMPTY_SHA256: Final = hashlib.sha256(b"").hexdigest()
MAX_CONFIG_BYTES: Final = 4_194_304
MAX_RECEIPT_BYTES: Final = 65_536
MAX_FIXTURE_BYTES: Final = 1_048_576
MAX_SYSTEM_RESPONSE_BYTES: Final = 131_072
_TOOL_NAMES: Final = ("get_release_guidance", "demo_artifact_sink")
_PREVIEW_CACHE_LIMIT: Final = 64
_CONTROL_ROOM_HEADERS: Final = {
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "deny",
}
_CONTROL_ROOM_CSP_DIRECTIVES: Final = (
    "default-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
)


class DesktopDemoError(VerityError):
    """A content-safe Desktop demo operation could not proceed."""

    code = "desktop_demo_error"


@dataclass(frozen=True, slots=True)
class DesktopDemoResult:
    operation: str
    confirmed: bool
    applied: bool
    state: str
    preview_digest: str
    config_path: Path
    receipt_path: Path
    staging_root: Path
    managed_entry: dict[str, Any]
    artifacts: tuple[dict[str, Any], ...]
    normal_integration_ready: bool
    issues: tuple[str, ...]
    operator_actions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DesktopDemoStatus:
    ready: bool
    fixture_ready: bool
    system_ready: bool
    state: str
    receipt_valid: bool
    managed_entry_intact: bool
    artifacts_intact: bool
    runtimes_intact: bool
    normal_integration_ready: bool
    fixture_probe_ready: bool
    daemon_ready: bool
    ledger_verified: bool
    policy_valid: bool
    memory_view_consistent: bool
    control_room_ready: bool
    control_room_headers_ready: bool
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DesktopFixtureProbe:
    ready: bool
    server_name: str | None
    protocol_version: str | None
    tool_names: tuple[str, ...]
    guidance_sha256: str | None
    sink_invoked: bool
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DesktopSystemReadiness:
    ready: bool
    daemon_ready: bool
    ledger_verified: bool
    policy_valid: bool
    memory_view_consistent: bool
    control_room_ready: bool
    control_room_headers_ready: bool
    issues: tuple[str, ...]


class _Runner(Protocol):
    def __call__(
        self,
        argv: list[str],
        *,
        environment: dict[str, str],
        timeout: float,
    ) -> CommandResult: ...


class _SystemProbe(Protocol):
    def __call__(
        self,
        *,
        host: str,
        port: int,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> DesktopSystemReadiness: ...


class _RuntimeIdentity(StrictModel):
    path: str = Field(min_length=1, max_length=4096)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    version: str = Field(min_length=1, max_length=128, pattern=r"^[ -~]+$")
    size_bytes: int = Field(ge=1, le=1_073_741_824)


class _Artifact(StrictModel):
    relative_path: Literal["poisoned_docs_server.py"]
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=1, le=MAX_FIXTURE_BYTES)
    file_mode: Literal["0600"]


class _ManagedOriginal(StrictModel):
    present: Literal[False]
    digest: None
    parent_table_present: bool


class _SinkOverride(StrictModel):
    approval_mode: Literal["prompt"]


class _ToolOverrides(StrictModel):
    demo_artifact_sink: _SinkOverride


class _ManagedEntry(StrictModel):
    name: Literal["verity_cordon_poisoned_docs"]
    canonicalization: Literal["VC-TOML-MANAGED-1"]
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    transport: Literal["stdio"]
    command: str = Field(min_length=1, max_length=4096)
    args: tuple[Literal["-I"], str]
    cwd: str = Field(min_length=1, max_length=4096)
    enabled: Literal[True]
    required: Literal[True]
    startup_timeout_sec: Literal[5]
    tool_timeout_sec: Literal[5]
    enabled_tools: tuple[
        Literal["get_release_guidance"],
        Literal["demo_artifact_sink"],
    ]
    default_tools_approval_mode: Literal["writes"]
    tool_overrides: _ToolOverrides


class _NormalIntegration(StrictModel):
    receipt_version: Literal["1.0.0", "2.0.0"]
    receipt_path: str = Field(min_length=1, max_length=4096)
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    doctor_ready: Literal[True]


class _Teardown(StrictModel):
    requested_at: str | None
    completed_at: str | None
    config_after_teardown_sha256: str | None


class _ReadinessPolicy(StrictModel):
    policy_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    mode: Literal["enforce", "shadow"]
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    validation_state: Literal["valid", "invalid"]


class _ReadinessResponse(StrictModel):
    schema_version: Literal["1.0.0"]
    ready: bool
    daemon_ready: bool
    ledger_verified: bool
    policy_valid: bool
    memory_view_consistent: bool
    policy: _ReadinessPolicy

    @model_validator(mode="after")
    def readiness_matches_components(self) -> _ReadinessResponse:
        expected = bool(
            self.daemon_ready
            and self.ledger_verified
            and self.policy_valid
            and self.memory_view_consistent
        )
        if self.ready != expected or self.policy_valid != (self.policy.validation_state == "valid"):
            raise ValueError("readiness components are inconsistent")
        return self


class _DesktopReceipt(StrictModel):
    receipt_version: Literal["1.0.0", "1.1.0"]
    installation_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    state: Literal["prepared", "failed", "installed", "removing", "removed"]
    operator_confirmed: Literal[True]
    confirmation_method: Literal["cli_yes", "interactive"]
    preview_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    confirmed_at: str
    created_at: str
    updated_at: str
    digest_algorithm: Literal["SHA-256"]
    codex_home: str = Field(min_length=1, max_length=4096)
    config_path: str = Field(min_length=1, max_length=4096)
    staging_root: str = Field(min_length=1, max_length=4096)
    config_existed_before: bool
    config_before_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    config_mode_before: int | None = Field(default=None, ge=0, le=0o777)
    config_unrelated_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    config_after_sha256: str | None
    failure_class: Literal["config_projection_mismatch"] | None = None
    backup_path: None
    backup_sha256: None
    managed_entry_original: _ManagedOriginal
    managed_entry: _ManagedEntry
    codex_runtime: _RuntimeIdentity
    python_runtime: _RuntimeIdentity
    artifacts: tuple[_Artifact, ...] = Field(min_length=1, max_length=8)
    normal_integration: _NormalIntegration
    teardown: _Teardown

    @model_validator(mode="after")
    def validate_state(self) -> _DesktopReceipt:
        for value in (self.confirmed_at, self.created_at, self.updated_at):
            _validate_time(value)
        if not self.config_existed_before and self.config_before_sha256 != EMPTY_SHA256:
            raise ValueError("new config must use the empty digest")
        if self.receipt_version == RECEIPT_VERSION:
            if self.config_mode_before is None or self.config_unrelated_sha256 is None:
                raise ValueError("current receipt requires config bindings")
            if self.config_mode_before & 0o077 or not self.config_mode_before & 0o400:
                raise ValueError("config mode must remain owner-readable and private")
        if self.state == "prepared":
            valid = (
                self.config_after_sha256 is None
                and self.failure_class is None
                and _empty_teardown(self.teardown)
            )
        elif self.state == "failed":
            valid = (
                self.receipt_version == RECEIPT_VERSION
                and _is_sha(self.config_after_sha256)
                and self.failure_class == "config_projection_mismatch"
                and _empty_teardown(self.teardown)
            )
        elif self.state == "installed":
            valid = (
                _is_sha(self.config_after_sha256)
                and self.failure_class is None
                and _empty_teardown(self.teardown)
            )
        elif self.state == "removing":
            valid = (
                _is_sha(self.config_after_sha256)
                and self.failure_class is None
                and self.teardown.requested_at is not None
                and self.teardown.completed_at is None
                and self.teardown.config_after_teardown_sha256 is None
            )
        else:
            valid = (
                _is_sha(self.config_after_sha256)
                and self.failure_class is None
                and self.teardown.requested_at is not None
                and self.teardown.completed_at is not None
                and _is_sha(self.teardown.config_after_teardown_sha256)
            )
        if not valid:
            raise ValueError("receipt state fields do not match")
        if self.teardown.requested_at is not None:
            _validate_time(self.teardown.requested_at)
        if self.teardown.completed_at is not None:
            _validate_time(self.teardown.completed_at)
        return self


@dataclass(frozen=True, slots=True)
class _PreviewSnapshot:
    digest: str
    config_sha256: str
    config_head: _FileHead
    config_mode: int
    config_unrelated_sha256: str
    fixture_sha256: str
    fixture_size: int
    codex_runtime: dict[str, Any]
    python_runtime: dict[str, Any]
    normal_receipt_sha256: str
    normal_receipt_version: str
    managed_entry: dict[str, Any]
    config_existed: bool
    managed_parent_present: bool
    prior_removed_receipt_sha256: str | None


@dataclass(frozen=True, slots=True)
class _FileHead:
    """One no-follow observation used to bind a later local mutation."""

    exists: bool
    sha256: str
    size: int
    device: int | None
    inode: int | None
    owner: int | None
    mode: int | None


_preview_cache: OrderedDict[str, _PreviewSnapshot] = OrderedDict()
_preview_lock = threading.Lock()
_operation_thread_lock = threading.RLock()


@contextmanager
def _operation_lock(data_dir: Path) -> Iterator[None]:
    """Serialize confirmed Verity demo mutations within this installation."""

    with _operation_thread_lock:
        _private_directory(data_dir)
        path = data_dir / "desktop-demo-operation.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(path, flags, 0o600)
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                raise DesktopDemoError("unsafe_operation_lock")
            if os.name != "nt" and (
                details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077
            ):
                raise DesktopDemoError("unsafe_operation_lock")
            if _fcntl is not None:
                _fcntl.flock(descriptor, _fcntl.LOCK_EX)
            yield
        except DesktopDemoError:
            raise
        except OSError as exc:
            raise DesktopDemoError("operation_lock_unavailable") from exc
        finally:
            if descriptor >= 0:
                if _fcntl is not None:
                    try:
                        _fcntl.flock(descriptor, _fcntl.LOCK_UN)
                    except OSError:
                        pass
                os.close(descriptor)


def _validate_time(value: str) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp must use canonical UTC Z notation")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must use UTC")


def _is_sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _empty_teardown(value: _Teardown) -> bool:
    return (
        value.requested_at is None
        and value.completed_at is None
        and value.config_after_teardown_sha256 is None
    )


def _default_runner(
    argv: list[str],
    *,
    environment: dict[str, str],
    timeout: float,
) -> CommandResult:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, never a shell
            argv,
            check=False,
            capture_output=True,
            env=environment,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DesktopDemoError("runtime_unavailable") from exc
    return CommandResult(completed.returncode, completed.stdout[:4096])


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_regular(
    path: Path,
    maximum: int,
    *,
    private: bool = False,
    executable: bool = False,
) -> tuple[bytes, os.stat_result]:
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        elif path.is_symlink():
            raise DesktopDemoError("unsafe_file")
        descriptor = os.open(path, flags)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size > maximum:
            raise DesktopDemoError("unsafe_file")
        if os.name != "nt":
            mode = stat.S_IMODE(details.st_mode)
            if details.st_uid not in {0, os.geteuid()} or mode & 0o022:
                raise DesktopDemoError("unsafe_file_permissions")
            if private and mode & 0o077:
                raise DesktopDemoError("unsafe_file_permissions")
            if executable and not mode & 0o100:
                raise DesktopDemoError("runtime_unavailable")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            content = handle.read(maximum + 1)
        if len(content) > maximum:
            raise DesktopDemoError("unsafe_file")
        return content, details
    except DesktopDemoError:
        raise
    except OSError as exc:
        raise DesktopDemoError("unsafe_file") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _hash_regular(path: Path, maximum: int, **kwargs: bool) -> tuple[str, int]:
    content, details = _read_regular(path, maximum, **kwargs)
    return _sha256_bytes(content), details.st_size


def _absent_head() -> _FileHead:
    return _FileHead(False, EMPTY_SHA256, 0, None, None, None, None)


def _head_from_read(content: bytes, details: os.stat_result) -> _FileHead:
    return _FileHead(
        True,
        _sha256_bytes(content),
        details.st_size,
        details.st_dev,
        details.st_ino,
        getattr(details, "st_uid", None),
        stat.S_IMODE(details.st_mode),
    )


def _read_file_snapshot(
    path: Path,
    maximum: int,
    *,
    private: bool,
) -> tuple[bytes, _FileHead]:
    """Read a regular file and prove the directory entry still names that inode."""

    try:
        before = path.lstat()
    except FileNotFoundError:
        return b"", _absent_head()
    except OSError as exc:
        raise DesktopDemoError("unsafe_file") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise DesktopDemoError("unsafe_file")
    content, opened = _read_regular(path, maximum, private=private)
    try:
        after = path.lstat()
    except OSError as exc:
        raise DesktopDemoError("file_state_changed") from exc
    opened_identity = (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        getattr(opened, "st_uid", None),
        stat.S_IMODE(opened.st_mode),
    )
    if opened_identity != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        getattr(before, "st_uid", None),
        stat.S_IMODE(before.st_mode),
    ) or opened_identity != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        getattr(after, "st_uid", None),
        stat.S_IMODE(after.st_mode),
    ):
        raise DesktopDemoError("file_state_changed")
    return content, _head_from_read(content, opened)


def _assert_file_head(
    path: Path,
    expected: _FileHead,
    *,
    maximum: int,
    private: bool,
    error: str,
) -> _FileHead:
    try:
        _, current = _read_file_snapshot(path, maximum, private=private)
    except DesktopDemoError as exc:
        raise DesktopDemoError(error) from exc
    if current != expected:
        raise DesktopDemoError(error)
    return current


def _assert_expected_write_target(
    path: Path,
    *,
    expected_exists: bool,
    expected_sha256: str,
    maximum: int,
    error: str,
) -> None:
    try:
        _, current = _read_file_snapshot(path, maximum, private=True)
    except DesktopDemoError as exc:
        raise DesktopDemoError(error) from exc
    if current.exists != expected_exists or current.sha256 != expected_sha256:
        raise DesktopDemoError(error)


def _atomic_write(
    path: Path,
    content: bytes,
    *,
    mode: int = 0o600,
    expected_exists: bool | None = None,
    expected_sha256: str | None = None,
    expected_maximum: int = MAX_CONFIG_BYTES,
    expected_error: str = "config_changed_after_preview",
) -> _FileHead:
    if (expected_exists is None) != (expected_sha256 is None):
        raise DesktopDemoError("expected_file_state_invalid")
    if expected_exists is not None and expected_sha256 is not None:
        _assert_expected_write_target(
            path,
            expected_exists=expected_exists,
            expected_sha256=expected_sha256,
            maximum=expected_maximum,
            error=expected_error,
        )
    elif path.exists() and path.is_symlink():
        raise DesktopDemoError("unsafe_write_target")
    _validated_demo_root(path.parent, label="write_target")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if expected_exists is not None and expected_sha256 is not None:
            _assert_expected_write_target(
                path,
                expected_exists=expected_exists,
                expected_sha256=expected_sha256,
                maximum=expected_maximum,
                error=expected_error,
            )
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        written, head = _read_file_snapshot(path, max(len(content), 1), private=True)
        if written != content or head.mode != mode:
            raise DesktopDemoError("atomic_write_verification_failed")
        return head
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _private_directory(path: Path) -> None:
    try:
        missing: list[Path] = []
        current = path
        while not current.exists():
            if current.is_symlink() or current.parent == current:
                raise DesktopDemoError("unsafe_demo_directory")
            missing.append(current)
            current = current.parent
        snapshot_trusted_directory(
            current,
            current_user_only=False,
            directory_label="demo directory parent",
            ancestor_label="demo directory parent",
        )
        for directory in reversed(missing):
            directory.mkdir(parents=False, exist_ok=False, mode=0o700)
            directory.chmod(0o700)
            snapshot_trusted_directory(
                directory,
                current_user_only=True,
                directory_label="demo directory",
                ancestor_label="demo directory",
            )
    except DesktopDemoError:
        raise
    except (ConfigurationError, OSError) as exc:
        raise DesktopDemoError("unsafe_demo_directory") from exc
    try:
        details = path.lstat()
    except OSError as exc:
        raise DesktopDemoError("unsafe_demo_directory") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise DesktopDemoError("unsafe_demo_directory")
    if os.name != "nt" and (
        details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077
    ):
        try:
            path.chmod(0o700)
            details = path.lstat()
        except OSError as exc:
            raise DesktopDemoError("unsafe_demo_directory") from exc
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
            raise DesktopDemoError("unsafe_demo_directory")


def _validated_demo_root(value: Path, *, label: str) -> Path:
    """Validate one existing private root without dereferencing symlinks.

    ``Path.resolve()`` is deliberately forbidden here: resolving first would
    erase the evidence that an operator-supplied root or one of its ancestors
    is a symbolic link. The exact lexical path is retained for receipt scope
    checks and all later reads and writes.
    """

    path = Path(value)
    error = f"unsafe_{label}"
    if not path.is_absolute() or "\x00" in os.fspath(path) or ".." in path.parts:
        raise DesktopDemoError(error)
    try:
        snapshot_trusted_directory(
            path,
            current_user_only=True,
            directory_label=label.replace("_", " "),
            ancestor_label=f"trusted {label.replace('_', ' ')}",
        )
    except ConfigurationError as exc:
        raise DesktopDemoError(error) from exc
    return path


def _resolved_runtime(
    path: Path | None,
    *,
    name: str,
) -> tuple[Path, ExecutableIdentity]:
    try:
        return resolve_trusted_executable(
            name,
            path,
            executable_label=f"{name} runtime",
            ancestor_label="trusted desktop demo",
        )
    except ConfigurationError as exc:
        raise DesktopDemoError("runtime_unavailable") from exc


def _runtime_environment(codex_home: Path) -> dict[str, str]:
    environment = {
        "CODEX_HOME": str(codex_home),
        "HOME": str(codex_home.parent),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
    }
    return environment


def _runtime_identity(
    path: Path,
    trust: ExecutableIdentity,
    *,
    runner: _Runner,
    codex_home: Path,
) -> dict[str, Any]:
    if not recheck_trusted_executable(
        path,
        trust,
        executable_label=f"{path.name} runtime",
        ancestor_label="trusted desktop demo",
    ):
        raise DesktopDemoError("runtime_drift")
    size = trust.target_chain[-1].size
    result = runner(
        [str(path), "--version"],
        environment=_runtime_environment(codex_home),
        timeout=5.0,
    )
    if result.returncode != 0:
        raise DesktopDemoError("runtime_unavailable")
    try:
        version = result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeError as exc:
        raise DesktopDemoError("runtime_unavailable") from exc
    if not version or len(version) > 128 or not version.isprintable():
        raise DesktopDemoError("runtime_unavailable")
    if not recheck_trusted_executable(
        path,
        trust,
        executable_label=f"{path.name} runtime",
        ancestor_label="trusted desktop demo",
    ):
        raise DesktopDemoError("runtime_drift")
    return {
        "path": str(path),
        "sha256": trust.digest,
        "version": version,
        "size_bytes": size,
    }


def _load_config(path: Path) -> tuple[Any, bytes, _FileHead]:
    try:
        raw, head = _read_file_snapshot(path, MAX_CONFIG_BYTES, private=True)
        if not head.exists:
            return tomlkit.document(), b"", head
        return tomlkit.parse(raw.decode("utf-8", errors="strict")), raw, head
    except DesktopDemoError:
        raise DesktopDemoError("unsafe_config") from None
    except (UnicodeError, tomlkit.exceptions.ParseError) as exc:
        raise DesktopDemoError("config_invalid") from exc


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_plain(item) for item in value]
    return value


def _unrelated_config_values(
    document: Any,
    *,
    managed_parent_present_before: bool,
) -> dict[str, Any]:
    """Return parsed config values outside the single managed demo entry."""

    plain = _plain(document)
    if not isinstance(plain, dict):
        raise DesktopDemoError("config_invalid")
    unrelated = dict(plain)
    servers = unrelated.get("mcp_servers")
    if servers is None:
        return unrelated
    if not isinstance(servers, dict):
        raise DesktopDemoError("config_invalid")
    remaining = dict(servers)
    remaining.pop(MANAGED_NAME, None)
    if remaining or managed_parent_present_before:
        unrelated["mcp_servers"] = remaining
    else:
        unrelated.pop("mcp_servers", None)
    return unrelated


def _parsed_config_values_match(left: Any, right: Any) -> bool:
    """Compare parsed TOML values without rendering their possibly secret content."""

    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return set(left) == set(right) and all(
            _parsed_config_values_match(left[key], right[key]) for key in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _parsed_config_values_match(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    if type(left) is not type(right):
        return False
    if isinstance(left, float) and math.isnan(left):
        return math.isnan(right)
    return bool(left == right)


def _typed_toml_value(value: Any) -> Any:
    """Encode parsed TOML values with explicit type tags for a safe digest."""

    if isinstance(value, Mapping):
        return {
            "type": "table",
            "value": {
                str(key): _typed_toml_value(value[key])
                for key in sorted(value, key=lambda item: str(item))
            },
        }
    if isinstance(value, list):
        return {"type": "array", "value": [_typed_toml_value(item) for item in value]}
    if isinstance(value, bool):
        return {"type": "boolean", "value": value}
    if isinstance(value, int):
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        if math.isnan(value):
            rendered = "nan"
        elif math.isinf(value):
            rendered = "-inf" if value < 0 else "inf"
        else:
            rendered = value.hex()
        return {"type": "float", "value": rendered}
    if isinstance(value, str):
        return {"type": "string", "value": str(value)}
    if isinstance(value, datetime):
        return {"type": "offset_datetime", "value": value.isoformat()}
    if isinstance(value, date):
        return {"type": "local_date", "value": value.isoformat()}
    if isinstance(value, datetime_time):
        return {"type": "local_time", "value": value.isoformat()}
    raise DesktopDemoError("config_invalid")


def _unrelated_config_digest(values: dict[str, Any]) -> str:
    try:
        return _sha256_bytes(canonical_json_bytes(_typed_toml_value(values)))
    except (TypeError, ValueError) as exc:
        raise DesktopDemoError("config_invalid") from exc


def _config_write_mode(head: _FileHead) -> int:
    if not head.exists:
        return 0o600
    if head.mode is None or head.mode & 0o077 or not head.mode & 0o400:
        raise DesktopDemoError("unsafe_config")
    return head.mode


def _managed_from_document(document: Any) -> dict[str, Any] | None:
    servers = document.get("mcp_servers")
    if servers is None:
        return None
    if not isinstance(servers, Mapping):
        raise DesktopDemoError("config_invalid")
    value = servers.get(MANAGED_NAME)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise DesktopDemoError("managed_entry_drift")
    return cast(dict[str, Any], _plain(value))


def _managed_parent_present(document: Any) -> bool:
    servers = document.get("mcp_servers")
    if servers is None:
        return False
    if not isinstance(servers, Mapping):
        raise DesktopDemoError("config_invalid")
    return True


def _config_managed(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "command": entry["command"],
        "args": list(entry["args"]),
        "cwd": entry["cwd"],
        "enabled": True,
        "required": True,
        "startup_timeout_sec": 5.0,
        "tool_timeout_sec": 5.0,
        "enabled_tools": list(_TOOL_NAMES),
        "default_tools_approval_mode": "writes",
        "tools": {"demo_artifact_sink": {"approval_mode": "prompt"}},
    }


def _managed_digest_payload(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in entry.items() if key not in {"sha256", "canonicalization"}}


def _managed_entry(python: Path, staging_root: Path) -> dict[str, Any]:
    script = staging_root / STAGED_SCRIPT_NAME
    value: dict[str, Any] = {
        "name": MANAGED_NAME,
        "canonicalization": CANONICALIZATION,
        "transport": "stdio",
        "command": str(python),
        "args": ["-I", str(script)],
        "cwd": str(staging_root),
        "enabled": True,
        "required": True,
        "startup_timeout_sec": 5,
        "tool_timeout_sec": 5,
        "enabled_tools": list(_TOOL_NAMES),
        "default_tools_approval_mode": "writes",
        "tool_overrides": {"demo_artifact_sink": {"approval_mode": "prompt"}},
    }
    value["sha256"] = _sha256_bytes(canonical_json_bytes(_managed_digest_payload(value)))
    return value


def _managed_values_match(actual: dict[str, Any] | None, expected: dict[str, Any]) -> bool:
    if actual is None:
        return False
    try:
        return canonical_json_bytes(actual) == canonical_json_bytes(expected)
    except (TypeError, ValueError):
        return False


def _managed_matches(document: Any, entry: dict[str, Any]) -> bool:
    actual = _managed_from_document(document)
    return _managed_values_match(actual, _config_managed(entry))


def _set_managed(document: Any, entry: dict[str, Any]) -> None:
    servers = document.get("mcp_servers")
    if servers is None:
        servers = tomlkit.table()
        document["mcp_servers"] = servers
    if not isinstance(servers, Mapping) or not hasattr(servers, "__setitem__"):
        raise DesktopDemoError("config_invalid")
    servers[MANAGED_NAME] = _config_managed(entry)


def _remove_managed(document: Any, *, remove_empty_parent: bool) -> None:
    servers = document.get("mcp_servers")
    if not isinstance(servers, Mapping) or not hasattr(servers, "__delitem__"):
        raise DesktopDemoError("managed_entry_drift")
    del servers[MANAGED_NAME]
    if remove_empty_parent and len(servers) == 0:
        del document["mcp_servers"]


def _normal_report(
    *,
    codex_home: Path,
    data_dir: Path,
    runner: CommandRunner,
    operator_confirmed_hook_trust: bool,
) -> CodexDoctorReport:
    return doctor_codex(
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )


def _normal_receipt(data_dir: Path) -> tuple[Path, str, str]:
    path = data_dir / NORMAL_RECEIPT_FILENAME
    try:
        raw, _ = _read_regular(path, MAX_RECEIPT_BYTES, private=True)
        parsed = parse_json_strict(raw)
    except (DesktopDemoError, TypeError, ValueError) as exc:
        raise DesktopDemoError("normal_integration_not_ready") from exc
    if not isinstance(parsed, dict) or parsed.get("schema_version") not in {
        NORMAL_LEGACY_RECEIPT_VERSION,
        NORMAL_RECEIPT_VERSION,
    }:
        raise DesktopDemoError("normal_integration_not_ready")
    return path, _sha256_bytes(raw), cast(str, parsed["schema_version"])


def _normal_receipt_matches(receipt: dict[str, Any], data_dir: Path) -> bool:
    try:
        current_path, current_digest, current_version = _normal_receipt(data_dir)
    except DesktopDemoError:
        return False
    recorded = cast(dict[str, Any], receipt["normal_integration"])
    return bool(
        current_path == Path(str(recorded["receipt_path"]))
        and current_digest == recorded["receipt_sha256"]
        and current_version == recorded["receipt_version"]
    )


def _cache_preview(snapshot: _PreviewSnapshot) -> None:
    with _preview_lock:
        _preview_cache[snapshot.digest] = snapshot
        _preview_cache.move_to_end(snapshot.digest)
        while len(_preview_cache) > _PREVIEW_CACHE_LIMIT:
            _preview_cache.popitem(last=False)


def _cached_preview(digest: str) -> _PreviewSnapshot | None:
    with _preview_lock:
        return _preview_cache.get(digest)


def _snapshot(
    repository_root: Path,
    *,
    codex_home: Path,
    data_dir: Path,
    codex_executable: Path | None,
    python_executable: Path | None,
    runner: _Runner,
    normal_ready: bool,
    prior_removed_receipt_sha256: str | None = None,
) -> _PreviewSnapshot:
    config_path = codex_home / "config.toml"
    document, raw_config, config_head = _load_config(config_path)
    config_existed = config_head.exists
    config_mode = _config_write_mode(config_head)
    managed_parent_present = _managed_parent_present(document)
    if _managed_from_document(document) is not None:
        raise DesktopDemoError("reserved_name_exists")
    unrelated = _unrelated_config_values(
        document,
        managed_parent_present_before=managed_parent_present,
    )
    unrelated_digest = _unrelated_config_digest(unrelated)
    source = repository_root / FIXTURE_SOURCE
    try:
        fixture_digest, fixture_size = _hash_regular(source, MAX_FIXTURE_BYTES, private=False)
    except DesktopDemoError as exc:
        raise DesktopDemoError("fixture_source_invalid") from exc
    python, python_trust = _resolved_runtime(
        python_executable or Path(sys.executable).resolve(),
        name="python3",
    )
    codex, codex_trust = _resolved_runtime(codex_executable, name="codex")
    python_identity = _runtime_identity(
        python,
        python_trust,
        runner=runner,
        codex_home=codex_home,
    )
    codex_identity = _runtime_identity(
        codex,
        codex_trust,
        runner=runner,
        codex_home=codex_home,
    )
    try:
        normal_path, normal_digest, normal_version = _normal_receipt(data_dir)
    except DesktopDemoError:
        if normal_ready:
            raise
        normal_path = data_dir / NORMAL_RECEIPT_FILENAME
        normal_digest = EMPTY_SHA256
        normal_version = NORMAL_RECEIPT_VERSION
    staging_root = data_dir / DEMO_DIRECTORY / STAGING_DIRECTORY
    managed = _managed_entry(python, staging_root)
    payload = {
        "contract": RECEIPT_VERSION,
        "codex_home": str(codex_home),
        "config_path": str(config_path),
        "config_sha256": _sha256_bytes(raw_config),
        "config_existed": config_existed,
        "config_mode": config_mode,
        "config_unrelated_sha256": unrelated_digest,
        "data_dir": str(data_dir),
        "fixture_sha256": fixture_digest,
        "fixture_size": fixture_size,
        "codex_runtime": codex_identity,
        "python_runtime": python_identity,
        "normal_receipt_path": str(normal_path),
        "normal_receipt_sha256": normal_digest,
        "normal_receipt_version": normal_version,
        "normal_ready": normal_ready,
        "managed_entry": managed,
        "managed_parent_present": managed_parent_present,
        "prior_removed_receipt_sha256": prior_removed_receipt_sha256,
    }
    digest = _sha256_bytes(canonical_json_bytes(payload))
    snapshot = _PreviewSnapshot(
        digest=digest,
        config_sha256=_sha256_bytes(raw_config),
        config_head=config_head,
        config_mode=config_mode,
        config_unrelated_sha256=unrelated_digest,
        fixture_sha256=fixture_digest,
        fixture_size=fixture_size,
        codex_runtime=codex_identity,
        python_runtime=python_identity,
        normal_receipt_sha256=normal_digest,
        normal_receipt_version=normal_version,
        managed_entry=managed,
        config_existed=config_existed,
        managed_parent_present=managed_parent_present,
        prior_removed_receipt_sha256=prior_removed_receipt_sha256,
    )
    _cache_preview(snapshot)
    return snapshot


def _paths(codex_home: Path, data_dir: Path) -> tuple[Path, Path, Path]:
    return (
        codex_home / "config.toml",
        data_dir / DEMO_RECEIPT_FILENAME,
        data_dir / DEMO_DIRECTORY / STAGING_DIRECTORY,
    )


def _operator_actions(operation: str, *, normal_ready: bool) -> tuple[str, ...]:
    if operation == "desktop_setup":
        if not normal_ready:
            return (
                "Preview the normal integration with `verity install-codex --source-root .`.",
                "Review and apply that integration separately, then rerun Desktop setup preview.",
            )
        return (
            "Before confirmed setup, close every ChatGPT Desktop task, exit all "
            "Codex CLI TUI and IDE Codex sessions, and fully quit the ChatGPT desktop app.",
            "Restart Codex Desktop.",
            "Use /mcp to confirm the synthetic demo server, then run a benign "
            "hook-delivery canary.",
            "Open a new task and run the Desktop demo only with synthetic data after "
            "the canary reaches a signed terminal decision.",
        )
    return (
        "Before confirmed teardown, close every ChatGPT Desktop task, exit all "
        "Codex CLI TUI and IDE Codex sessions, and fully quit the ChatGPT desktop app.",
        "Restart Codex Desktop after removing the synthetic fixture.",
        "Use /mcp to confirm the synthetic demo server is absent.",
    )


def _result(
    *,
    operation: str,
    confirmed: bool,
    applied: bool,
    state: str,
    preview_digest: str,
    config_path: Path,
    receipt_path: Path,
    staging_root: Path,
    managed_entry: dict[str, Any],
    artifacts: tuple[dict[str, Any], ...],
    normal_ready: bool,
    issues: tuple[str, ...] = (),
) -> DesktopDemoResult:
    return DesktopDemoResult(
        operation=operation,
        confirmed=confirmed,
        applied=applied,
        state=state,
        preview_digest=preview_digest,
        config_path=config_path,
        receipt_path=receipt_path,
        staging_root=staging_root,
        managed_entry=managed_entry,
        artifacts=artifacts,
        normal_integration_ready=normal_ready,
        issues=issues,
        operator_actions=_operator_actions(operation, normal_ready=normal_ready),
    )


def _receipt_json(value: dict[str, Any]) -> bytes:
    try:
        validated = _DesktopReceipt.model_validate(value).model_dump(
            mode="json", exclude_unset=True
        )
    except ValidationError as exc:
        raise DesktopDemoError("receipt_invalid") from exc
    return (json.dumps(validated, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _absolute(value: str) -> Path:
    if "\x00" in value:
        raise DesktopDemoError("receipt_scope_invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise DesktopDemoError("receipt_scope_invalid")
    return path


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_receipt_scope(
    receipt: dict[str, Any],
    *,
    codex_home: Path,
    data_dir: Path,
) -> None:
    expected_config, _, expected_staging = _paths(codex_home, data_dir)
    recorded_home = _absolute(str(receipt["codex_home"]))
    config_path = _absolute(str(receipt["config_path"]))
    staging_root = _absolute(str(receipt["staging_root"]))
    if (
        recorded_home != codex_home
        or config_path != expected_config
        or staging_root != expected_staging
        or not _is_within(staging_root, data_dir)
    ):
        raise DesktopDemoError("receipt_scope_invalid")
    normal = cast(dict[str, Any], receipt["normal_integration"])
    if _absolute(str(normal["receipt_path"])) != data_dir / NORMAL_RECEIPT_FILENAME:
        raise DesktopDemoError("receipt_scope_invalid")
    managed = cast(dict[str, Any], receipt["managed_entry"])
    python_runtime = cast(dict[str, Any], receipt["python_runtime"])
    command = _absolute(str(managed["command"]))
    runtime_path = _absolute(str(python_runtime["path"]))
    arguments = managed.get("args")
    if (
        command != runtime_path
        or managed.get("cwd") != str(staging_root)
        or not isinstance(arguments, list)
        or arguments != ["-I", str(staging_root / STAGED_SCRIPT_NAME)]
    ):
        raise DesktopDemoError("receipt_scope_invalid")
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise DesktopDemoError("receipt_scope_invalid")
    if artifacts[0].get("relative_path") != STAGED_SCRIPT_NAME:
        raise DesktopDemoError("receipt_scope_invalid")


def _receipt_managed_digest_valid(receipt: dict[str, Any]) -> bool:
    managed = cast(dict[str, Any], receipt["managed_entry"])
    expected = _sha256_bytes(canonical_json_bytes(_managed_digest_payload(managed)))
    return managed.get("sha256") == expected


def _parse_desktop_demo_receipt_with_head(
    path: Path,
    *,
    codex_home: Path,
    data_dir: Path,
) -> tuple[dict[str, Any], _FileHead]:
    """Parse a private receipt with duplicate-key, schema, and scope checks."""

    try:
        raw, head = _read_file_snapshot(path, MAX_RECEIPT_BYTES, private=True)
        if not head.exists:
            raise DesktopDemoError("receipt_invalid")
    except DesktopDemoError as exc:
        message = (
            "receipt_permissions" if path.exists() and not path.is_symlink() else "receipt_invalid"
        )
        raise DesktopDemoError(message) from exc
    try:
        parsed = parse_json_strict(raw)
        if not isinstance(parsed, dict):
            raise ValueError
        validated = _DesktopReceipt.model_validate(parsed).model_dump(
            mode="json",
            exclude_unset=True,
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DesktopDemoError("receipt_invalid") from exc
    resolved_home = _validated_demo_root(codex_home, label="codex_home")
    resolved_data = _validated_demo_root(data_dir, label="data_dir")
    _validate_receipt_scope(
        validated,
        codex_home=resolved_home,
        data_dir=resolved_data,
    )
    return validated, head


def parse_desktop_demo_receipt(
    path: Path,
    *,
    codex_home: Path,
    data_dir: Path,
) -> dict[str, Any]:
    """Parse a private receipt with duplicate-key, schema, and scope checks."""

    receipt, _ = _parse_desktop_demo_receipt_with_head(
        path,
        codex_home=codex_home,
        data_dir=data_dir,
    )
    return receipt


def transition_desktop_demo_receipt(
    receipt: dict[str, Any],
    *,
    target_state: str,
    occurred_at: str,
    config_sha256: str | None = None,
) -> dict[str, Any]:
    """Apply one forward-only write-ahead receipt transition."""

    try:
        current = _DesktopReceipt.model_validate(receipt).model_dump(
            mode="json",
            exclude_unset=True,
        )
    except ValidationError as exc:
        raise DesktopDemoError("receipt_invalid") from exc
    transitions = {
        "prepared": {"failed", "installed"},
        "failed": {"removing"},
        "installed": {"removing"},
        "removing": {"removed"},
    }
    if target_state not in transitions.get(str(current["state"]), set()):
        raise DesktopDemoError("receipt_transition_invalid")
    try:
        _validate_time(occurred_at)
    except ValueError as exc:
        raise DesktopDemoError("receipt_transition_invalid") from exc
    if target_state in {"failed", "installed", "removed"} and not _is_sha(config_sha256):
        raise DesktopDemoError("receipt_transition_invalid")
    updated = dict(current)
    updated["state"] = target_state
    updated["updated_at"] = occurred_at
    teardown = dict(cast(dict[str, Any], updated["teardown"]))
    if target_state == "failed":
        updated["config_after_sha256"] = config_sha256
        updated["failure_class"] = "config_projection_mismatch"
    elif target_state == "installed":
        updated["config_after_sha256"] = config_sha256
    elif target_state == "removing":
        updated["failure_class"] = None
        teardown["requested_at"] = occurred_at
    else:
        teardown["completed_at"] = occurred_at
        teardown["config_after_teardown_sha256"] = config_sha256
    updated["teardown"] = teardown
    try:
        return _DesktopReceipt.model_validate(updated).model_dump(
            mode="json",
            exclude_unset=True,
        )
    except ValidationError as exc:
        raise DesktopDemoError("receipt_transition_invalid") from exc


def _artifact_from_snapshot(snapshot: _PreviewSnapshot) -> dict[str, Any]:
    return {
        "relative_path": STAGED_SCRIPT_NAME,
        "sha256": snapshot.fixture_sha256,
        "size_bytes": snapshot.fixture_size,
        "file_mode": "0600",
    }


def _receipt_payload(
    snapshot: _PreviewSnapshot,
    *,
    codex_home: Path,
    data_dir: Path,
    confirmed_at: str,
) -> dict[str, Any]:
    config_path, _, staging_root = _paths(codex_home, data_dir)
    normal_path = data_dir / NORMAL_RECEIPT_FILENAME
    return {
        "receipt_version": RECEIPT_VERSION,
        "installation_id": new_id(),
        "state": "prepared",
        "operator_confirmed": True,
        "confirmation_method": "cli_yes",
        "preview_digest": snapshot.digest,
        "confirmed_at": confirmed_at,
        "created_at": confirmed_at,
        "updated_at": confirmed_at,
        "digest_algorithm": "SHA-256",
        "codex_home": str(codex_home),
        "config_path": str(config_path),
        "staging_root": str(staging_root),
        "config_existed_before": snapshot.config_existed,
        "config_before_sha256": snapshot.config_sha256,
        "config_mode_before": snapshot.config_mode,
        "config_unrelated_sha256": snapshot.config_unrelated_sha256,
        "config_after_sha256": None,
        "failure_class": None,
        "backup_path": None,
        "backup_sha256": None,
        "managed_entry_original": {
            "present": False,
            "digest": None,
            "parent_table_present": snapshot.managed_parent_present,
        },
        "managed_entry": snapshot.managed_entry,
        "codex_runtime": snapshot.codex_runtime,
        "python_runtime": snapshot.python_runtime,
        "artifacts": [_artifact_from_snapshot(snapshot)],
        "normal_integration": {
            "receipt_version": snapshot.normal_receipt_version,
            "receipt_path": str(normal_path),
            "receipt_sha256": snapshot.normal_receipt_sha256,
            "doctor_ready": True,
        },
        "teardown": {
            "requested_at": None,
            "completed_at": None,
            "config_after_teardown_sha256": None,
        },
    }


def _compare_preview(current: _PreviewSnapshot, expected_digest: str | None) -> None:
    if expected_digest is None or not _is_sha(expected_digest):
        raise DesktopDemoError("preview_digest_required")
    if current.digest == expected_digest:
        return
    expected = _cached_preview(expected_digest)
    if expected is None:
        raise DesktopDemoError("preview_digest_mismatch")
    if current.config_sha256 != expected.config_sha256:
        raise DesktopDemoError("config_changed_after_preview")
    if (
        current.fixture_sha256 != expected.fixture_sha256
        or current.fixture_size != expected.fixture_size
    ):
        raise DesktopDemoError("fixture_source_drift")
    if (
        current.codex_runtime != expected.codex_runtime
        or current.python_runtime != expected.python_runtime
    ):
        raise DesktopDemoError("runtime_drift")
    raise DesktopDemoError("preview_digest_mismatch")


def _stage_fixture(source: Path, target: Path, *, expected_digest: str, expected_size: int) -> None:
    # Verify bounded source bytes before creating even the private staging tree.
    try:
        source_raw, source_head = _read_file_snapshot(source, MAX_FIXTURE_BYTES, private=False)
    except DesktopDemoError as exc:
        raise DesktopDemoError("fixture_source_drift") from exc
    if (
        not source_head.exists
        or len(source_raw) != expected_size
        or source_head.sha256 != expected_digest
    ):
        raise DesktopDemoError("fixture_source_drift")
    if target.parent.exists():
        try:
            details = target.parent.lstat()
        except OSError as exc:
            raise DesktopDemoError("unsafe_staging") from exc
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise DesktopDemoError("unsafe_staging")
    _private_directory(target.parent)
    if target.exists() or target.is_symlink():
        try:
            digest, size = _hash_regular(target, MAX_FIXTURE_BYTES, private=True)
        except DesktopDemoError as exc:
            raise DesktopDemoError("unsafe_staging") from exc
        if digest != expected_digest or size != expected_size:
            raise DesktopDemoError("staged_artifact_drift")
        return
    try:
        _atomic_write(
            target,
            source_raw,
            mode=0o600,
            expected_exists=False,
            expected_sha256=EMPTY_SHA256,
            expected_maximum=MAX_FIXTURE_BYTES,
            expected_error="staged_artifact_drift",
        )
        digest, size = _hash_regular(target, MAX_FIXTURE_BYTES, private=True)
        if digest != expected_digest or size != expected_size:
            raise DesktopDemoError("staged_artifact_drift")
    except DesktopDemoError:
        raise
    except OSError as exc:
        raise DesktopDemoError("setup_interrupted") from exc


def _write_receipt(
    path: Path,
    receipt: dict[str, Any],
    *,
    expected_head: _FileHead,
) -> _FileHead:
    _assert_file_head(
        path,
        expected_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="receipt_drift",
    )
    return _atomic_write(
        path,
        _receipt_json(receipt),
        mode=0o600,
        expected_exists=expected_head.exists,
        expected_sha256=expected_head.sha256,
        expected_maximum=MAX_RECEIPT_BYTES,
        expected_error="receipt_drift",
    )


def _archive_removed_receipt(
    receipt_path: Path,
    receipt: dict[str, Any],
    *,
    data_dir: Path,
    expected_head: _FileHead,
) -> None:
    _assert_file_head(
        receipt_path,
        expected_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="removed_receipt_drift",
    )
    raw, current_head = _read_file_snapshot(receipt_path, MAX_RECEIPT_BYTES, private=True)
    if current_head != expected_head or receipt["state"] != "removed":
        raise DesktopDemoError("removed_receipt_drift")
    history = data_dir / DEMO_DIRECTORY / "history"
    _assert_file_head(
        receipt_path,
        expected_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="removed_receipt_drift",
    )
    _private_directory(history)
    target = history / f"{receipt['installation_id']}.removed.json"
    existing, target_head = _read_file_snapshot(target, MAX_RECEIPT_BYTES, private=True)
    if target_head.exists:
        if existing != raw:
            raise DesktopDemoError("unsafe_receipt_history")
        return
    _assert_file_head(
        receipt_path,
        expected_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="removed_receipt_drift",
    )
    _atomic_write(
        target,
        raw,
        mode=0o600,
        expected_exists=False,
        expected_sha256=EMPTY_SHA256,
        expected_maximum=MAX_RECEIPT_BYTES,
        expected_error="unsafe_receipt_history",
    )


def _normal_ready(
    *,
    codex_home: Path,
    data_dir: Path,
    runner: CommandRunner,
    operator_confirmed_hook_trust: bool,
) -> bool:
    try:
        report = _normal_report(
            codex_home=codex_home,
            data_dir=data_dir,
            runner=runner,
            operator_confirmed_hook_trust=operator_confirmed_hook_trust,
        )
        return report.ready
    except Exception:
        return False


def _require_normal_binding(
    *,
    expected_path: Path,
    expected_sha256: str,
    expected_version: str,
    codex_home: Path,
    data_dir: Path,
    runner: CommandRunner,
    operator_confirmed_hook_trust: bool,
) -> None:
    """Rebind the v2 normal receipt and doctor state immediately before mutation."""

    if expected_version != NORMAL_RECEIPT_VERSION:
        raise DesktopDemoError("normal_integration_not_ready")
    if not _normal_ready(
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    ):
        raise DesktopDemoError("normal_integration_not_ready")
    try:
        current_path, current_digest, current_version = _normal_receipt(data_dir)
    except DesktopDemoError as exc:
        raise DesktopDemoError("normal_integration_drift") from exc
    if (
        current_path != expected_path
        or current_digest != expected_sha256
        or current_version != expected_version
    ):
        raise DesktopDemoError("normal_integration_drift")


def _require_receipt_normal_binding(
    receipt: dict[str, Any],
    *,
    codex_home: Path,
    data_dir: Path,
    runner: CommandRunner,
    operator_confirmed_hook_trust: bool,
) -> None:
    normal = cast(dict[str, Any], receipt["normal_integration"])
    _require_normal_binding(
        expected_path=Path(str(normal["receipt_path"])),
        expected_sha256=str(normal["receipt_sha256"]),
        expected_version=str(normal["receipt_version"]),
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )


def _require_snapshot_normal_binding(
    snapshot: _PreviewSnapshot,
    *,
    codex_home: Path,
    data_dir: Path,
    runner: CommandRunner,
    operator_confirmed_hook_trust: bool,
) -> None:
    _require_normal_binding(
        expected_path=data_dir / NORMAL_RECEIPT_FILENAME,
        expected_sha256=snapshot.normal_receipt_sha256,
        expected_version=snapshot.normal_receipt_version,
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )


def _persist_projection_failure(
    receipt_path: Path,
    receipt: dict[str, Any],
    receipt_head: _FileHead,
    *,
    config_path: Path,
    config_head: _FileHead,
    config_sha256: str,
) -> None:
    if config_head.sha256 != config_sha256:
        raise DesktopDemoError("config_changed_before_finalization")
    _assert_file_head(
        config_path,
        config_head,
        maximum=MAX_CONFIG_BYTES,
        private=True,
        error="config_changed_before_finalization",
    )
    failed = transition_desktop_demo_receipt(
        receipt,
        target_state="failed",
        occurred_at=format_utc(),
        config_sha256=config_sha256,
    )
    try:
        _write_receipt(receipt_path, failed, expected_head=receipt_head)
    except Exception as exc:
        raise DesktopDemoError("setup_interrupted") from exc
    raise DesktopDemoError("demo_setup_non_finalizable")


def _setup_recovery(
    repository_root: Path,
    *,
    receipt: dict[str, Any],
    receipt_head: _FileHead,
    expected_preview_digest: str | None,
    codex_home: Path,
    data_dir: Path,
    normal_ready: bool,
    runner: CommandRunner,
    operator_confirmed_hook_trust: bool,
) -> DesktopDemoResult:
    config_path, receipt_path, staging_root = _paths(codex_home, data_dir)
    if not _receipt_managed_digest_valid(receipt):
        raise DesktopDemoError("receipt_invalid")
    if receipt["state"] == "failed":
        raise DesktopDemoError("demo_setup_non_finalizable")
    if receipt["state"] != "prepared":
        raise DesktopDemoError("demo_already_installed")
    if receipt["receipt_version"] != RECEIPT_VERSION:
        raise DesktopDemoError("receipt_upgrade_required")
    if expected_preview_digest != receipt["preview_digest"]:
        raise DesktopDemoError("preview_digest_mismatch")
    if not normal_ready:
        raise DesktopDemoError("normal_integration_not_ready")
    if not _normal_receipt_matches(receipt, data_dir):
        raise DesktopDemoError("normal_integration_drift")
    if not _runtimes_intact(receipt):
        raise DesktopDemoError("runtime_drift")
    artifacts_valid, artifacts_present = _artifact_removal_state(receipt, data_dir)
    if not artifacts_valid:
        raise DesktopDemoError("staged_artifact_drift")
    artifacts = cast(list[dict[str, Any]], receipt["artifacts"])
    document, raw_config, config_head = _load_config(config_path)
    managed = cast(dict[str, Any], receipt["managed_entry"])
    actual = _managed_from_document(document)
    managed_original = cast(dict[str, Any], receipt["managed_entry_original"])
    managed_parent_present_before = bool(managed_original["parent_table_present"])
    unrelated_before = _unrelated_config_values(
        document,
        managed_parent_present_before=managed_parent_present_before,
    )
    projection_matches = (
        _unrelated_config_digest(unrelated_before) == receipt["config_unrelated_sha256"]
    )
    config_mode = int(receipt["config_mode_before"])
    if config_head.exists and config_head.mode != config_mode:
        raise DesktopDemoError("config_mode_drift")
    config_write_required = actual is None
    if config_write_required:
        if not projection_matches:
            raise DesktopDemoError("config_projection_drift")
        if (
            config_head.exists != receipt["config_existed_before"]
            or _sha256_bytes(raw_config) != receipt["config_before_sha256"]
        ):
            raise DesktopDemoError("config_changed_after_preview")
    elif not _managed_matches(document, managed):
        raise DesktopDemoError("managed_entry_drift")
    elif not projection_matches:
        if not artifacts_present:
            raise DesktopDemoError("staged_artifact_drift")
        _require_receipt_normal_binding(
            receipt,
            codex_home=codex_home,
            data_dir=data_dir,
            runner=runner,
            operator_confirmed_hook_trust=operator_confirmed_hook_trust,
        )
        _assert_file_head(
            receipt_path,
            receipt_head,
            maximum=MAX_RECEIPT_BYTES,
            private=True,
            error="receipt_drift",
        )
        _persist_projection_failure(
            receipt_path,
            receipt,
            receipt_head,
            config_path=config_path,
            config_head=config_head,
            config_sha256=_sha256_bytes(raw_config),
        )

    if not artifacts_present:
        _require_receipt_normal_binding(
            receipt,
            codex_home=codex_home,
            data_dir=data_dir,
            runner=runner,
            operator_confirmed_hook_trust=operator_confirmed_hook_trust,
        )
        _assert_file_head(
            receipt_path,
            receipt_head,
            maximum=MAX_RECEIPT_BYTES,
            private=True,
            error="receipt_drift",
        )
        artifact = artifacts[0]
        _stage_fixture(
            repository_root / FIXTURE_SOURCE,
            staging_root / str(artifact["relative_path"]),
            expected_digest=str(artifact["sha256"]),
            expected_size=int(artifact["size_bytes"]),
        )
    if not _artifact_intact(receipt, data_dir):
        raise DesktopDemoError("staged_artifact_drift")
    if config_write_required:
        _require_receipt_normal_binding(
            receipt,
            codex_home=codex_home,
            data_dir=data_dir,
            runner=runner,
            operator_confirmed_hook_trust=operator_confirmed_hook_trust,
        )
        _assert_file_head(
            receipt_path,
            receipt_head,
            maximum=MAX_RECEIPT_BYTES,
            private=True,
            error="receipt_drift",
        )
        _set_managed(document, managed)
        try:
            _atomic_write(
                config_path,
                tomlkit.dumps(document).encode("utf-8"),
                mode=config_mode,
                expected_exists=config_head.exists,
                expected_sha256=_sha256_bytes(raw_config),
            )
        except DesktopDemoError:
            raise
        except Exception as exc:
            raise DesktopDemoError("setup_interrupted") from exc
        verified_document, verified_raw, verified_head = _load_config(config_path)
        unrelated_after = _unrelated_config_values(
            verified_document,
            managed_parent_present_before=managed_parent_present_before,
        )
        if not _managed_matches(verified_document, managed):
            raise DesktopDemoError("setup_interrupted")
        if verified_head.mode != config_mode:
            raise DesktopDemoError("config_mode_drift")
        if (
            not _parsed_config_values_match(
                unrelated_before,
                unrelated_after,
            )
            or _unrelated_config_digest(unrelated_after) != receipt["config_unrelated_sha256"]
        ):
            _persist_projection_failure(
                receipt_path,
                receipt,
                receipt_head,
                config_path=config_path,
                config_head=verified_head,
                config_sha256=_sha256_bytes(verified_raw),
            )
    else:
        verified_document, verified_raw, verified_head = _load_config(config_path)
        if not _managed_matches(verified_document, managed):
            raise DesktopDemoError("managed_entry_drift")
        verified_unrelated = _unrelated_config_values(
            verified_document,
            managed_parent_present_before=managed_parent_present_before,
        )
        if _unrelated_config_digest(verified_unrelated) != receipt["config_unrelated_sha256"]:
            raise DesktopDemoError("config_projection_drift")
        if verified_head.mode != config_mode:
            raise DesktopDemoError("config_mode_drift")
    _require_receipt_normal_binding(
        receipt,
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )
    _assert_file_head(
        receipt_path,
        receipt_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="receipt_drift",
    )
    if not _artifact_intact(receipt, data_dir):
        raise DesktopDemoError("staged_artifact_drift")
    final_document, final_raw, final_head = _load_config(config_path)
    final_unrelated = _unrelated_config_values(
        final_document,
        managed_parent_present_before=managed_parent_present_before,
    )
    if (
        not _managed_matches(final_document, managed)
        or _unrelated_config_digest(final_unrelated) != receipt["config_unrelated_sha256"]
        or final_head.mode != config_mode
    ):
        raise DesktopDemoError("config_changed_before_finalization")
    _require_receipt_normal_binding(
        receipt,
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )
    _assert_file_head(
        receipt_path,
        receipt_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="receipt_drift",
    )
    config_digest = _sha256_bytes(final_raw)
    installed = transition_desktop_demo_receipt(
        receipt,
        target_state="installed",
        occurred_at=format_utc(),
        config_sha256=config_digest,
    )
    _require_receipt_normal_binding(
        receipt,
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )
    _assert_file_head(
        receipt_path,
        receipt_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="receipt_drift",
    )
    try:
        _write_receipt(receipt_path, installed, expected_head=receipt_head)
    except Exception as exc:
        raise DesktopDemoError("setup_interrupted") from exc
    return _result(
        operation="desktop_setup",
        confirmed=True,
        applied=True,
        state="installed",
        preview_digest=str(receipt["preview_digest"]),
        config_path=config_path,
        receipt_path=receipt_path,
        staging_root=staging_root,
        managed_entry=managed,
        artifacts=tuple(artifacts),
        normal_ready=normal_ready,
    )


def setup_desktop_demo(
    repository_root: Path,
    *,
    confirmed: bool = False,
    expected_preview_digest: str | None = None,
    codex_home: Path,
    data_dir: Path,
    codex_executable: Path | None = None,
    python_executable: Path | None = None,
    runner: CommandRunner = _default_runner,
    operator_confirmed_hook_trust: bool = False,
    _lock_acquired: bool = False,
) -> DesktopDemoResult:
    """Preview or install the one reviewed synthetic Desktop MCP entry."""

    resolved_repository = Path(repository_root).resolve()
    resolved_home = _validated_demo_root(codex_home, label="codex_home")
    resolved_data = _validated_demo_root(data_dir, label="data_dir")
    if confirmed and not _lock_acquired:
        with _operation_lock(resolved_data):
            return setup_desktop_demo(
                resolved_repository,
                confirmed=True,
                expected_preview_digest=expected_preview_digest,
                codex_home=resolved_home,
                data_dir=resolved_data,
                codex_executable=codex_executable,
                python_executable=python_executable,
                runner=runner,
                operator_confirmed_hook_trust=operator_confirmed_hook_trust,
                _lock_acquired=True,
            )
    config_path, receipt_path, staging_root = _paths(resolved_home, resolved_data)
    ready = _normal_ready(
        codex_home=resolved_home,
        data_dir=resolved_data,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )
    prior_removed_receipt: dict[str, Any] | None = None
    prior_removed_receipt_head: _FileHead | None = None
    active_receipt_head = _absent_head()
    if receipt_path.exists() or receipt_path.is_symlink():
        receipt, active_receipt_head = _parse_desktop_demo_receipt_with_head(
            receipt_path,
            codex_home=resolved_home,
            data_dir=resolved_data,
        )
        if receipt["state"] != "removed":
            if confirmed:
                return _setup_recovery(
                    resolved_repository,
                    receipt=receipt,
                    receipt_head=active_receipt_head,
                    expected_preview_digest=expected_preview_digest,
                    codex_home=resolved_home,
                    data_dir=resolved_data,
                    normal_ready=ready,
                    runner=runner,
                    operator_confirmed_hook_trust=operator_confirmed_hook_trust,
                )
            issues = () if ready else ("normal_integration_not_ready",)
            return _result(
                operation="desktop_setup",
                confirmed=False,
                applied=False,
                state=str(receipt["state"]),
                preview_digest=str(receipt["preview_digest"]),
                config_path=config_path,
                receipt_path=receipt_path,
                staging_root=staging_root,
                managed_entry=cast(dict[str, Any], receipt["managed_entry"]),
                artifacts=tuple(cast(list[dict[str, Any]], receipt["artifacts"])),
                normal_ready=ready,
                issues=issues,
            )
        if not _receipt_managed_digest_valid(receipt):
            raise DesktopDemoError("receipt_invalid")
        removed_document, _, _ = _load_config(config_path)
        if _managed_from_document(removed_document) is not None:
            raise DesktopDemoError("removed_state_drift")
        artifacts_valid, artifacts_present = _artifact_removal_state(receipt, resolved_data)
        if not artifacts_valid or artifacts_present:
            raise DesktopDemoError("removed_state_drift")
        prior_removed_receipt = receipt
        prior_removed_receipt_head = active_receipt_head

    snapshot = _snapshot(
        resolved_repository,
        codex_home=resolved_home,
        data_dir=resolved_data,
        codex_executable=codex_executable,
        python_executable=python_executable,
        runner=runner,
        normal_ready=ready,
        prior_removed_receipt_sha256=(
            prior_removed_receipt_head.sha256 if prior_removed_receipt_head is not None else None
        ),
    )
    artifact = _artifact_from_snapshot(snapshot)
    issues = () if ready else ("normal_integration_not_ready",)
    preview = _result(
        operation="desktop_setup",
        confirmed=False,
        applied=False,
        state="absent",
        preview_digest=snapshot.digest,
        config_path=config_path,
        receipt_path=receipt_path,
        staging_root=staging_root,
        managed_entry=snapshot.managed_entry,
        artifacts=(artifact,),
        normal_ready=ready,
        issues=issues,
    )
    if not confirmed:
        return preview
    if not ready:
        raise DesktopDemoError("normal_integration_not_ready")

    _compare_preview(snapshot, expected_preview_digest)
    source = resolved_repository / FIXTURE_SOURCE
    cached = _cached_preview(cast(str, expected_preview_digest))
    if cached is None:
        raise DesktopDemoError("preview_digest_mismatch")
    current_source_digest, current_source_size = _hash_regular(source, MAX_FIXTURE_BYTES)
    if current_source_digest != cached.fixture_sha256 or current_source_size != cached.fixture_size:
        raise DesktopDemoError("fixture_source_drift")
    current_codex, current_codex_trust = _resolved_runtime(codex_executable, name="codex")
    current_python, current_python_trust = _resolved_runtime(
        python_executable or Path(sys.executable).resolve(),
        name="python3",
    )
    current_codex_identity = _runtime_identity(
        current_codex,
        current_codex_trust,
        runner=runner,
        codex_home=resolved_home,
    )
    current_python_identity = _runtime_identity(
        current_python,
        current_python_trust,
        runner=runner,
        codex_home=resolved_home,
    )
    if (
        current_codex_identity != cached.codex_runtime
        or current_python_identity != cached.python_runtime
    ):
        raise DesktopDemoError("runtime_drift")

    _require_snapshot_normal_binding(
        snapshot,
        codex_home=resolved_home,
        data_dir=resolved_data,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )

    demo_root = resolved_data / DEMO_DIRECTORY
    if staging_root.exists() and staging_root.is_symlink():
        raise DesktopDemoError("unsafe_staging")
    _private_directory(resolved_data)
    _private_directory(demo_root)
    if prior_removed_receipt is not None and prior_removed_receipt_head is not None:
        _require_snapshot_normal_binding(
            snapshot,
            codex_home=resolved_home,
            data_dir=resolved_data,
            runner=runner,
            operator_confirmed_hook_trust=operator_confirmed_hook_trust,
        )
        _archive_removed_receipt(
            receipt_path,
            prior_removed_receipt,
            data_dir=resolved_data,
            expected_head=prior_removed_receipt_head,
        )
    document, raw_config, config_head = _load_config(config_path)
    if (
        config_head.exists != snapshot.config_existed
        or _sha256_bytes(raw_config) != snapshot.config_sha256
        or _config_write_mode(config_head) != snapshot.config_mode
    ):
        raise DesktopDemoError("config_changed_after_preview")
    if _managed_from_document(document) is not None:
        raise DesktopDemoError("reserved_name_exists")
    unrelated_before = _unrelated_config_values(
        document,
        managed_parent_present_before=snapshot.managed_parent_present,
    )
    if _unrelated_config_digest(unrelated_before) != snapshot.config_unrelated_sha256:
        raise DesktopDemoError("config_projection_drift")
    receipt = _receipt_payload(
        snapshot,
        codex_home=resolved_home,
        data_dir=resolved_data,
        confirmed_at=format_utc(),
    )
    _require_snapshot_normal_binding(
        snapshot,
        codex_home=resolved_home,
        data_dir=resolved_data,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )
    try:
        receipt_head = _write_receipt(
            receipt_path,
            receipt,
            expected_head=active_receipt_head,
        )
    except Exception as exc:
        raise DesktopDemoError("setup_interrupted") from exc
    _require_snapshot_normal_binding(
        snapshot,
        codex_home=resolved_home,
        data_dir=resolved_data,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )
    _assert_file_head(
        receipt_path,
        receipt_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="receipt_drift",
    )
    _stage_fixture(
        source,
        staging_root / STAGED_SCRIPT_NAME,
        expected_digest=snapshot.fixture_sha256,
        expected_size=snapshot.fixture_size,
    )
    _require_snapshot_normal_binding(
        snapshot,
        codex_home=resolved_home,
        data_dir=resolved_data,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )
    _assert_file_head(
        receipt_path,
        receipt_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="receipt_drift",
    )
    _set_managed(document, snapshot.managed_entry)
    rendered = tomlkit.dumps(document).encode("utf-8")
    try:
        _atomic_write(
            config_path,
            rendered,
            mode=snapshot.config_mode,
            expected_exists=config_head.exists,
            expected_sha256=snapshot.config_sha256,
        )
    except DesktopDemoError:
        raise
    except Exception as exc:
        raise DesktopDemoError("setup_interrupted") from exc
    verified_document, verified_raw, verified_head = _load_config(config_path)
    unrelated_after = _unrelated_config_values(
        verified_document,
        managed_parent_present_before=snapshot.managed_parent_present,
    )
    if not _managed_matches(verified_document, snapshot.managed_entry):
        raise DesktopDemoError("setup_interrupted")
    if verified_head.mode != snapshot.config_mode:
        raise DesktopDemoError("config_mode_drift")
    if (
        not _parsed_config_values_match(
            unrelated_before,
            unrelated_after,
        )
        or _unrelated_config_digest(unrelated_after) != snapshot.config_unrelated_sha256
    ):
        _persist_projection_failure(
            receipt_path,
            receipt,
            receipt_head,
            config_path=config_path,
            config_head=verified_head,
            config_sha256=_sha256_bytes(verified_raw),
        )
    _require_snapshot_normal_binding(
        snapshot,
        codex_home=resolved_home,
        data_dir=resolved_data,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )
    _assert_file_head(
        receipt_path,
        receipt_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="receipt_drift",
    )
    if not _artifact_intact(receipt, resolved_data):
        raise DesktopDemoError("staged_artifact_drift")
    final_document, final_raw, final_head = _load_config(config_path)
    final_unrelated = _unrelated_config_values(
        final_document,
        managed_parent_present_before=snapshot.managed_parent_present,
    )
    if (
        not _managed_matches(final_document, snapshot.managed_entry)
        or _unrelated_config_digest(final_unrelated) != snapshot.config_unrelated_sha256
        or final_head.mode != snapshot.config_mode
    ):
        raise DesktopDemoError("config_changed_before_finalization")
    _require_snapshot_normal_binding(
        snapshot,
        codex_home=resolved_home,
        data_dir=resolved_data,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )
    _assert_file_head(
        receipt_path,
        receipt_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="receipt_drift",
    )
    installed = transition_desktop_demo_receipt(
        receipt,
        target_state="installed",
        occurred_at=format_utc(),
        config_sha256=_sha256_bytes(final_raw),
    )
    _require_snapshot_normal_binding(
        snapshot,
        codex_home=resolved_home,
        data_dir=resolved_data,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )
    _assert_file_head(
        receipt_path,
        receipt_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="receipt_drift",
    )
    try:
        _write_receipt(receipt_path, installed, expected_head=receipt_head)
    except Exception as exc:
        raise DesktopDemoError("setup_interrupted") from exc
    return _result(
        operation="desktop_setup",
        confirmed=True,
        applied=True,
        state="installed",
        preview_digest=snapshot.digest,
        config_path=config_path,
        receipt_path=receipt_path,
        staging_root=staging_root,
        managed_entry=snapshot.managed_entry,
        artifacts=(artifact,),
        normal_ready=True,
    )


def _private_directory_intact(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        return False
    return not (
        os.name != "nt"
        and (details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077)
    )


def _staging_directories_intact(staging: Path, data_dir: Path) -> bool:
    for path in (data_dir / DEMO_DIRECTORY, staging):
        if not _private_directory_intact(path):
            return False
    return True


def _artifact_removal_state(receipt: dict[str, Any], data_dir: Path) -> tuple[bool, bool]:
    staging = Path(str(receipt["staging_root"]))
    demo_root = data_dir / DEMO_DIRECTORY
    if not _private_directory_intact(demo_root):
        return False, False
    if not staging.exists() and not staging.is_symlink():
        return True, False
    if not _staging_directories_intact(staging, data_dir):
        return False, False
    artifacts = cast(list[dict[str, Any]], receipt["artifacts"])
    all_present = True
    for artifact in artifacts:
        path = staging / str(artifact["relative_path"])
        if not _is_within(path, staging):
            return False, False
        if not path.exists() and not path.is_symlink():
            all_present = False
            continue
        try:
            digest, size = _hash_regular(path, MAX_FIXTURE_BYTES, private=True)
        except DesktopDemoError:
            return False, False
        if digest != artifact["sha256"] or size != artifact["size_bytes"]:
            return False, False
    return True, all_present


def _artifact_intact(receipt: dict[str, Any], data_dir: Path) -> bool:
    valid, all_present = _artifact_removal_state(receipt, data_dir)
    return valid and all_present


def _stat_matches_head(details: os.stat_result, expected: _FileHead) -> bool:
    return bool(
        expected.exists
        and details.st_dev == expected.device
        and details.st_ino == expected.inode
        and details.st_size == expected.size
        and getattr(details, "st_uid", None) == expected.owner
        and stat.S_IMODE(details.st_mode) == expected.mode
        and stat.S_ISREG(details.st_mode)
    )


def _restore_quarantined_entry(
    directory: int,
    *,
    quarantined: str,
    original: str,
) -> None:
    try:
        os.stat(original, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        try:
            os.rename(
                quarantined,
                original,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
        except OSError:
            pass


def _anchored_remove_artifact(
    path: Path,
    *,
    expected_digest: str,
    expected_size: int,
) -> None:
    """Rename, reverify, then unlink only the exact receipt-bound inode."""

    if os.name == "nt":  # pragma: no cover - Desktop demo target is exercised on macOS.
        raise DesktopDemoError("staged_artifact_drift")
    raw, expected_head = _read_file_snapshot(path, MAX_FIXTURE_BYTES, private=True)
    if (
        not expected_head.exists
        or expected_head.sha256 != expected_digest
        or expected_head.size != expected_size
        or expected_head.mode != 0o600
        or _sha256_bytes(raw) != expected_digest
    ):
        raise DesktopDemoError("staged_artifact_drift")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory = -1
    quarantine = f".{path.name}.verity-remove-{new_id()}"
    moved = False
    try:
        directory = os.open(path.parent, flags)
        current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if not _stat_matches_head(current, expected_head):
            raise DesktopDemoError("staged_artifact_drift")
        try:
            os.stat(quarantine, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise DesktopDemoError("staged_artifact_drift")
        os.rename(
            path.name,
            quarantine,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        moved = True
        moved_details = os.stat(quarantine, dir_fd=directory, follow_symlinks=False)
        if not _stat_matches_head(moved_details, expected_head):
            _restore_quarantined_entry(
                directory,
                quarantined=quarantine,
                original=path.name,
            )
            moved = False
            raise DesktopDemoError("staged_artifact_drift")
        quarantined_path = path.parent / quarantine
        moved_raw, moved_head = _read_file_snapshot(
            quarantined_path,
            MAX_FIXTURE_BYTES,
            private=True,
        )
        if moved_head != expected_head or moved_raw != raw:
            _restore_quarantined_entry(
                directory,
                quarantined=quarantine,
                original=path.name,
            )
            moved = False
            raise DesktopDemoError("staged_artifact_drift")
        final_details = os.stat(quarantine, dir_fd=directory, follow_symlinks=False)
        if not _stat_matches_head(final_details, expected_head):
            _restore_quarantined_entry(
                directory,
                quarantined=quarantine,
                original=path.name,
            )
            moved = False
            raise DesktopDemoError("staged_artifact_drift")
        os.unlink(quarantine, dir_fd=directory)
        moved = False
        os.fsync(directory)
    except DesktopDemoError:
        raise
    except OSError as exc:
        if moved and directory >= 0:
            _restore_quarantined_entry(
                directory,
                quarantined=quarantine,
                original=path.name,
            )
        raise DesktopDemoError("staged_artifact_drift") from exc
    finally:
        if directory >= 0:
            os.close(directory)


def _runtimes_intact(receipt: dict[str, Any]) -> bool:
    for name in ("codex_runtime", "python_runtime"):
        identity = cast(dict[str, Any], receipt[name])
        try:
            path = Path(str(identity["path"]))
            resolved, trust = resolve_trusted_executable(
                "codex" if name == "codex_runtime" else "python3",
                path,
                executable_label=f"{name} executable",
                ancestor_label="trusted desktop demo",
            )
        except ConfigurationError:
            return False
        if (
            resolved != path
            or trust.digest != identity["sha256"]
            or trust.target_chain[-1].size != identity["size_bytes"]
        ):
            return False
    return True


def _terminate_probe(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        if process.poll() is not None:
            return
        try:
            process.terminate()
        except (PermissionError, ProcessLookupError):
            return
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (PermissionError, ProcessLookupError):
            return
    try:
        process.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        pass
    if os.name == "nt":
        try:
            process.kill()
        except (PermissionError, ProcessLookupError):
            return
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (PermissionError, ProcessLookupError):
            return
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass


def _probe_request(identifier: int, method: str, params: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params},
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def probe_desktop_fixture(
    staged_script: Path,
    *,
    python_executable: Path,
    timeout_seconds: float = 2.0,
    max_output_bytes: int = 65_536,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> DesktopFixtureProbe:
    """Probe only initialize/list/guidance and return no raw child content."""

    failure = DesktopFixtureProbe(False, None, None, (), None, False, ("fixture_probe_failed",))
    if not 0 < timeout_seconds <= 5 or not 256 <= max_output_bytes <= 1_048_576:
        return failure
    if (expected_sha256 is None) != (expected_size is None):
        return failure
    if expected_sha256 is not None and (
        not _is_sha(expected_sha256)
        or expected_size is None
        or not 0 < expected_size <= MAX_FIXTURE_BYTES
    ):
        return failure
    try:
        script = Path(staged_script)
        if not script.is_absolute() or ".." in script.parts or script.is_symlink():
            raise DesktopDemoError("unsafe_staged_script")
        snapshot_trusted_directory(
            script.parent,
            current_user_only=True,
            directory_label="desktop fixture directory",
            ancestor_label="trusted desktop fixture",
        )
        python, python_trust = _resolved_runtime(Path(python_executable), name="python3")
        if not recheck_trusted_executable(
            python,
            python_trust,
            executable_label="Python runtime",
            ancestor_label="trusted desktop demo",
        ):
            raise DesktopDemoError("runtime_drift")
        script_content, script_details = _read_regular(
            script,
            MAX_FIXTURE_BYTES,
            private=True,
        )
        if expected_sha256 is not None and (
            _sha256_bytes(script_content) != expected_sha256
            or script_details.st_size != expected_size
        ):
            raise DesktopDemoError("staged_artifact_drift")
        process = subprocess.Popen(  # noqa: S603 - fixed executable and arguments
            [str(python), "-I", str(script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=script.parent,
            env={
                "PYTHONNOUSERSITE": "1",
                "PYTHONUTF8": "1",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
            start_new_session=os.name != "nt",
        )
    except (ConfigurationError, DesktopDemoError, OSError):
        return failure
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    request = b"".join(
        (
            _probe_request(
                1,
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "verity-desktop-probe", "version": "1.0.0"},
                },
            ),
            _probe_request(2, "tools/list", {}),
            _probe_request(
                3,
                "tools/call",
                {"name": "get_release_guidance", "arguments": {"release_channel": "stable"}},
            ),
        )
    )
    output: list[bytes] = []
    error_output: list[bytes] = []
    exceeded = threading.Event()
    responses_complete = threading.Event()

    def read_bounded(
        stream: Any,
        target: list[bytes],
        limit: int,
        completion: threading.Event | None = None,
    ) -> None:
        total = 0
        newlines = 0
        try:
            while chunk := stream.read(4096):
                total += len(chunk)
                if total > limit:
                    exceeded.set()
                    return
                target.append(chunk)
                if completion is not None:
                    newlines += chunk.count(b"\n")
                    if newlines >= 3:
                        completion.set()
        except (OSError, ValueError):
            return

    stdout_thread = threading.Thread(
        target=read_bounded,
        args=(process.stdout, output, max_output_bytes, responses_complete),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=read_bounded,
        args=(process.stderr, error_output, min(max_output_bytes, 4096)),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    deadline = time.monotonic() + timeout_seconds
    terminated_after_responses = False
    try:
        process.stdin.write(request)
        process.stdin.flush()
        process.stdin.close()
        while process.poll() is None and not exceeded.is_set() and not responses_complete.is_set():
            if time.monotonic() >= deadline:
                _terminate_probe(process)
                return DesktopFixtureProbe(
                    False,
                    None,
                    None,
                    (),
                    None,
                    False,
                    ("fixture_probe_timeout",),
                )
            time.sleep(0.005)
        if responses_complete.is_set():
            terminated_after_responses = True
            _terminate_probe(process)
        if exceeded.is_set():
            _terminate_probe(process)
            return DesktopFixtureProbe(
                False,
                None,
                None,
                (),
                None,
                False,
                ("fixture_probe_output_limit",),
            )
        remaining = max(0.0, deadline - time.monotonic())
        stdout_thread.join(remaining)
        stderr_thread.join(remaining)
        if stdout_thread.is_alive() or stderr_thread.is_alive():
            _terminate_probe(process)
            return DesktopFixtureProbe(
                False,
                None,
                None,
                (),
                None,
                False,
                ("fixture_probe_timeout",),
            )
        if (process.returncode != 0 and not terminated_after_responses) or error_output:
            return failure
        raw = b"".join(output)
        if not raw.endswith(b"\n") or len(raw) > max_output_bytes:
            return failure
        responses = [parse_json_strict(line) for line in raw.splitlines()]
        if len(responses) != 3 or any(not isinstance(item, dict) for item in responses):
            return failure
        by_id = {item.get("id"): item for item in responses}
        if set(by_id) != {1, 2, 3} or any("error" in item for item in responses):
            return failure
        initialize = by_id[1]["result"]
        tools = by_id[2]["result"]["tools"]
        guidance = by_id[3]["result"]["content"][0]["text"]
        server_name = initialize["serverInfo"]["name"]
        protocol = initialize["protocolVersion"]
        tool_names = tuple(item["name"] for item in tools)
        if (
            server_name != "verity-cordon-poisoned-docs-fixture"
            or protocol != "2025-11-25"
            or tool_names != _TOOL_NAMES
            or not isinstance(guidance, str)
        ):
            return failure
        return DesktopFixtureProbe(
            True,
            server_name,
            protocol,
            tool_names,
            _sha256_bytes(guidance.encode("utf-8")),
            False,
            (),
        )
    except (BrokenPipeError, KeyError, OSError, TypeError, ValueError):
        _terminate_probe(process)
        return failure
    finally:
        _terminate_probe(process)
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass
        stdout_thread.join(0.2)
        stderr_thread.join(0.2)


def _system_failure(issue: str) -> DesktopSystemReadiness:
    return DesktopSystemReadiness(
        ready=False,
        daemon_ready=False,
        ledger_verified=False,
        policy_valid=False,
        memory_view_consistent=False,
        control_room_ready=False,
        control_room_headers_ready=False,
        issues=(issue,),
    )


def _direct_loopback_get(
    *,
    host: str,
    port: int,
    path: str,
    accept: str,
    timeout_seconds: float,
    max_response_bytes: int,
) -> tuple[int, bytes, dict[str, tuple[str, ...]]]:
    validated = validate_loopback_host(host)
    connect_host = "127.0.0.1" if validated == "localhost" else validated
    rendered_host = f"[{validated}]" if ":" in validated else validated
    connection = http.client.HTTPConnection(connect_host, port, timeout=timeout_seconds)
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Host": f"{rendered_host}:{port}",
                "Accept": accept,
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        body = response.read(max_response_bytes + 1)
        header_values: dict[str, list[str]] = {}
        for name, value in response.getheaders():
            header_values.setdefault(name.lower(), []).append(value.strip())
        return (
            response.status,
            body,
            {name: tuple(values) for name, values in header_values.items()},
        )
    finally:
        connection.close()


def _control_room_headers_ready(headers: Mapping[str, tuple[str, ...]]) -> bool:
    for name, expected in _CONTROL_ROOM_HEADERS.items():
        values = headers.get(name, ())
        if len(values) != 1 or values[0].lower() != expected:
            return False
    csp_values = headers.get("content-security-policy", ())
    if len(csp_values) != 1:
        return False
    return all(directive in csp_values[0] for directive in _CONTROL_ROOM_CSP_DIRECTIVES)


def probe_desktop_system(
    *,
    host: str,
    port: int,
    timeout_seconds: float = 1.0,
    max_response_bytes: int = MAX_SYSTEM_RESPONSE_BYTES,
) -> DesktopSystemReadiness:
    """Verify daemon and Control Room state through unauthenticated loopback GETs."""

    if (
        not isinstance(port, int)
        or not 1 <= port <= 65_535
        or not 0 < timeout_seconds <= 5
        or not 1_024 <= max_response_bytes <= 1_048_576
    ):
        return _system_failure("system_probe_configuration_invalid")
    try:
        status_code, body, headers = _direct_loopback_get(
            host=host,
            port=port,
            path="/api/v1/readiness",
            accept="application/json",
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
    except (ConfigurationError, OSError, TimeoutError, http.client.HTTPException):
        return _system_failure("system_unreachable")
    if status_code != 200:
        return _system_failure("readiness_http_error")
    if len(body) > max_response_bytes:
        return _system_failure("readiness_output_limit")
    content_types = headers.get("content-type", ())
    if (
        len(content_types) != 1
        or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
    ):
        return _system_failure("readiness_contract_invalid")
    try:
        parsed = parse_json_strict(body.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("readiness response must be an object")
        readiness = _ReadinessResponse.model_validate(parsed)
    except (UnicodeDecodeError, ValueError, ValidationError):
        return _system_failure("readiness_contract_invalid")

    issues: list[str] = []
    if not readiness.daemon_ready:
        issues.append("daemon_not_ready")
    if not readiness.ledger_verified:
        issues.append("ledger_invalid")
    if not readiness.policy_valid:
        issues.append("policy_invalid")
    if not readiness.memory_view_consistent:
        issues.append("materialized_view_stale")

    try:
        control_status, control_body, control_headers = _direct_loopback_get(
            host=host,
            port=port,
            path="/",
            accept="text/html",
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
    except (ConfigurationError, OSError, TimeoutError, http.client.HTTPException):
        issues.append("control_room_unreachable")
        control_status = 0
        control_body = b""
        control_headers = {}
    control_content_types = control_headers.get("content-type", ())
    control_content_type_ready = bool(
        len(control_content_types) == 1
        and control_content_types[0].split(";", 1)[0].strip().lower() == "text/html"
    )
    control_room_ready = bool(
        control_status == 200
        and 0 < len(control_body) <= max_response_bytes
        and control_content_type_ready
    )
    if control_status == 200 and len(control_body) > max_response_bytes:
        issues.append("control_room_output_limit")
    elif control_status != 200:
        issues.append("control_room_http_error")
    elif not control_body or not control_content_type_ready:
        issues.append("control_room_contract_invalid")
    control_room_headers_ready = _control_room_headers_ready(control_headers)
    if not control_room_headers_ready:
        issues.append("control_room_security_headers_invalid")

    system_ready = bool(readiness.ready and control_room_ready and control_room_headers_ready)
    return DesktopSystemReadiness(
        ready=system_ready,
        daemon_ready=readiness.daemon_ready,
        ledger_verified=readiness.ledger_verified,
        policy_valid=readiness.policy_valid,
        memory_view_consistent=readiness.memory_view_consistent,
        control_room_ready=control_room_ready,
        control_room_headers_ready=control_room_headers_ready,
        issues=tuple(dict.fromkeys(issues)),
    )


def status_desktop_demo(
    repository_root: Path,
    *,
    codex_home: Path,
    data_dir: Path,
    runner: CommandRunner = _default_runner,
    operator_confirmed_hook_trust: bool = False,
    probe: bool = True,
    daemon_host: str = "127.0.0.1",
    daemon_port: int = 8765,
    system_probe: _SystemProbe = probe_desktop_system,
) -> DesktopDemoStatus:
    """Return content-safe demo readiness without exposing receipt or config data."""

    del repository_root  # receipt-bound staged state is authoritative after setup
    resolved_home = _validated_demo_root(codex_home, label="codex_home")
    resolved_data = _validated_demo_root(data_dir, label="data_dir")
    config_path, receipt_path, _ = _paths(resolved_home, resolved_data)
    normal_doctor_ready = _normal_ready(
        codex_home=resolved_home,
        data_dir=resolved_data,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )
    system = system_probe(
        host=daemon_host,
        port=daemon_port,
        timeout_seconds=1.0,
        max_response_bytes=MAX_SYSTEM_RESPONSE_BYTES,
    )
    issues: list[str] = list(system.issues)
    if not normal_doctor_ready:
        issues.append("normal_integration_not_ready")
    try:
        receipt = parse_desktop_demo_receipt(
            receipt_path,
            codex_home=resolved_home,
            data_dir=resolved_data,
        )
        receipt_digest_valid = _receipt_managed_digest_valid(receipt)
        normal_receipt_intact = _normal_receipt_matches(receipt, resolved_data)
        receipt_valid = receipt_digest_valid and normal_receipt_intact
        normal_ready = normal_doctor_ready and normal_receipt_intact
    except DesktopDemoError:
        issues.append("desktop_demo_receipt_invalid")
        return DesktopDemoStatus(
            ready=False,
            fixture_ready=False,
            system_ready=system.ready,
            state="invalid",
            receipt_valid=False,
            managed_entry_intact=False,
            artifacts_intact=False,
            runtimes_intact=False,
            normal_integration_ready=normal_doctor_ready,
            fixture_probe_ready=False,
            daemon_ready=system.daemon_ready,
            ledger_verified=system.ledger_verified,
            policy_valid=system.policy_valid,
            memory_view_consistent=system.memory_view_consistent,
            control_room_ready=system.control_room_ready,
            control_room_headers_ready=system.control_room_headers_ready,
            issues=tuple(dict.fromkeys(issues)),
        )
    if not receipt_digest_valid:
        issues.append("desktop_demo_receipt_invalid")
    if not normal_receipt_intact:
        issues.append("normal_integration_drift")
    state = str(receipt["state"])
    if state != "installed":
        issues.append("desktop_demo_not_installed")
    try:
        document, _, _ = _load_config(config_path)
        managed_intact = _managed_matches(
            document,
            cast(dict[str, Any], receipt["managed_entry"]),
        )
    except DesktopDemoError:
        managed_intact = False
    if not managed_intact:
        issues.append("managed_entry_drift")
    artifacts_intact = _artifact_intact(receipt, resolved_data)
    if not artifacts_intact:
        issues.append("staged_artifact_drift")
    runtimes_intact = _runtimes_intact(receipt)
    if not runtimes_intact:
        issues.append("runtime_drift")
    fixture_probe_ready = False
    if (
        probe
        and state == "installed"
        and receipt_valid
        and normal_ready
        and managed_intact
        and artifacts_intact
        and runtimes_intact
    ):
        staging_root = Path(str(receipt["staging_root"]))
        python_runtime = cast(dict[str, Any], receipt["python_runtime"])
        artifact = cast(list[dict[str, Any]], receipt["artifacts"])[0]
        report = probe_desktop_fixture(
            staging_root / STAGED_SCRIPT_NAME,
            python_executable=Path(str(python_runtime["path"])),
            expected_sha256=str(artifact["sha256"]),
            expected_size=int(artifact["size_bytes"]),
        )
        fixture_probe_ready = report.ready
        if not fixture_probe_ready:
            issues.extend(report.issues)
    elif not probe:
        issues.append("fixture_probe_not_run")
    else:
        issues.append("fixture_probe_not_run")
    fixture_ready = bool(
        state == "installed"
        and receipt_valid
        and managed_intact
        and artifacts_intact
        and runtimes_intact
        and normal_ready
        and fixture_probe_ready
    )
    ready = fixture_ready and system.ready
    return DesktopDemoStatus(
        ready=ready,
        fixture_ready=fixture_ready,
        system_ready=system.ready,
        state=state,
        receipt_valid=receipt_valid,
        managed_entry_intact=managed_intact,
        artifacts_intact=artifacts_intact,
        runtimes_intact=runtimes_intact,
        normal_integration_ready=normal_ready,
        fixture_probe_ready=fixture_probe_ready,
        daemon_ready=system.daemon_ready,
        ledger_verified=system.ledger_verified,
        policy_valid=system.policy_valid,
        memory_view_consistent=system.memory_view_consistent,
        control_room_ready=system.control_room_ready,
        control_room_headers_ready=system.control_room_headers_ready,
        issues=tuple(dict.fromkeys(issues)),
    )


def _teardown_snapshot(
    receipt: dict[str, Any],
    receipt_head: _FileHead,
    document: Any,
    raw_config: bytes,
    data_dir: Path,
) -> str:
    managed = cast(dict[str, Any], receipt["managed_entry"])
    actual_managed = _managed_from_document(document)
    artifacts_valid, artifacts_present = _artifact_removal_state(receipt, data_dir)
    payload = {
        "operation": "desktop_teardown",
        "receipt_sha256": receipt_head.sha256,
        "state": receipt["state"],
        "config_sha256": _sha256_bytes(raw_config),
        "managed_entry_intact": _managed_values_match(
            actual_managed,
            _config_managed(managed),
        ),
        "managed_entry_absent": actual_managed is None,
        "artifacts_valid": artifacts_valid,
        "artifacts_present": artifacts_present,
        "runtimes_intact": _runtimes_intact(receipt),
    }
    return _sha256_bytes(canonical_json_bytes(payload))


def teardown_desktop_demo(
    repository_root: Path,
    *,
    confirmed: bool = False,
    expected_preview_digest: str | None = None,
    codex_home: Path,
    data_dir: Path,
    runner: CommandRunner = _default_runner,
    operator_confirmed_hook_trust: bool = False,
    _lock_acquired: bool = False,
) -> DesktopDemoResult:
    """Preview or remove only the exact receipt-bound demo entry and artifact."""

    resolved_home = _validated_demo_root(codex_home, label="codex_home")
    resolved_data = _validated_demo_root(data_dir, label="data_dir")
    if confirmed and not _lock_acquired:
        with _operation_lock(resolved_data):
            return teardown_desktop_demo(
                repository_root,
                confirmed=True,
                expected_preview_digest=expected_preview_digest,
                codex_home=resolved_home,
                data_dir=resolved_data,
                runner=runner,
                operator_confirmed_hook_trust=operator_confirmed_hook_trust,
                _lock_acquired=True,
            )
    del repository_root
    config_path, receipt_path, staging_root = _paths(resolved_home, resolved_data)
    normal_ready = _normal_ready(
        codex_home=resolved_home,
        data_dir=resolved_data,
        runner=runner,
        operator_confirmed_hook_trust=operator_confirmed_hook_trust,
    )
    receipt, receipt_head = _parse_desktop_demo_receipt_with_head(
        receipt_path,
        codex_home=resolved_home,
        data_dir=resolved_data,
    )
    if not _receipt_managed_digest_valid(receipt):
        raise DesktopDemoError("receipt_invalid")
    if receipt["state"] not in {"failed", "installed", "removing"}:
        raise DesktopDemoError("desktop_demo_not_installed")
    document, raw_config, config_head = _load_config(config_path)
    config_mode = _config_write_mode(config_head)
    managed = cast(dict[str, Any], receipt["managed_entry"])
    actual_managed = _managed_from_document(document)
    managed_intact = _managed_values_match(actual_managed, _config_managed(managed))
    managed_absent = actual_managed is None
    artifacts_valid, artifacts_present = _artifact_removal_state(receipt, resolved_data)
    runtimes_intact = _runtimes_intact(receipt)
    removing = receipt["state"] == "removing"
    managed_recoverable = managed_intact or (removing and managed_absent)
    artifacts_recoverable = artifacts_valid and (artifacts_present or removing)
    issues: list[str] = []
    if not normal_ready:
        issues.append("normal_integration_not_ready")
    if not managed_recoverable:
        issues.append("managed_entry_drift")
    if not artifacts_recoverable:
        issues.append("staged_artifact_drift")
    if not runtimes_intact:
        issues.append("runtime_drift")
    managed_original = cast(dict[str, Any], receipt["managed_entry_original"])
    parent_present_before = bool(managed_original["parent_table_present"])
    unrelated_before = _unrelated_config_values(
        document,
        managed_parent_present_before=parent_present_before,
    )
    preview_digest = _teardown_snapshot(
        receipt,
        receipt_head,
        document,
        raw_config,
        resolved_data,
    )
    result = _result(
        operation="desktop_teardown",
        confirmed=False,
        applied=False,
        state=str(receipt["state"]),
        preview_digest=preview_digest,
        config_path=config_path,
        receipt_path=receipt_path,
        staging_root=staging_root,
        managed_entry=managed,
        artifacts=tuple(cast(list[dict[str, Any]], receipt["artifacts"])),
        normal_ready=normal_ready,
        issues=tuple(issues),
    )
    if not confirmed:
        return result
    if expected_preview_digest != preview_digest:
        raise DesktopDemoError("config_changed_after_preview")
    if not managed_recoverable:
        raise DesktopDemoError("managed_entry_drift")
    if not artifacts_recoverable:
        raise DesktopDemoError("staged_artifact_drift")
    if not runtimes_intact:
        raise DesktopDemoError("runtime_drift")
    current = receipt
    current_receipt_head = receipt_head
    if receipt["state"] in {"failed", "installed"}:
        current = transition_desktop_demo_receipt(
            receipt,
            target_state="removing",
            occurred_at=format_utc(),
        )
        try:
            current_receipt_head = _write_receipt(
                receipt_path,
                current,
                expected_head=receipt_head,
            )
        except Exception as exc:
            raise DesktopDemoError("teardown_interrupted") from exc
    if managed_intact:
        _assert_file_head(
            receipt_path,
            current_receipt_head,
            maximum=MAX_RECEIPT_BYTES,
            private=True,
            error="receipt_drift",
        )
        original = cast(dict[str, Any], current["managed_entry_original"])
        _remove_managed(
            document,
            remove_empty_parent=not bool(original["parent_table_present"]),
        )
        try:
            _atomic_write(
                config_path,
                tomlkit.dumps(document).encode("utf-8"),
                mode=config_mode,
                expected_exists=config_head.exists,
                expected_sha256=_sha256_bytes(raw_config),
            )
        except DesktopDemoError:
            raise
        except Exception as exc:
            raise DesktopDemoError("teardown_interrupted") from exc
    _assert_file_head(
        receipt_path,
        current_receipt_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="receipt_drift",
    )
    verified_document, _, verified_config_head = _load_config(config_path)
    verified_unrelated = _unrelated_config_values(
        verified_document,
        managed_parent_present_before=parent_present_before,
    )
    if (
        _managed_from_document(verified_document) is not None
        or not _parsed_config_values_match(unrelated_before, verified_unrelated)
        or verified_config_head.mode != config_mode
    ):
        raise DesktopDemoError("teardown_config_verification_failed")
    artifacts = cast(list[dict[str, Any]], current["artifacts"])
    for artifact in artifacts:
        target = staging_root / str(artifact["relative_path"])
        if not target.exists() and not target.is_symlink():
            continue
        _assert_file_head(
            receipt_path,
            current_receipt_head,
            maximum=MAX_RECEIPT_BYTES,
            private=True,
            error="receipt_drift",
        )
        _anchored_remove_artifact(
            target,
            expected_digest=str(artifact["sha256"]),
            expected_size=int(artifact["size_bytes"]),
        )
    try:
        staging_root.rmdir()
    except OSError:
        # Unknown files are operator-owned and intentionally prevent removal.
        pass
    final_document, final_raw, final_config_head = _load_config(config_path)
    final_unrelated = _unrelated_config_values(
        final_document,
        managed_parent_present_before=parent_present_before,
    )
    if (
        _managed_from_document(final_document) is not None
        or not _parsed_config_values_match(verified_unrelated, final_unrelated)
        or final_config_head.mode != config_mode
    ):
        raise DesktopDemoError("teardown_config_verification_failed")
    _assert_file_head(
        receipt_path,
        current_receipt_head,
        maximum=MAX_RECEIPT_BYTES,
        private=True,
        error="receipt_drift",
    )
    removed = transition_desktop_demo_receipt(
        current,
        target_state="removed",
        occurred_at=format_utc(),
        config_sha256=_sha256_bytes(final_raw),
    )
    try:
        _write_receipt(receipt_path, removed, expected_head=current_receipt_head)
    except Exception as exc:
        raise DesktopDemoError("teardown_interrupted") from exc
    return _result(
        operation="desktop_teardown",
        confirmed=True,
        applied=True,
        state="removed",
        preview_digest=preview_digest,
        config_path=config_path,
        receipt_path=receipt_path,
        staging_root=staging_root,
        managed_entry=managed,
        artifacts=tuple(artifacts),
        normal_ready=normal_ready,
    )


__all__ = [
    "DesktopDemoError",
    "DesktopDemoResult",
    "DesktopDemoStatus",
    "DesktopFixtureProbe",
    "DesktopSystemReadiness",
    "parse_desktop_demo_receipt",
    "probe_desktop_fixture",
    "probe_desktop_system",
    "setup_desktop_demo",
    "status_desktop_demo",
    "teardown_desktop_demo",
    "transition_desktop_demo_receipt",
]
