"""Receipt-bound Codex Desktop setup for the synthetic poisoned-docs fixture.

This module is intentionally separate from the normal Codex installer. It
manages one reserved MCP entry, one reviewed local script, and one private
write-ahead receipt. It never changes Verity ledger or memory state.
"""

from __future__ import annotations

import hashlib
import http.client
import json
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
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal, Protocol, cast

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows remains an unverified target.
    _fcntl = None  # type: ignore[assignment]

import tomlkit
from pydantic import Field, ValidationError, model_validator

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
RECEIPT_VERSION: Final = "1.0.0"
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
    receipt_version: Literal["1.0.0"]
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
    receipt_version: Literal["1.0.0"]
    installation_id: str = Field(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    state: Literal["prepared", "installed", "removing", "removed"]
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
    config_after_sha256: str | None
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
        if self.state == "prepared":
            valid = self.config_after_sha256 is None and _empty_teardown(self.teardown)
        elif self.state == "installed":
            valid = _is_sha(self.config_after_sha256) and _empty_teardown(self.teardown)
        elif self.state == "removing":
            valid = (
                _is_sha(self.config_after_sha256)
                and self.teardown.requested_at is not None
                and self.teardown.completed_at is None
                and self.teardown.config_after_teardown_sha256 is None
            )
        else:
            valid = (
                _is_sha(self.config_after_sha256)
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
    fixture_sha256: str
    fixture_size: int
    codex_runtime: dict[str, Any]
    python_runtime: dict[str, Any]
    normal_receipt_sha256: str
    managed_entry: dict[str, Any]
    config_existed: bool
    managed_parent_present: bool
    prior_removed_receipt_sha256: str | None


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


def _atomic_write(
    path: Path,
    content: bytes,
    *,
    mode: int = 0o600,
    expected_sha256: str | None = None,
) -> None:
    if path.exists() and path.is_symlink():
        raise DesktopDemoError("unsafe_write_target")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if expected_sha256 is not None:
            if path.exists() or path.is_symlink():
                current, _ = _read_regular(path, MAX_CONFIG_BYTES, private=True)
            else:
                current = b""
            if _sha256_bytes(current) != expected_sha256:
                raise DesktopDemoError("config_changed_after_preview")
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
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
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


def _load_config(path: Path) -> tuple[Any, bytes]:
    if not path.exists():
        if path.is_symlink():
            raise DesktopDemoError("unsafe_config")
        return tomlkit.document(), b""
    try:
        raw, _ = _read_regular(path, MAX_CONFIG_BYTES, private=True)
        return tomlkit.parse(raw.decode("utf-8", errors="strict")), raw
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
    if not isinstance(parsed, dict) or parsed.get("schema_version") != RECEIPT_VERSION:
        raise DesktopDemoError("normal_integration_not_ready")
    return path, _sha256_bytes(raw), RECEIPT_VERSION


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
    document, raw_config = _load_config(config_path)
    config_existed = config_path.exists()
    managed_parent_present = _managed_parent_present(document)
    if _managed_from_document(document) is not None:
        raise DesktopDemoError("reserved_name_exists")
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
        normal_path, normal_digest, _ = _normal_receipt(data_dir)
    except DesktopDemoError:
        if normal_ready:
            raise
        normal_path = data_dir / NORMAL_RECEIPT_FILENAME
        normal_digest = EMPTY_SHA256
    staging_root = data_dir / DEMO_DIRECTORY / STAGING_DIRECTORY
    managed = _managed_entry(python, staging_root)
    payload = {
        "contract": RECEIPT_VERSION,
        "codex_home": str(codex_home),
        "config_path": str(config_path),
        "config_sha256": _sha256_bytes(raw_config),
        "config_existed": config_existed,
        "data_dir": str(data_dir),
        "fixture_sha256": fixture_digest,
        "fixture_size": fixture_size,
        "codex_runtime": codex_identity,
        "python_runtime": python_identity,
        "normal_receipt_path": str(normal_path),
        "normal_receipt_sha256": normal_digest,
        "normal_ready": normal_ready,
        "managed_entry": managed,
        "managed_parent_present": managed_parent_present,
        "prior_removed_receipt_sha256": prior_removed_receipt_sha256,
    }
    digest = _sha256_bytes(canonical_json_bytes(payload))
    snapshot = _PreviewSnapshot(
        digest=digest,
        config_sha256=_sha256_bytes(raw_config),
        fixture_sha256=fixture_digest,
        fixture_size=fixture_size,
        codex_runtime=codex_identity,
        python_runtime=python_identity,
        normal_receipt_sha256=normal_digest,
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
            "Restart Codex Desktop.",
            "Open a new task and run the Desktop demo only with synthetic data.",
            "Run verity doctor and wait for a signed terminal evidence decision.",
        )
    return ("Restart Codex Desktop after removing the synthetic fixture.",)


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
        validated = _DesktopReceipt.model_validate(value).model_dump(mode="json")
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


def parse_desktop_demo_receipt(
    path: Path,
    *,
    codex_home: Path,
    data_dir: Path,
) -> dict[str, Any]:
    """Parse a private receipt with duplicate-key, schema, and scope checks."""

    try:
        raw, _ = _read_regular(path, MAX_RECEIPT_BYTES, private=True)
    except DesktopDemoError as exc:
        message = (
            "receipt_permissions" if path.exists() and not path.is_symlink() else "receipt_invalid"
        )
        raise DesktopDemoError(message) from exc
    try:
        parsed = parse_json_strict(raw)
        if not isinstance(parsed, dict):
            raise ValueError
        validated = _DesktopReceipt.model_validate(parsed).model_dump(mode="json")
    except (TypeError, ValueError, ValidationError) as exc:
        raise DesktopDemoError("receipt_invalid") from exc
    resolved_home = _validated_demo_root(codex_home, label="codex_home")
    resolved_data = _validated_demo_root(data_dir, label="data_dir")
    _validate_receipt_scope(
        validated,
        codex_home=resolved_home,
        data_dir=resolved_data,
    )
    return validated


def transition_desktop_demo_receipt(
    receipt: dict[str, Any],
    *,
    target_state: str,
    occurred_at: str,
    config_sha256: str | None = None,
) -> dict[str, Any]:
    """Apply one forward-only write-ahead receipt transition."""

    try:
        current = _DesktopReceipt.model_validate(receipt).model_dump(mode="json")
    except ValidationError as exc:
        raise DesktopDemoError("receipt_invalid") from exc
    transitions = {
        "prepared": "installed",
        "installed": "removing",
        "removing": "removed",
    }
    if transitions.get(str(current["state"])) != target_state:
        raise DesktopDemoError("receipt_transition_invalid")
    try:
        _validate_time(occurred_at)
    except ValueError as exc:
        raise DesktopDemoError("receipt_transition_invalid") from exc
    if target_state in {"installed", "removed"} and not _is_sha(config_sha256):
        raise DesktopDemoError("receipt_transition_invalid")
    updated = dict(current)
    updated["state"] = target_state
    updated["updated_at"] = occurred_at
    teardown = dict(cast(dict[str, Any], updated["teardown"]))
    if target_state == "installed":
        updated["config_after_sha256"] = config_sha256
    elif target_state == "removing":
        teardown["requested_at"] = occurred_at
    else:
        teardown["completed_at"] = occurred_at
        teardown["config_after_teardown_sha256"] = config_sha256
    updated["teardown"] = teardown
    try:
        return _DesktopReceipt.model_validate(updated).model_dump(mode="json")
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
        "config_after_sha256": None,
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
            "receipt_version": RECEIPT_VERSION,
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
        source_raw, _ = _read_regular(source, MAX_FIXTURE_BYTES)
        if len(source_raw) != expected_size or _sha256_bytes(source_raw) != expected_digest:
            raise DesktopDemoError("fixture_source_drift")
        _atomic_write(target, source_raw, mode=0o600)
        digest, size = _hash_regular(target, MAX_FIXTURE_BYTES, private=True)
        if digest != expected_digest or size != expected_size:
            raise DesktopDemoError("staged_artifact_drift")
    except DesktopDemoError:
        raise
    except OSError as exc:
        raise DesktopDemoError("setup_interrupted") from exc


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    _atomic_write(path, _receipt_json(receipt), mode=0o600)


def _archive_removed_receipt(
    receipt_path: Path,
    receipt: dict[str, Any],
    *,
    data_dir: Path,
    expected_sha256: str,
) -> None:
    raw, _ = _read_regular(receipt_path, MAX_RECEIPT_BYTES, private=True)
    if _sha256_bytes(raw) != expected_sha256 or receipt["state"] != "removed":
        raise DesktopDemoError("removed_receipt_drift")
    history = data_dir / DEMO_DIRECTORY / "history"
    _private_directory(history)
    target = history / f"{receipt['installation_id']}.removed.json"
    if target.exists() or target.is_symlink():
        if target.is_symlink():
            raise DesktopDemoError("unsafe_receipt_history")
        existing, _ = _read_regular(target, MAX_RECEIPT_BYTES, private=True)
        if existing != raw:
            raise DesktopDemoError("unsafe_receipt_history")
        return
    _atomic_write(target, raw, mode=0o600)


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


def _setup_recovery(
    repository_root: Path,
    *,
    receipt: dict[str, Any],
    expected_preview_digest: str | None,
    codex_home: Path,
    data_dir: Path,
    normal_ready: bool,
) -> DesktopDemoResult:
    del repository_root
    config_path, receipt_path, staging_root = _paths(codex_home, data_dir)
    if not _receipt_managed_digest_valid(receipt):
        raise DesktopDemoError("receipt_invalid")
    if receipt["state"] != "prepared":
        raise DesktopDemoError("demo_already_installed")
    if expected_preview_digest != receipt["preview_digest"]:
        raise DesktopDemoError("preview_digest_mismatch")
    if not normal_ready:
        raise DesktopDemoError("normal_integration_not_ready")
    if not _normal_receipt_matches(receipt, data_dir):
        raise DesktopDemoError("normal_integration_drift")
    if not _runtimes_intact(receipt):
        raise DesktopDemoError("runtime_drift")
    if not _artifact_intact(receipt, data_dir):
        raise DesktopDemoError("staged_artifact_drift")
    document, raw_config = _load_config(config_path)
    managed = cast(dict[str, Any], receipt["managed_entry"])
    actual = _managed_from_document(document)
    if actual is None:
        if _sha256_bytes(raw_config) != receipt["config_before_sha256"]:
            raise DesktopDemoError("config_changed_after_preview")
        _set_managed(document, managed)
        try:
            _atomic_write(
                config_path,
                tomlkit.dumps(document).encode("utf-8"),
                mode=0o600,
                expected_sha256=_sha256_bytes(raw_config),
            )
        except DesktopDemoError:
            raise
        except Exception as exc:
            raise DesktopDemoError("setup_interrupted") from exc
    elif not _managed_matches(document, managed):
        raise DesktopDemoError("managed_entry_drift")
    artifacts = cast(list[dict[str, Any]], receipt["artifacts"])
    config_digest = _sha256_bytes(_load_config(config_path)[1])
    installed = transition_desktop_demo_receipt(
        receipt,
        target_state="installed",
        occurred_at=format_utc(),
        config_sha256=config_digest,
    )
    try:
        _write_receipt(receipt_path, installed)
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
    prior_removed_receipt_sha256: str | None = None
    if receipt_path.exists() or receipt_path.is_symlink():
        receipt = parse_desktop_demo_receipt(
            receipt_path,
            codex_home=resolved_home,
            data_dir=resolved_data,
        )
        if receipt["state"] != "removed":
            if confirmed:
                return _setup_recovery(
                    resolved_repository,
                    receipt=receipt,
                    expected_preview_digest=expected_preview_digest,
                    codex_home=resolved_home,
                    data_dir=resolved_data,
                    normal_ready=ready,
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
        removed_document, _ = _load_config(config_path)
        if _managed_from_document(removed_document) is not None:
            raise DesktopDemoError("removed_state_drift")
        artifacts_valid, artifacts_present = _artifact_removal_state(receipt, resolved_data)
        if not artifacts_valid or artifacts_present:
            raise DesktopDemoError("removed_state_drift")
        prior_raw, _ = _read_regular(receipt_path, MAX_RECEIPT_BYTES, private=True)
        prior_removed_receipt = receipt
        prior_removed_receipt_sha256 = _sha256_bytes(prior_raw)

    snapshot = _snapshot(
        resolved_repository,
        codex_home=resolved_home,
        data_dir=resolved_data,
        codex_executable=codex_executable,
        python_executable=python_executable,
        runner=runner,
        normal_ready=ready,
        prior_removed_receipt_sha256=prior_removed_receipt_sha256,
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

    demo_root = resolved_data / DEMO_DIRECTORY
    if staging_root.exists() and staging_root.is_symlink():
        raise DesktopDemoError("unsafe_staging")
    _private_directory(resolved_data)
    _private_directory(demo_root)
    if prior_removed_receipt is not None and prior_removed_receipt_sha256 is not None:
        _archive_removed_receipt(
            receipt_path,
            prior_removed_receipt,
            data_dir=resolved_data,
            expected_sha256=prior_removed_receipt_sha256,
        )
    _stage_fixture(
        source,
        staging_root / STAGED_SCRIPT_NAME,
        expected_digest=snapshot.fixture_sha256,
        expected_size=snapshot.fixture_size,
    )
    document, raw_config = _load_config(config_path)
    if _sha256_bytes(raw_config) != snapshot.config_sha256:
        raise DesktopDemoError("config_changed_after_preview")
    if _managed_from_document(document) is not None:
        raise DesktopDemoError("reserved_name_exists")
    receipt = _receipt_payload(
        snapshot,
        codex_home=resolved_home,
        data_dir=resolved_data,
        confirmed_at=format_utc(),
    )
    try:
        _write_receipt(receipt_path, receipt)
    except Exception as exc:
        raise DesktopDemoError("setup_interrupted") from exc
    _set_managed(document, snapshot.managed_entry)
    rendered = tomlkit.dumps(document).encode("utf-8")
    try:
        _atomic_write(
            config_path,
            rendered,
            mode=0o600,
            expected_sha256=snapshot.config_sha256,
        )
    except DesktopDemoError:
        raise
    except Exception as exc:
        raise DesktopDemoError("setup_interrupted") from exc
    verified_document, verified_raw = _load_config(config_path)
    if not _managed_matches(verified_document, snapshot.managed_entry):
        raise DesktopDemoError("setup_interrupted")
    installed = transition_desktop_demo_receipt(
        receipt,
        target_state="installed",
        occurred_at=format_utc(),
        config_sha256=_sha256_bytes(verified_raw),
    )
    try:
        _write_receipt(receipt_path, installed)
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
        document, _ = _load_config(config_path)
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
    receipt_path: Path,
    receipt: dict[str, Any],
    document: Any,
    raw_config: bytes,
    data_dir: Path,
) -> str:
    managed = cast(dict[str, Any], receipt["managed_entry"])
    actual_managed = _managed_from_document(document)
    artifacts_valid, artifacts_present = _artifact_removal_state(receipt, data_dir)
    payload = {
        "operation": "desktop_teardown",
        "receipt_sha256": _hash_regular(receipt_path, MAX_RECEIPT_BYTES, private=True)[0],
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
    receipt = parse_desktop_demo_receipt(
        receipt_path,
        codex_home=resolved_home,
        data_dir=resolved_data,
    )
    if not _receipt_managed_digest_valid(receipt):
        raise DesktopDemoError("receipt_invalid")
    if receipt["state"] not in {"installed", "removing"}:
        raise DesktopDemoError("desktop_demo_not_installed")
    document, raw_config = _load_config(config_path)
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
    preview_digest = _teardown_snapshot(
        receipt_path,
        receipt,
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
    if receipt["state"] == "installed":
        current = transition_desktop_demo_receipt(
            receipt,
            target_state="removing",
            occurred_at=format_utc(),
        )
        try:
            _write_receipt(receipt_path, current)
        except Exception as exc:
            raise DesktopDemoError("teardown_interrupted") from exc
    if managed_intact:
        original = cast(dict[str, Any], current["managed_entry_original"])
        _remove_managed(
            document,
            remove_empty_parent=not bool(original["parent_table_present"]),
        )
        try:
            _atomic_write(
                config_path,
                tomlkit.dumps(document).encode("utf-8"),
                mode=0o600,
                expected_sha256=_sha256_bytes(raw_config),
            )
        except DesktopDemoError:
            raise
        except Exception as exc:
            raise DesktopDemoError("teardown_interrupted") from exc
    artifacts = cast(list[dict[str, Any]], current["artifacts"])
    for artifact in artifacts:
        target = staging_root / str(artifact["relative_path"])
        if not target.exists() and not target.is_symlink():
            continue
        try:
            digest, size = _hash_regular(target, MAX_FIXTURE_BYTES, private=True)
        except DesktopDemoError as exc:
            raise DesktopDemoError("staged_artifact_drift") from exc
        if digest != artifact["sha256"] or size != artifact["size_bytes"]:
            raise DesktopDemoError("staged_artifact_drift")
        target.unlink()
    try:
        staging_root.rmdir()
    except OSError:
        # Unknown files are operator-owned and intentionally prevent removal.
        pass
    _, final_raw = _load_config(config_path)
    removed = transition_desktop_demo_receipt(
        current,
        target_state="removed",
        occurred_at=format_utc(),
        config_sha256=_sha256_bytes(final_raw),
    )
    try:
        _write_receipt(receipt_path, removed)
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
