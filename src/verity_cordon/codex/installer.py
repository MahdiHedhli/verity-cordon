"""Reviewable Codex configuration and local-plugin integration.

The installer changes only the five documented hook/memory controls. It stages
the public hook runtime in a local marketplace, records a restrictive receipt,
and leaves Codex's non-managed hook trust review to the operator.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol, cast

import tomlkit
from platformdirs import user_data_path

from verity_cordon.codex.hooks import SELECTED_EVENTS, WARNING, parse_one_object
from verity_cordon.core.errors import ConfigurationError
from verity_cordon.core.executable_trust import (
    recheck_trusted_executable,
    snapshot_trusted_directory,
    snapshot_trusted_executable,
)

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows remains an unverified target.
    _fcntl = None  # type: ignore[assignment]

PLUGIN_NAME: Final = "verity-cordon"
MARKETPLACE_NAME: Final = "verity-cordon-local"
RECEIPT_VERSION: Final = "2.0.0"
LEGACY_RECEIPT_VERSION: Final = "1.0.0"
RECEIPT_FILENAME: Final = "codex-integration-receipt.json"
MARKETPLACE_DIRECTORY: Final = "codex-marketplace"
MARKETPLACE_STAGING_DIRECTORY: Final = ".codex-marketplace.staged"
MARKETPLACE_RETIRED_DIRECTORY: Final = ".codex-marketplace.retired"
MARKETPLACE_REMOVAL_DIRECTORY: Final = ".codex-marketplace.removing"
OPERATION_LOCK_FILENAME: Final = "codex-integration-operation.lock"
INSTALL_PREVIEW_CONTRACT: Final = "VC-CODEX-INSTALL-PREVIEW-1"
MAX_CONFIG_BYTES: Final = 4_194_304
MAX_RECEIPT_BYTES: Final = 65_536
MAX_PLUGIN_FILE_BYTES: Final = 2_097_152
STAGED_PLUGIN_FILES: Final = frozenset(
    {
        ".codex-plugin/plugin.json",
        "hooks/hooks.json",
        "src/verity_cordon/codex/hooks.py",
    }
)
STAGED_MARKETPLACE_FILE: Final = ".agents/plugins/marketplace.json"
EMPTY_SHA256: Final = hashlib.sha256(b"").hexdigest()
COMMAND_KEYS: Final = (
    "marketplace_add",
    "plugin_refresh_remove",
    "plugin_add",
    "plugin_remove",
    "marketplace_remove",
)
INSTALL_STRATEGIES: Final = frozenset({"install", "refresh_plugin", "complete"})
_operation_thread_lock = threading.RLock()
_UNSET: Final = object()

REQUIRED_CONFIG: Final[tuple[tuple[str, str, bool], ...]] = (
    ("features", "hooks", True),
    ("features", "memories", False),
    ("memories", "generate_memories", False),
    ("memories", "use_memories", False),
    ("memories", "disable_on_external_context", True),
)


class CodexIntegrationError(Exception):
    """A content-safe Codex integration operation could not proceed."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: bytes = b""


class CommandRunner(Protocol):
    def __call__(
        self,
        argv: list[str],
        *,
        environment: dict[str, str],
        timeout: float,
    ) -> CommandResult: ...


@dataclass(frozen=True, slots=True)
class ConfigChange:
    dotted_key: str
    previous: bool | None
    previous_present: bool
    required: bool


@dataclass(frozen=True, slots=True)
class IntegrationResult:
    operation: str
    confirmed: bool
    applied: bool
    config_path: Path
    backup_path: Path | None
    marketplace_root: Path
    changes: tuple[ConfigChange, ...]
    commands: tuple[tuple[str, ...], ...]
    marketplace_registered: bool
    plugin_installed: bool
    issues: tuple[str, ...]
    operator_actions: tuple[str, ...]
    preview_digest: str | None = None
    artifacts: tuple[dict[str, Any], ...] = ()
    hook_manifest: dict[str, Any] | None = None
    hook_runtime: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class _MarketplacePlan:
    files: dict[str, bytes]
    artifacts: tuple[dict[str, Any], ...]
    hook_manifest: dict[str, Any]


@dataclass(frozen=True, slots=True)
class CodexDoctorReport:
    config_path: Path
    config_valid: bool
    required_config_active: bool
    effective_features_valid: bool
    marketplace_staged: bool
    staged_files_intact: bool
    plugin_installed: bool
    plugin_enabled: bool
    installed_cache_intact: bool
    hook_runtime_verified: bool
    receipt_present: bool
    mechanically_ready: bool
    trust_review_required: bool
    ready: bool
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _PluginState:
    installed: bool
    enabled: bool
    version: str | None
    source_path: Path | None


def _default_codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()


def _default_data_dir() -> Path:
    explicit = os.environ.get("VERITY_DATA_DIR")
    if explicit:
        return Path(explicit).expanduser()
    return user_data_path("verity-cordon", "Verity Cordon", ensure_exists=False)


def _validated_root(value: Path, *, label: str) -> Path:
    """Retain one absolute lexical root and validate every existing ancestor."""

    path = Path(value).expanduser()
    if not path.is_absolute() or "\x00" in os.fspath(path) or ".." in path.parts:
        raise CodexIntegrationError(f"unsafe_{label}")
    candidate = path
    try:
        if candidate.is_symlink():
            raise CodexIntegrationError(f"unsafe_{label}")
        while not candidate.exists():
            if candidate.is_symlink() or candidate.parent == candidate:
                raise CodexIntegrationError(f"unsafe_{label}")
            candidate = candidate.parent
        snapshot_trusted_directory(
            candidate,
            current_user_only=candidate == path,
            directory_label=label.replace("_", " "),
            ancestor_label=f"trusted {label.replace('_', ' ')}",
        )
    except CodexIntegrationError:
        raise
    except (ConfigurationError, OSError) as exc:
        raise CodexIntegrationError(f"unsafe_{label}") from exc
    return path


def _ensure_codex_home(path: Path) -> None:
    if not path.exists():
        path.mkdir(parents=True, mode=0o700)
    try:
        snapshot_trusted_directory(
            path,
            current_user_only=True,
            directory_label="Codex home",
            ancestor_label="trusted Codex home",
        )
    except (ConfigurationError, OSError) as exc:
        raise CodexIntegrationError("unsafe_codex_home") from exc


@contextmanager
def _operation_lock(data_dir: Path) -> Iterator[None]:
    """Serialize cooperating normal install and uninstall mutations."""

    with _operation_thread_lock:
        _ensure_private_directory(data_dir)
        path = data_dir / OPERATION_LOCK_FILENAME
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(path, flags, 0o600)
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                raise CodexIntegrationError("unsafe_integration_operation_lock")
            if os.name != "nt" and (
                details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077
            ):
                raise CodexIntegrationError("unsafe_integration_operation_lock")
            if _fcntl is not None:
                _fcntl.flock(descriptor, _fcntl.LOCK_EX)
        except CodexIntegrationError:
            raise
        except OSError as exc:
            raise CodexIntegrationError("integration_operation_lock_unavailable") from exc
        try:
            yield
        finally:
            if descriptor >= 0:
                if _fcntl is not None:
                    try:
                        _fcntl.flock(descriptor, _fcntl.LOCK_UN)
                    except OSError:
                        pass
                os.close(descriptor)


def _default_runner(
    argv: list[str],
    *,
    environment: dict[str, str],
    timeout: float,
) -> CommandResult:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv,
            check=False,
            capture_output=True,
            env=environment,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CodexIntegrationError("codex_command_unavailable") from exc
    output = completed.stdout[:1_048_576]
    return CommandResult(returncode=completed.returncode, stdout=output)


def _ensure_private_directory(path: Path) -> None:
    existed = path.exists() or path.is_symlink()
    if not existed:
        path.mkdir(parents=True, exist_ok=False, mode=0o700)
    try:
        if not existed:
            path.chmod(0o700)
        snapshot_trusted_directory(
            path,
            current_user_only=True,
            directory_label="integration directory",
            ancestor_label="integration directory",
        )
    except (ConfigurationError, OSError) as exc:
        raise CodexIntegrationError("unsafe_integration_directory") from exc


def _marketplace_paths(data_dir: Path) -> tuple[Path, Path, Path, Path]:
    return (
        data_dir / MARKETPLACE_DIRECTORY,
        data_dir / MARKETPLACE_STAGING_DIRECTORY,
        data_dir / MARKETPLACE_RETIRED_DIRECTORY,
        data_dir / MARKETPLACE_REMOVAL_DIRECTORY,
    )


def _validate_secure_tree(path: Path) -> None:
    """Reject every symlink, unsafe owner/mode, or special node in a tree."""

    try:
        snapshot_trusted_directory(
            path,
            current_user_only=True,
            directory_label="marketplace tree",
            ancestor_label="marketplace tree",
        )
        for root, directories, files in os.walk(path, topdown=True, followlinks=False):
            for name in [*directories, *files]:
                candidate = Path(root) / name
                details = candidate.lstat()
                if stat.S_ISLNK(details.st_mode) or not (
                    stat.S_ISDIR(details.st_mode) or stat.S_ISREG(details.st_mode)
                ):
                    raise CodexIntegrationError("unsafe_marketplace_tree")
                if os.name != "nt" and (
                    details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o022
                ):
                    raise CodexIntegrationError("unsafe_marketplace_tree")
    except CodexIntegrationError:
        raise
    except (ConfigurationError, OSError) as exc:
        raise CodexIntegrationError("unsafe_marketplace_tree") from exc


def _safe_remove_marketplace_tree(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    _validate_secure_tree(path)
    shutil.rmtree(path)


def _rename_marketplace_tree(source: Path, target: Path) -> None:
    if target.exists() or target.is_symlink():
        raise CodexIntegrationError("marketplace_recovery_collision")
    _validate_secure_tree(source)
    os.replace(source, target)


def _assert_regular_file(path: Path, *, private: bool = False) -> None:
    details = path.lstat()
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise CodexIntegrationError("unsafe_integration_file")
    if private and os.name != "nt":
        if details.st_mode & 0o077 or details.st_uid != os.geteuid():
            raise CodexIntegrationError("unsafe_integration_file_permissions")


def _read_bounded(
    path: Path,
    maximum: int,
    *,
    private: bool = False,
    security_critical: bool = False,
) -> bytes:
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        elif path.is_symlink():
            raise CodexIntegrationError("unsafe_integration_file")
        descriptor = os.open(path, flags)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise CodexIntegrationError("unsafe_integration_file")
        if private and os.name != "nt":
            if details.st_mode & 0o077 or details.st_uid != os.geteuid():
                raise CodexIntegrationError("unsafe_integration_file_permissions")
        if security_critical and os.name != "nt":
            if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o022:
                raise CodexIntegrationError("unsafe_integration_file_permissions")
        if details.st_size > maximum:
            raise CodexIntegrationError("integration_file_too_large")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            content = handle.read(maximum + 1)
        if len(content) > maximum:
            raise CodexIntegrationError("integration_file_too_large")
        return content
    except CodexIntegrationError:
        raise
    except OSError as exc:
        raise CodexIntegrationError("integration_file_unreadable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _atomic_write(
    path: Path,
    content: bytes,
    *,
    mode: int = 0o600,
    expected_sha256: str | None = None,
    expected_existed: bool | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise CodexIntegrationError("unsafe_integration_write_target")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if expected_sha256 is not None:
            current_exists = path.exists()
            if path.is_symlink() or (
                expected_existed is not None and current_exists != expected_existed
            ):
                raise CodexIntegrationError("codex_config_changed_during_operation")
            current = (
                _read_bounded(path, MAX_CONFIG_BYTES, security_critical=True)
                if current_exists
                else b""
            )
            if hashlib.sha256(current).hexdigest() != expected_sha256:
                raise CodexIntegrationError("codex_config_changed_during_operation")
        os.replace(temporary, path)
        if os.name != "nt":
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_descriptor = os.open(path.parent, directory_flags)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _load_config(path: Path) -> tuple[Any, bytes]:
    if not path.exists():
        if path.is_symlink():
            raise CodexIntegrationError("unsafe_codex_config")
        return tomlkit.document(), b""
    raw = _read_bounded(path, MAX_CONFIG_BYTES, security_critical=True)
    try:
        return tomlkit.parse(raw.decode("utf-8")), raw
    except (UnicodeError, tomlkit.exceptions.ParseError) as exc:
        raise CodexIntegrationError("codex_config_invalid") from exc


def _get_table(document: Any, section: str, *, create: bool) -> Any:
    table = document.get(section)
    if table is None:
        if not create:
            return None
        table = tomlkit.table()
        document[section] = table
    if not hasattr(table, "get") or not hasattr(table, "__setitem__"):
        raise CodexIntegrationError("codex_config_section_invalid")
    return table


def _config_changes(document: Any) -> tuple[ConfigChange, ...]:
    changes: list[ConfigChange] = []
    for section, key, required in REQUIRED_CONFIG:
        table = _get_table(document, section, create=False)
        present = table is not None and key in table
        previous = table.get(key) if present else None
        if present and not isinstance(previous, bool):
            raise CodexIntegrationError("codex_config_control_not_boolean")
        changes.append(
            ConfigChange(
                dotted_key=f"{section}.{key}",
                previous=cast(bool | None, previous),
                previous_present=present,
                required=required,
            )
        )
    return tuple(changes)


def _apply_required_config(document: Any) -> None:
    for section, key, required in REQUIRED_CONFIG:
        table = _get_table(document, section, create=True)
        table[key] = required


def _restore_config(document: Any, changes: tuple[ConfigChange, ...]) -> None:
    sections_present_before = {
        change.dotted_key.split(".", 1)[0] for change in changes if change.previous_present
    }
    for change in changes:
        section, key = change.dotted_key.split(".", 1)
        table = _get_table(document, section, create=change.previous_present)
        if change.previous_present:
            table[key] = change.previous
        elif table is not None and key in table:
            del table[key]
    for section in {item[0] for item in REQUIRED_CONFIG} - sections_present_before:
        table = document.get(section)
        if table is not None and len(table) == 0:
            del document[section]


def _backup(path: Path, raw: bytes, *, label: str) -> Path | None:
    if not raw:
        return None
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    for suffix in range(100):
        extra = "" if suffix == 0 else f"-{suffix}"
        target = path.with_name(f"{path.name}.verity-cordon-{label}-{timestamp}{extra}.bak")
        try:
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
        except FileExistsError:
            continue
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        return target
    raise CodexIntegrationError("codex_config_backup_collision")


def _sha256(path: Path) -> str:
    return hashlib.sha256(_read_bounded(path, 2_097_152)).hexdigest()


def _marketplace_document() -> dict[str, Any]:
    return {
        "name": MARKETPLACE_NAME,
        "interface": {"displayName": "Verity Cordon local integration"},
        "plugins": [
            {
                "name": PLUGIN_NAME,
                "source": {"source": "local", "path": f"./plugins/{PLUGIN_NAME}"},
                "policy": {
                    "installation": "AVAILABLE",
                    "authentication": "ON_INSTALL",
                },
                "category": "Developer Tools",
            }
        ],
    }


def _verified_hook_python() -> Path:
    interpreter = Path(sys.executable).resolve()
    try:
        _assert_regular_file(interpreter)
    except (OSError, CodexIntegrationError) as exc:
        raise CodexIntegrationError("hook_python_unavailable") from exc
    if not os.access(interpreter, os.X_OK) or '"' in str(interpreter):
        raise CodexIntegrationError("hook_python_unavailable")
    return interpreter


def _query_python_version(interpreter: Path) -> list[int]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"LANG", "LC_ALL", "SystemRoot", "WINDIR"}
    }
    environment.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_COLOR": "1"})
    try:
        completed = subprocess.run(  # noqa: S603 - verified absolute interpreter
            [
                str(interpreter),
                "-I",
                "-c",
                "import json,sys;print(json.dumps(list(sys.version_info[:3])))",
            ],
            check=False,
            capture_output=True,
            env=environment,
            timeout=3.0,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CodexIntegrationError("hook_python_unavailable") from exc
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 128:
        raise CodexIntegrationError("hook_python_unavailable")
    try:
        version = json.loads(completed.stdout.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CodexIntegrationError("hook_python_unavailable") from exc
    if (
        not isinstance(version, list)
        or len(version) != 3
        or any(not isinstance(item, int) or isinstance(item, bool) for item in version)
        or not (3, 12) <= tuple(version) < (4, 0)
    ):
        raise CodexIntegrationError("hook_python_unavailable")
    return cast(list[int], version)


def _hook_runtime_identity(interpreter: Path) -> dict[str, Any]:
    try:
        resolved, identity = snapshot_trusted_executable(
            interpreter,
            executable_label="hook Python executable",
            ancestor_label="hook Python executable",
        )
    except ConfigurationError as exc:
        raise CodexIntegrationError("hook_python_unavailable") from exc
    if resolved != interpreter:
        raise CodexIntegrationError("hook_python_unavailable")
    version = _query_python_version(resolved)
    if not recheck_trusted_executable(
        resolved,
        identity,
        executable_label="hook Python executable",
        ancestor_label="hook Python executable",
    ):
        raise CodexIntegrationError("hook_python_drift")
    return {
        "path": str(resolved),
        "sha256": identity.digest,
        "size_bytes": identity.target_chain[-1].size,
        "version": version,
    }


def _runtime_identity_matches(interpreter: Path, expected: dict[str, Any]) -> bool:
    """Verify digest and size before executing a receipt-bound interpreter."""

    try:
        resolved, identity = snapshot_trusted_executable(
            interpreter,
            executable_label="hook Python executable",
            ancestor_label="hook Python executable",
        )
        if (
            resolved != interpreter
            or expected.get("path") != str(resolved)
            or expected.get("sha256") != identity.digest
            or expected.get("size_bytes") != identity.target_chain[-1].size
        ):
            return False
        version = _query_python_version(resolved)
        return version == expected.get("version") and recheck_trusted_executable(
            resolved,
            identity,
            executable_label="hook Python executable",
            ancestor_label="hook Python executable",
        )
    except (ConfigurationError, OSError, CodexIntegrationError):
        return False


def _render_staged_hooks(source: bytes, interpreter: Path) -> bytes:
    try:
        document = parse_one_object(source, maximum_bytes=262_144)
        hooks = document.get("hooks")
        if not isinstance(hooks, dict) or set(hooks) != SELECTED_EVENTS:
            raise CodexIntegrationError("plugin_hooks_invalid")
        for event, groups in hooks.items():
            if not isinstance(groups, list):
                raise CodexIntegrationError("plugin_hooks_invalid")
            for group in groups:
                if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                    raise CodexIntegrationError("plugin_hooks_invalid")
                for handler in group["hooks"]:
                    if not isinstance(handler, dict) or handler.get("type") != "command":
                        raise CodexIntegrationError("plugin_hooks_invalid")
                    handler["command"] = (
                        f"{shlex.quote(str(interpreter))} "
                        '"$PLUGIN_ROOT/src/verity_cordon/codex/hooks.py" '
                        f"{event}"
                    )
                    windows_python = str(interpreter).replace("/", "\\")
                    handler["commandWindows"] = (
                        f'"{windows_python}" '
                        '"%PLUGIN_ROOT%\\src\\verity_cordon\\codex\\hooks.py" '
                        f"{event}"
                    )
    except CodexIntegrationError:
        raise
    except Exception as exc:
        raise CodexIntegrationError("plugin_hooks_invalid") from exc
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _marketplace_plan(plugin_root: Path, *, interpreter: Path) -> _MarketplacePlan:
    sources = {
        ".codex-plugin/plugin.json": plugin_root / ".codex-plugin" / "plugin.json",
        "hooks/hooks.json": plugin_root / "hooks" / "hooks.json",
        "src/verity_cordon/codex/hooks.py": (
            plugin_root / "src" / "verity_cordon" / "codex" / "hooks.py"
        ),
    }
    for source in sources.values():
        if not source.exists():
            raise CodexIntegrationError("plugin_source_incomplete")
        _assert_regular_file(source)

    files = {
        relative: (
            _render_staged_hooks(_read_bounded(source, 262_144), interpreter)
            if relative == "hooks/hooks.json"
            else _read_bounded(source, MAX_PLUGIN_FILE_BYTES)
        )
        for relative, source in sources.items()
    }
    files[STAGED_MARKETPLACE_FILE] = (
        json.dumps(_marketplace_document(), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    artifacts = tuple(
        {
            "relative_path": relative,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
        }
        for relative, content in sorted(files.items())
    )
    hook_manifest = parse_one_object(files["hooks/hooks.json"], maximum_bytes=262_144)
    return _MarketplacePlan(
        files=files,
        artifacts=artifacts,
        hook_manifest=hook_manifest,
    )


def _planned_target(root: Path, relative: str) -> Path:
    if relative == STAGED_MARKETPLACE_FILE:
        return root / relative
    return root / "plugins" / PLUGIN_NAME / relative


def _write_staging_tree(staging_root: Path, plan: _MarketplacePlan) -> None:
    expected = _planned_digests(plan)
    if staging_root.exists() or staging_root.is_symlink():
        if _marketplace_matches(staging_root, expected):
            return
        _safe_remove_marketplace_tree(staging_root)
    _ensure_private_directory(staging_root)
    try:
        parents = {_planned_target(staging_root, relative).parent for relative in plan.files}
        for parent in sorted(parents, key=lambda item: len(item.parts)):
            current = parent
            missing: list[Path] = []
            while current != staging_root and not current.exists():
                missing.append(current)
                current = current.parent
            for directory in reversed(missing):
                _ensure_private_directory(directory)
            if parent != staging_root:
                _ensure_private_directory(parent)
        for relative, content in plan.files.items():
            _atomic_write(_planned_target(staging_root, relative), content)
        if not _marketplace_matches(staging_root, expected):
            raise CodexIntegrationError("staged_plugin_drift")
    except BaseException:
        # The deterministic path is receipt-bound before this function runs.
        # Leave a safe partial tree for the next exact recovery attempt.
        if staging_root.exists() and not staging_root.is_symlink():
            _validate_secure_tree(staging_root)
        raise


def _converge_marketplace(
    *,
    marketplace_root: Path,
    staging_root: Path,
    retired_root: Path,
    removal_root: Path,
    plan: _MarketplacePlan,
    previous_digests: dict[str, str] | None,
) -> dict[str, str]:
    """Converge every deterministic executable tree to one active target."""

    target_digests = _planned_digests(plan)
    if removal_root.exists() or removal_root.is_symlink():
        raise CodexIntegrationError("marketplace_removal_recovery_required")

    active_target = _marketplace_matches(marketplace_root, target_digests)
    active_previous = previous_digests is not None and _marketplace_matches(
        marketplace_root, previous_digests
    )
    active_exists = marketplace_root.exists() or marketplace_root.is_symlink()
    retired_exists = retired_root.exists() or retired_root.is_symlink()
    retired_previous = previous_digests is not None and _marketplace_matches(
        retired_root, previous_digests
    )

    if retired_exists and not retired_previous:
        raise CodexIntegrationError("retired_marketplace_drift")
    if active_exists and not active_target and not active_previous:
        raise CodexIntegrationError("prepared_marketplace_drift")

    if active_target:
        if staging_root.exists() or staging_root.is_symlink():
            _safe_remove_marketplace_tree(staging_root)
        if retired_exists:
            _safe_remove_marketplace_tree(retired_root)
        return target_digests

    _write_staging_tree(staging_root, plan)
    if active_previous:
        if retired_exists:
            # A duplicate prior tree is never needed; retain only the active one
            # until the deterministic rename succeeds.
            _safe_remove_marketplace_tree(retired_root)
        _rename_marketplace_tree(marketplace_root, retired_root)
        retired_exists = True
    elif active_exists:
        raise CodexIntegrationError("prepared_marketplace_drift")
    elif previous_digests is not None and not retired_previous:
        raise CodexIntegrationError("previous_marketplace_missing")

    _rename_marketplace_tree(staging_root, marketplace_root)
    if not _marketplace_matches(marketplace_root, target_digests):
        raise CodexIntegrationError("staged_plugin_drift")
    if retired_exists or retired_root.exists() or retired_root.is_symlink():
        _safe_remove_marketplace_tree(retired_root)
    return target_digests


def _sweep_unreceipted_marketplace_paths(data_dir: Path) -> None:
    marketplace_root, staging_root, retired_root, removal_root = _marketplace_paths(data_dir)
    if marketplace_root.exists() or marketplace_root.is_symlink():
        raise CodexIntegrationError("unbound_existing_marketplace")
    for retained in (staging_root, retired_root, removal_root):
        _safe_remove_marketplace_tree(retained)


def _install_preview_digest(
    *,
    config_path: Path,
    raw_config: bytes,
    receipt_path: Path,
    marketplace_root: Path,
    changes: tuple[ConfigChange, ...],
    commands: tuple[tuple[str, ...], ...],
    hook_runtime: dict[str, Any],
    plan: _MarketplacePlan,
) -> str:
    payload = {
        "contract": INSTALL_PREVIEW_CONTRACT,
        "config_path": str(config_path),
        "config_existed": config_path.exists(),
        "config_sha256": hashlib.sha256(raw_config).hexdigest(),
        "receipt_sha256": _sha256(receipt_path) if receipt_path.exists() else None,
        "marketplace_root": str(marketplace_root),
        "required_config": [
            {
                "dotted_key": change.dotted_key,
                "previous_present": change.previous_present,
                "previous": change.previous,
                "required": change.required,
            }
            for change in changes
        ],
        "commands": [list(command) for command in commands],
        "hook_runtime": hook_runtime,
        "artifacts": list(plan.artifacts),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _receipt_payload(
    *,
    state: str,
    preview_digest: str,
    config_path: Path,
    config_existed_before: bool,
    config_before_sha256: str,
    config_after_sha256: str,
    backup_path: Path | None,
    backup_sha256: str | None,
    marketplace_root: Path,
    marketplace_staging_root: Path,
    marketplace_retired_root: Path,
    marketplace_removal_root: Path,
    changes: tuple[ConfigChange, ...],
    staged_digests: dict[str, str],
    previous_staged_digests: dict[str, str] | None,
    hook_runtime: dict[str, Any],
    install_strategy: str = "install",
    command_progress: dict[str, bool] | None = None,
) -> dict[str, Any]:
    if install_strategy not in INSTALL_STRATEGIES:
        raise CodexIntegrationError("integration_install_strategy_invalid")
    progress = (
        dict(command_progress)
        if command_progress is not None
        else {key: False for key in COMMAND_KEYS}
    )
    if set(progress) != set(COMMAND_KEYS) or not all(
        isinstance(value, bool) for value in progress.values()
    ):
        raise CodexIntegrationError("integration_command_progress_invalid")
    return {
        "schema_version": RECEIPT_VERSION,
        "state": state,
        "preview_digest": preview_digest,
        "config_path": str(config_path),
        "config_existed_before": config_existed_before,
        "config_before_sha256": config_before_sha256,
        "config_after_sha256": config_after_sha256,
        "backup_path": str(backup_path) if backup_path else None,
        "backup_sha256": backup_sha256,
        "marketplace_root": str(marketplace_root),
        "marketplace_staging_root": str(marketplace_staging_root),
        "marketplace_retired_root": str(marketplace_retired_root),
        "marketplace_removal_root": str(marketplace_removal_root),
        "required_config": [
            {
                "dotted_key": change.dotted_key,
                "previous_present": change.previous_present,
                "previous": change.previous,
                "required": change.required,
            }
            for change in changes
        ],
        "staged_digests": staged_digests,
        "previous_staged_digests": previous_staged_digests,
        "hook_runtime": hook_runtime,
        "install_strategy": install_strategy,
        "command_progress": progress,
        "uninstall": None,
    }


def _write_receipt(
    path: Path,
    payload: dict[str, Any],
    *,
    expected_sha256: str | None = None,
    expected_existed: bool | None = None,
) -> None:
    content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(
        path,
        content,
        expected_sha256=expected_sha256,
        expected_existed=expected_existed,
    )


def _read_receipt(path: Path) -> tuple[dict[str, Any], tuple[ConfigChange, ...]]:
    raw = _read_bounded(path, MAX_RECEIPT_BYTES, private=True)
    try:
        receipt = parse_one_object(raw, maximum_bytes=MAX_RECEIPT_BYTES)
    except Exception as exc:
        raise CodexIntegrationError("integration_receipt_invalid") from exc
    version = receipt.get("schema_version")
    if version not in {LEGACY_RECEIPT_VERSION, RECEIPT_VERSION}:
        raise CodexIntegrationError("integration_receipt_version_invalid")
    raw_changes = receipt.get("required_config")
    if not isinstance(raw_changes, list) or len(raw_changes) != len(REQUIRED_CONFIG):
        raise CodexIntegrationError("integration_receipt_invalid")
    changes: list[ConfigChange] = []
    expected_keys = {f"{section}.{key}" for section, key, _ in REQUIRED_CONFIG}
    required_values = {f"{section}.{key}": required for section, key, required in REQUIRED_CONFIG}
    for item in raw_changes:
        if not isinstance(item, dict) or set(item) != {
            "dotted_key",
            "previous_present",
            "previous",
            "required",
        }:
            raise CodexIntegrationError("integration_receipt_invalid")
        dotted = item.get("dotted_key")
        previous_present = item.get("previous_present")
        previous = item.get("previous")
        required = item.get("required")
        if (
            not isinstance(dotted, str)
            or dotted not in expected_keys
            or not isinstance(previous_present, bool)
            or (previous is not None and not isinstance(previous, bool))
            or not isinstance(required, bool)
            or required != required_values.get(dotted)
        ):
            raise CodexIntegrationError("integration_receipt_invalid")
        changes.append(ConfigChange(dotted, previous, previous_present, required))
    if {change.dotted_key for change in changes} != expected_keys:
        raise CodexIntegrationError("integration_receipt_invalid")
    if version == LEGACY_RECEIPT_VERSION:
        expected_receipt_keys = {
            "schema_version",
            "config_path",
            "backup_path",
            "marketplace_root",
            "required_config",
            "staged_digests",
            "hook_python",
            "hook_python_version",
        }
        if set(receipt) != expected_receipt_keys:
            raise CodexIntegrationError("integration_receipt_invalid")
        hook_python = receipt.get("hook_python")
        hook_version = receipt.get("hook_python_version")
        if (
            not isinstance(hook_python, str)
            or not Path(hook_python).is_absolute()
            or not isinstance(hook_version, list)
            or len(hook_version) != 3
            or any(not isinstance(item, int) or isinstance(item, bool) for item in hook_version)
        ):
            raise CodexIntegrationError("integration_receipt_invalid")
    else:
        expected_receipt_keys = {
            "schema_version",
            "state",
            "preview_digest",
            "config_path",
            "config_existed_before",
            "config_before_sha256",
            "config_after_sha256",
            "backup_path",
            "backup_sha256",
            "marketplace_root",
            "marketplace_staging_root",
            "marketplace_retired_root",
            "marketplace_removal_root",
            "required_config",
            "staged_digests",
            "previous_staged_digests",
            "hook_runtime",
            "install_strategy",
            "command_progress",
            "uninstall",
        }
        if set(receipt) != expected_receipt_keys:
            raise CodexIntegrationError("integration_receipt_invalid")
        if receipt.get("state") not in {
            "prepared",
            "installed",
            "uninstall_commands",
            "uninstall_config",
            "uninstall_tree",
            "uninstall_receipt",
        }:
            raise CodexIntegrationError("integration_receipt_invalid")
        if not _is_sha(receipt.get("preview_digest")):
            raise CodexIntegrationError("integration_receipt_invalid")
        if not isinstance(receipt.get("config_existed_before"), bool):
            raise CodexIntegrationError("integration_receipt_invalid")
        for key in ("config_before_sha256", "config_after_sha256"):
            if not _is_sha(receipt.get(key)):
                raise CodexIntegrationError("integration_receipt_invalid")
        backup_path = receipt.get("backup_path")
        backup_digest = receipt.get("backup_sha256")
        if (backup_path is None) != (backup_digest is None) or (
            backup_digest is not None and not _is_sha(backup_digest)
        ):
            raise CodexIntegrationError("integration_receipt_invalid")
        runtime = receipt.get("hook_runtime")
        if not _runtime_identity_shape(runtime):
            raise CodexIntegrationError("integration_receipt_invalid")
        previous = receipt.get("previous_staged_digests")
        if previous is not None and not _staged_digest_shape(previous):
            raise CodexIntegrationError("integration_receipt_invalid")
        if receipt["state"] != "prepared" and previous is not None:
            raise CodexIntegrationError("integration_receipt_invalid")
        progress = receipt.get("command_progress")
        if not (
            isinstance(progress, dict)
            and set(progress) == set(COMMAND_KEYS)
            and all(isinstance(value, bool) for value in progress.values())
        ):
            raise CodexIntegrationError("integration_receipt_invalid")
        install_strategy = receipt.get("install_strategy")
        if install_strategy not in INSTALL_STRATEGIES:
            raise CodexIntegrationError("integration_receipt_invalid")
        if progress["plugin_add"] and not progress["marketplace_add"]:
            raise CodexIntegrationError("integration_receipt_invalid")
        if install_strategy == "install" and progress["plugin_refresh_remove"]:
            raise CodexIntegrationError("integration_receipt_invalid")
        if install_strategy == "refresh_plugin" and (
            progress["plugin_add"] and not progress["plugin_refresh_remove"]
        ):
            raise CodexIntegrationError("integration_receipt_invalid")
        if install_strategy == "complete" and not (
            progress["marketplace_add"] and progress["plugin_add"]
        ):
            raise CodexIntegrationError("integration_receipt_invalid")
        uninstall = receipt.get("uninstall")
        if uninstall is not None and not _uninstall_metadata_shape(uninstall):
            raise CodexIntegrationError("integration_receipt_invalid")
        if receipt["state"] in {"prepared", "installed", "uninstall_commands"}:
            if uninstall is not None:
                raise CodexIntegrationError("integration_receipt_invalid")
        elif uninstall is None:
            raise CodexIntegrationError("integration_receipt_invalid")
    if not _staged_digest_shape(receipt.get("staged_digests")):
        raise CodexIntegrationError("integration_receipt_invalid")
    return receipt, tuple(changes)


def _is_sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _staged_digest_shape(value: object) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value) == {*STAGED_PLUGIN_FILES, STAGED_MARKETPLACE_FILE}
        and all(isinstance(key, str) and _is_sha(item) for key, item in value.items())
    )


def _runtime_identity_shape(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "path",
        "sha256",
        "size_bytes",
        "version",
    }:
        return False
    path = value.get("path")
    size = value.get("size_bytes")
    version = value.get("version")
    return bool(
        isinstance(path, str)
        and Path(path).is_absolute()
        and _is_sha(value.get("sha256"))
        and isinstance(size, int)
        and not isinstance(size, bool)
        and size > 0
        and isinstance(version, list)
        and len(version) == 3
        and all(isinstance(item, int) and not isinstance(item, bool) for item in version)
    )


def _uninstall_metadata_shape(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "config_existed_before",
        "config_before_sha256",
        "config_after_sha256",
        "backup_path",
        "backup_sha256",
    }:
        return False
    backup_path = value.get("backup_path")
    backup_sha = value.get("backup_sha256")
    return bool(
        isinstance(value.get("config_existed_before"), bool)
        and _is_sha(value.get("config_before_sha256"))
        and _is_sha(value.get("config_after_sha256"))
        and (backup_path is None or isinstance(backup_path, str))
        and (backup_path is None) == (backup_sha is None)
        and (backup_sha is None or _is_sha(backup_sha))
    )


def _receipt_state(receipt: dict[str, Any]) -> str:
    return (
        "installed"
        if receipt.get("schema_version") == LEGACY_RECEIPT_VERSION
        else cast(str, receipt["state"])
    )


def _codex_environment(codex_home: Path) -> dict[str, str]:
    safe_names = {
        "APPDATA",
        "ComSpec",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "LOGNAME",
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USER",
        "WINDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    }
    environment = {key: value for key, value in os.environ.items() if key in safe_names}
    environment["CODEX_HOME"] = str(codex_home)
    return environment


def _run_json_command(
    runner: CommandRunner,
    argv: list[str],
    *,
    codex_home: Path,
) -> bool:
    result = runner(argv, environment=_codex_environment(codex_home), timeout=20.0)
    if result.returncode != 0:
        return False
    if result.stdout:
        try:
            parse_one_object(result.stdout, maximum_bytes=1_048_576)
        except Exception:
            return False
    return True


def _commands(
    marketplace_root: Path,
    *,
    operation: str,
    install_strategy: str = "install",
) -> tuple[tuple[str, ...], ...]:
    if operation == "install":
        commands: list[tuple[str, ...]] = [
            ("codex", "plugin", "marketplace", "add", str(marketplace_root), "--json"),
        ]
        if install_strategy == "refresh_plugin":
            commands.append(
                (
                    "codex",
                    "plugin",
                    "remove",
                    f"{PLUGIN_NAME}@{MARKETPLACE_NAME}",
                    "--json",
                )
            )
        commands.append(("codex", "plugin", "add", f"{PLUGIN_NAME}@{MARKETPLACE_NAME}", "--json"))
        return tuple(commands)
    return (
        ("codex", "plugin", "remove", f"{PLUGIN_NAME}@{MARKETPLACE_NAME}", "--json"),
        ("codex", "plugin", "marketplace", "remove", MARKETPLACE_NAME, "--json"),
    )


def _receipt_scope(
    receipt: dict[str, Any],
    *,
    config_path: Path,
    data_dir: Path,
) -> tuple[Path, Path | None, Path | None]:
    recorded_config = receipt.get("config_path")
    recorded_marketplace = receipt.get("marketplace_root")
    recorded_backup = receipt.get("backup_path")
    (
        expected_marketplace,
        expected_staging,
        expected_retired,
        expected_removal,
    ) = _marketplace_paths(data_dir)
    if (
        not isinstance(recorded_config, str)
        or not Path(recorded_config).is_absolute()
        or Path(recorded_config) != config_path
        or not isinstance(recorded_marketplace, str)
        or not Path(recorded_marketplace).is_absolute()
        or Path(recorded_marketplace) != expected_marketplace
        or (recorded_backup is not None and not isinstance(recorded_backup, str))
    ):
        raise CodexIntegrationError("integration_receipt_scope_invalid")
    if receipt.get("schema_version") == RECEIPT_VERSION and (
        receipt.get("marketplace_staging_root") != str(expected_staging)
        or receipt.get("marketplace_retired_root") != str(expected_retired)
        or receipt.get("marketplace_removal_root") != str(expected_removal)
    ):
        raise CodexIntegrationError("integration_receipt_scope_invalid")
    backup_path = Path(recorded_backup) if recorded_backup else None
    if backup_path is not None:
        if (
            not backup_path.is_absolute()
            or backup_path.parent != config_path.parent
            or not backup_path.name.startswith(f"{config_path.name}.verity-cordon-")
        ):
            raise CodexIntegrationError("integration_receipt_scope_invalid")
        backup_raw = _read_bounded(backup_path, MAX_CONFIG_BYTES, private=True)
        expected_backup = receipt.get("backup_sha256")
        if receipt.get("schema_version") == RECEIPT_VERSION and (
            not _is_sha(expected_backup)
            or hashlib.sha256(backup_raw).hexdigest() != expected_backup
        ):
            raise CodexIntegrationError("integration_receipt_scope_invalid")
    uninstall = receipt.get("uninstall")
    if isinstance(uninstall, dict) and uninstall.get("backup_path") is not None:
        uninstall_backup = Path(cast(str, uninstall["backup_path"]))
        if (
            not uninstall_backup.is_absolute()
            or uninstall_backup.parent != config_path.parent
            or not uninstall_backup.name.startswith(f"{config_path.name}.verity-cordon-uninstall-")
        ):
            raise CodexIntegrationError("integration_receipt_scope_invalid")
        uninstall_raw = _read_bounded(uninstall_backup, MAX_CONFIG_BYTES, private=True)
        if hashlib.sha256(uninstall_raw).hexdigest() != uninstall.get("backup_sha256"):
            raise CodexIntegrationError("integration_receipt_scope_invalid")
    if receipt.get("schema_version") == RECEIPT_VERSION:
        runtime = cast(dict[str, Any], receipt["hook_runtime"])
        runtime_path = Path(cast(str, runtime["path"]))
    else:
        runtime_path = Path(cast(str, receipt["hook_python"]))
    return (
        expected_marketplace,
        backup_path,
        runtime_path,
    )


def _planned_digests(plan: _MarketplacePlan) -> dict[str, str]:
    return {str(item["relative_path"]): str(item["sha256"]) for item in plan.artifacts}


def _marketplace_matches(marketplace_root: Path, digests: dict[str, str]) -> bool:
    if marketplace_root.is_symlink() or not marketplace_root.is_dir():
        return False
    try:
        _validate_secure_tree(marketplace_root)
        expected_files = {
            _planned_target(marketplace_root, relative).relative_to(marketplace_root)
            for relative in digests
        }
        expected_directories: set[Path] = set()
        for relative in expected_files:
            expected_directories.update(
                parent for parent in relative.parents if parent != Path(".")
            )
        actual_files: set[Path] = set()
        actual_directories: set[Path] = set()
        for root, directories, files in os.walk(marketplace_root, topdown=True, followlinks=False):
            root_path = Path(root)
            actual_directories.update(
                (root_path / name).relative_to(marketplace_root) for name in directories
            )
            actual_files.update((root_path / name).relative_to(marketplace_root) for name in files)
        return (
            actual_files == expected_files
            and actual_directories == expected_directories
            and all(
                _sha256(_planned_target(marketplace_root, relative)) == expected
                for relative, expected in digests.items()
            )
        )
    except (OSError, CodexIntegrationError):
        return False


def _receipt_runtime_matches_current(receipt: dict[str, Any]) -> tuple[bool, Path | None]:
    if receipt.get("schema_version") != RECEIPT_VERSION:
        return False, None
    try:
        interpreter = _verified_hook_python()
        expected = cast(dict[str, Any], receipt["hook_runtime"])
        if Path(cast(str, expected["path"])) != interpreter:
            return False, None
        return _runtime_identity_matches(interpreter, expected), interpreter
    except (OSError, CodexIntegrationError):
        return False, None


def _installed_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    installed = dict(receipt)
    installed["state"] = "installed"
    installed["previous_staged_digests"] = None
    return installed


def _prior_registration_progress(receipt: dict[str, Any]) -> tuple[bool, bool]:
    if receipt.get("schema_version") == RECEIPT_VERSION:
        progress = cast(dict[str, bool], receipt["command_progress"])
        plugin_present = progress["plugin_add"] or (
            receipt["install_strategy"] == "refresh_plugin"
            and not progress["plugin_refresh_remove"]
        )
        return progress["marketplace_add"], plugin_present
    # Version 1 was written only after both documented registration commands.
    return True, True


def _planned_install_strategy(
    receipt: dict[str, Any] | None,
    planned_digests: dict[str, str],
) -> str:
    if receipt is None:
        return "install"
    if receipt.get("schema_version") == RECEIPT_VERSION and (
        _receipt_state(receipt) == "prepared" or receipt.get("staged_digests") == planned_digests
    ):
        return cast(str, receipt["install_strategy"])
    _, plugin_installed = _prior_registration_progress(receipt)
    return "refresh_plugin" if plugin_installed else "install"


def _prepared_command_progress(
    receipt: dict[str, Any] | None,
) -> dict[str, bool]:
    progress = {key: False for key in COMMAND_KEYS}
    if receipt is not None:
        marketplace_registered, _ = _prior_registration_progress(receipt)
        progress["marketplace_add"] = marketplace_registered
    return progress


def _transition_receipt(
    path: Path,
    receipt: dict[str, Any],
    *,
    state: str | None = None,
    command_succeeded: str | None = None,
    install_strategy: str | None = None,
    uninstall: object = _UNSET,
) -> dict[str, Any]:
    updated = dict(receipt)
    if state is not None:
        updated["state"] = state
    if command_succeeded is not None:
        if command_succeeded not in COMMAND_KEYS:
            raise CodexIntegrationError("integration_command_progress_invalid")
        progress = dict(cast(dict[str, bool], receipt["command_progress"]))
        progress[command_succeeded] = True
        updated["command_progress"] = progress
    if install_strategy is not None:
        if install_strategy not in INSTALL_STRATEGIES:
            raise CodexIntegrationError("integration_install_strategy_invalid")
        updated["install_strategy"] = install_strategy
    if uninstall is not _UNSET:
        updated["uninstall"] = uninstall
    expected = _sha256(path)
    _write_receipt(
        path,
        updated,
        expected_sha256=expected,
        expected_existed=True,
    )
    return updated


def _run_install_commands(
    *,
    runner: CommandRunner,
    commands: tuple[tuple[str, ...], ...],
    codex_home: Path,
    receipt_path: Path,
    receipt: dict[str, Any],
    run_codex_commands: bool,
) -> tuple[bool, bool, tuple[str, ...], dict[str, Any]]:
    issues: list[str] = []
    progress = cast(dict[str, bool], receipt["command_progress"])
    install_strategy = cast(str, receipt["install_strategy"])
    refresh_plugin = install_strategy == "refresh_plugin"
    marketplace_registered = progress["marketplace_add"]
    plugin_installed = progress["plugin_add"]
    if run_codex_commands:
        if not marketplace_registered:
            marketplace_registered = _run_json_command(
                runner,
                list(commands[0]),
                codex_home=codex_home,
            )
            if marketplace_registered:
                receipt = _transition_receipt(
                    receipt_path,
                    receipt,
                    command_succeeded="marketplace_add",
                )
        refresh_ready = not refresh_plugin
        if marketplace_registered:
            if refresh_plugin:
                progress = cast(dict[str, bool], receipt["command_progress"])
                refresh_ready = progress["plugin_refresh_remove"]
                if not refresh_ready:
                    refresh_ready = _run_json_command(
                        runner,
                        list(commands[1]),
                        codex_home=codex_home,
                    )
                    if refresh_ready:
                        receipt = _transition_receipt(
                            receipt_path,
                            receipt,
                            command_succeeded="plugin_refresh_remove",
                        )
                    else:
                        issues.append("plugin_refresh_remove_failed")
            if refresh_ready and not plugin_installed:
                add_index = 2 if refresh_plugin else 1
                plugin_installed = _run_json_command(
                    runner,
                    list(commands[add_index]),
                    codex_home=codex_home,
                )
                if plugin_installed:
                    receipt = _transition_receipt(
                        receipt_path,
                        receipt,
                        command_succeeded="plugin_add",
                    )
        else:
            issues.append("marketplace_registration_failed")
        if marketplace_registered and refresh_ready and not plugin_installed:
            issues.append("plugin_install_failed")
    else:
        issues.append("codex_commands_require_operator_execution")
    return marketplace_registered, plugin_installed, tuple(issues), receipt


def _config_head_matches(
    path: Path,
    *,
    expected_sha256: str,
    expected_existed: bool,
) -> bool:
    if path.is_symlink() or path.exists() != expected_existed:
        return False
    try:
        current = (
            _read_bounded(path, MAX_CONFIG_BYTES, security_critical=True)
            if expected_existed
            else b""
        )
    except CodexIntegrationError:
        return False
    return hashlib.sha256(current).hexdigest() == expected_sha256


def _backup_digest(path: Path | None) -> str | None:
    if path is None:
        return None
    return hashlib.sha256(_read_bounded(path, MAX_CONFIG_BYTES, private=True)).hexdigest()


def _cleanup_unbound_backup(path: Path, expected_sha256: str) -> None:
    current = hashlib.sha256(_read_bounded(path, MAX_CONFIG_BYTES, private=True)).hexdigest()
    if current != expected_sha256:
        raise CodexIntegrationError("unbound_backup_drift")
    try:
        path.unlink()
    except OSError as exc:
        raise CodexIntegrationError("unbound_backup_cleanup_failed") from exc


def install_codex(
    plugin_root: Path,
    *,
    confirmed: bool = False,
    expected_preview_digest: str | None = None,
    codex_home: Path | None = None,
    data_dir: Path | None = None,
    run_codex_commands: bool = True,
    runner: CommandRunner = _default_runner,
    _lock_acquired: bool = False,
) -> IntegrationResult:
    """Preview or digest-confirm the documented local Codex integration."""

    resolved_home = _validated_root(
        codex_home if codex_home is not None else _default_codex_home(),
        label="codex_home",
    )
    resolved_data = _validated_root(
        data_dir if data_dir is not None else _default_data_dir(),
        label="verity_data_dir",
    )
    config_path = resolved_home / "config.toml"
    (
        marketplace_root,
        staging_root,
        retired_root,
        removal_root,
    ) = _marketplace_paths(resolved_data)
    document, raw_config = _load_config(config_path)
    config_existed = config_path.exists()
    changes = _config_changes(document)
    receipt_path = resolved_data / RECEIPT_FILENAME
    existing_backup: Path | None = None
    receipt: dict[str, Any] | None = None
    receipt_exists = receipt_path.exists() or receipt_path.is_symlink()
    if receipt_exists:
        receipt, original_changes = _read_receipt(receipt_path)
        marketplace_root, existing_backup, _ = _receipt_scope(
            receipt,
            config_path=config_path,
            data_dir=resolved_data,
        )
        changes = original_changes
        receipt_state = _receipt_state(receipt)
        if receipt_state == "installed":
            if not _required_config_matches(document) and not _original_config_matches(
                document, changes
            ):
                raise CodexIntegrationError("codex_config_drift_requires_review")
            if not _marketplace_matches(
                marketplace_root,
                cast(dict[str, str], receipt["staged_digests"]),
            ):
                raise CodexIntegrationError("staged_plugin_drift")
        elif receipt_state == "prepared":
            raw_digest = hashlib.sha256(raw_config).hexdigest()
            before = cast(str, receipt["config_before_sha256"])
            after = cast(str, receipt["config_after_sha256"])
            before_matches = (
                raw_digest == before
                and config_path.exists() is receipt["config_existed_before"]
                and _original_config_matches(document, changes)
            )
            after_matches = raw_digest == after and _required_config_matches(document)
            if not before_matches and not after_matches:
                raise CodexIntegrationError("codex_config_drift_requires_review")
        else:
            raise CodexIntegrationError("integration_uninstall_recovery_required")
    hook_python = _verified_hook_python()
    hook_runtime = _hook_runtime_identity(hook_python)
    plan = _marketplace_plan(plugin_root.resolve(), interpreter=hook_python)
    planned_digests = _planned_digests(plan)
    install_strategy = _planned_install_strategy(receipt, planned_digests)
    commands = _commands(
        marketplace_root,
        operation="install",
        install_strategy=install_strategy,
    )
    if receipt is not None and _receipt_state(receipt) == "prepared":
        if (
            receipt.get("schema_version") != RECEIPT_VERSION
            or receipt["staged_digests"] != planned_digests
            or receipt["hook_runtime"] != hook_runtime
        ):
            raise CodexIntegrationError("prepared_install_inputs_drift")
        preview_digest = cast(str, receipt["preview_digest"])
    else:
        preview_digest = _install_preview_digest(
            config_path=config_path,
            raw_config=raw_config,
            receipt_path=receipt_path,
            marketplace_root=marketplace_root,
            changes=changes,
            commands=commands,
            hook_runtime=hook_runtime,
            plan=plan,
        )
    actions = (
        "Review the exact rendered hook manifest, per-artifact SHA-256 values, and "
        "hook-runtime path/SHA-256/version in this preview, then retain its "
        "preview_digest for confirmed installation.",
        "Before confirmed installation, close every ChatGPT Desktop task, exit "
        "all Codex CLI TUI and IDE Codex sessions, and fully quit the ChatGPT "
        "desktop app.",
        "Apply only with the exact separately reviewed preview_digest.",
        "After installation, start Codex CLI, use /hooks to review the installed "
        "Verity hook definitions, trust their exact current hashes, then exit the CLI.",
        "Start the Verity daemon, then run the Codex integration doctor with "
        "--confirm-hook-trust after the /hooks review.",
        "Restart Codex and verify the integration in a new task only after the "
        "daemon and doctor are ready.",
    )
    if not confirmed:
        return IntegrationResult(
            "install",
            False,
            False,
            config_path,
            None,
            marketplace_root,
            changes,
            commands,
            False,
            False,
            (),
            actions,
            preview_digest,
            plan.artifacts,
            plan.hook_manifest,
            hook_runtime,
        )

    if not expected_preview_digest or not re.fullmatch(r"[0-9a-f]{64}", expected_preview_digest):
        raise CodexIntegrationError("install_preview_digest_required")
    if expected_preview_digest != preview_digest:
        raise CodexIntegrationError("install_preview_digest_mismatch")
    if not _lock_acquired:
        with _operation_lock(resolved_data):
            return install_codex(
                plugin_root,
                confirmed=True,
                expected_preview_digest=expected_preview_digest,
                codex_home=resolved_home,
                data_dir=resolved_data,
                run_codex_commands=run_codex_commands,
                runner=runner,
                _lock_acquired=True,
            )

    _ensure_codex_home(resolved_home)
    receipt_head_sha = _sha256(receipt_path) if receipt is not None else EMPTY_SHA256
    config_existed = config_path.exists()
    config_before_sha = hashlib.sha256(raw_config).hexdigest()
    rendered = raw_config
    config_after_sha = config_before_sha
    resume_commands_only = bool(
        receipt is not None
        and receipt.get("schema_version") == RECEIPT_VERSION
        and _receipt_state(receipt) == "installed"
        and receipt.get("staged_digests") == planned_digests
        and receipt.get("hook_runtime") == hook_runtime
        and _required_config_matches(document)
        and _marketplace_matches(marketplace_root, planned_digests)
        and not any(
            path.exists() or path.is_symlink()
            for path in (staging_root, retired_root, removal_root)
        )
    )

    if resume_commands_only:
        backup_path = existing_backup
    elif receipt is not None and _receipt_state(receipt) == "prepared":
        prepared = receipt
        previous = cast(dict[str, str] | None, prepared["previous_staged_digests"])
        _converge_marketplace(
            marketplace_root=marketplace_root,
            staging_root=staging_root,
            retired_root=retired_root,
            removal_root=removal_root,
            plan=plan,
            previous_digests=previous,
        )

        raw_digest = hashlib.sha256(raw_config).hexdigest()
        before_matches = (
            raw_digest == prepared["config_before_sha256"]
            and config_path.exists() is prepared["config_existed_before"]
            and _original_config_matches(document, changes)
        )
        after_matches = raw_digest == prepared["config_after_sha256"] and _required_config_matches(
            document
        )
        if before_matches:
            recovery_document, _ = _load_config(config_path)
            _apply_required_config(recovery_document)
            recovery_rendered = tomlkit.dumps(recovery_document).encode("utf-8")
            if hashlib.sha256(recovery_rendered).hexdigest() != prepared["config_after_sha256"]:
                raise CodexIntegrationError("prepared_install_inputs_drift")
            _atomic_write(
                config_path,
                recovery_rendered,
                expected_sha256=cast(str, prepared["config_before_sha256"]),
                expected_existed=cast(bool, prepared["config_existed_before"]),
            )
        elif not after_matches:
            raise CodexIntegrationError("codex_config_drift_requires_review")
        if not _marketplace_matches(marketplace_root, planned_digests) or not _config_head_matches(
            config_path,
            expected_sha256=cast(str, prepared["config_after_sha256"]),
            expected_existed=True,
        ):
            raise CodexIntegrationError("install_recovery_verification_failed")
        _write_receipt(
            receipt_path,
            _installed_receipt(prepared),
            expected_sha256=receipt_head_sha,
            expected_existed=True,
        )
        backup_path = existing_backup
        receipt = _installed_receipt(prepared)
    else:
        if not _required_config_matches(document):
            _apply_required_config(document)
            rendered = tomlkit.dumps(document).encode("utf-8")
        config_after_sha = hashlib.sha256(rendered).hexdigest()
        previous_digests = (
            cast(dict[str, str], receipt["staged_digests"]) if receipt is not None else None
        )
        backup_path = existing_backup
        if receipt is None:
            _sweep_unreceipted_marketplace_paths(resolved_data)
            backup_path = _backup(config_path, raw_config, label="install")
        prepared = _receipt_payload(
            state="prepared",
            preview_digest=preview_digest,
            config_path=config_path,
            config_existed_before=config_existed,
            config_before_sha256=config_before_sha,
            config_after_sha256=config_after_sha,
            backup_path=backup_path,
            backup_sha256=_backup_digest(backup_path),
            marketplace_root=marketplace_root,
            marketplace_staging_root=staging_root,
            marketplace_retired_root=retired_root,
            marketplace_removal_root=removal_root,
            changes=changes,
            staged_digests=planned_digests,
            previous_staged_digests=previous_digests,
            hook_runtime=hook_runtime,
            install_strategy=install_strategy,
            command_progress=_prepared_command_progress(receipt),
        )
        # The prepared receipt binds both the old and new marketplace states
        # before staging can replace any executable artifact.
        created_backup = receipt is None and backup_path is not None
        try:
            _write_receipt(
                receipt_path,
                prepared,
                expected_sha256=receipt_head_sha,
                expected_existed=receipt is not None,
            )
        except BaseException:
            bound = False
            try:
                observed, _ = _read_receipt(receipt_path)
                bound = observed == prepared
            except (OSError, CodexIntegrationError):
                pass
            if created_backup and not bound and backup_path is not None:
                digest = cast(str, prepared["backup_sha256"])
                _cleanup_unbound_backup(backup_path, digest)
            raise
        prepared_receipt_sha = _sha256(receipt_path)
        _converge_marketplace(
            marketplace_root=marketplace_root,
            staging_root=staging_root,
            retired_root=retired_root,
            removal_root=removal_root,
            plan=plan,
            previous_digests=previous_digests,
        )
        if rendered != raw_config:
            _atomic_write(
                config_path,
                rendered,
                expected_sha256=config_before_sha,
                expected_existed=config_existed,
            )
        elif not _config_head_matches(
            config_path,
            expected_sha256=config_before_sha,
            expected_existed=config_existed,
        ):
            raise CodexIntegrationError("codex_config_changed_during_operation")
        if not _marketplace_matches(marketplace_root, planned_digests) or not _config_head_matches(
            config_path,
            expected_sha256=config_after_sha,
            expected_existed=True,
        ):
            raise CodexIntegrationError("install_verification_failed")
        _write_receipt(
            receipt_path,
            _installed_receipt(prepared),
            expected_sha256=prepared_receipt_sha,
            expected_existed=True,
        )
        receipt = _installed_receipt(prepared)

    if receipt is None:  # pragma: no cover - guarded by both convergence branches.
        raise CodexIntegrationError("integration_receipt_missing")
    marketplace_registered, plugin_installed, issues, receipt = _run_install_commands(
        runner=runner,
        commands=commands,
        codex_home=resolved_home,
        receipt_path=receipt_path,
        receipt=receipt,
        run_codex_commands=run_codex_commands,
    )
    if marketplace_registered and plugin_installed and receipt["install_strategy"] != "complete":
        receipt = _transition_receipt(
            receipt_path,
            receipt,
            install_strategy="complete",
        )

    return IntegrationResult(
        "install",
        True,
        True,
        config_path,
        backup_path,
        marketplace_root,
        changes,
        commands,
        marketplace_registered,
        plugin_installed,
        issues,
        actions,
        preview_digest,
        plan.artifacts,
        plan.hook_manifest,
        hook_runtime,
    )


def _required_config_matches(document: Any) -> bool:
    for section, key, required in REQUIRED_CONFIG:
        table = _get_table(document, section, create=False)
        if table is None or table.get(key) is not required:
            return False
    return True


def _original_config_matches(document: Any, changes: tuple[ConfigChange, ...]) -> bool:
    for change in changes:
        section, key = change.dotted_key.split(".", 1)
        table = _get_table(document, section, create=False)
        present = table is not None and key in table
        if present != change.previous_present:
            return False
        if present and table.get(key) is not change.previous:
            return False
    return True


def _run_uninstall_commands(
    *,
    runner: CommandRunner,
    commands: tuple[tuple[str, ...], ...],
    codex_home: Path,
    receipt_path: Path,
    receipt: dict[str, Any],
    run_codex_commands: bool,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    progress = cast(dict[str, bool], receipt["command_progress"])
    plugin_present = progress["plugin_add"] or (
        receipt["install_strategy"] == "refresh_plugin" and not progress["plugin_refresh_remove"]
    )
    if not progress["plugin_remove"]:
        if not plugin_present:
            receipt = _transition_receipt(receipt_path, receipt, command_succeeded="plugin_remove")
        elif not run_codex_commands:
            return receipt, ("remove_plugin_before_restoring_config",)
        elif _run_json_command(runner, list(commands[0]), codex_home=codex_home):
            receipt = _transition_receipt(receipt_path, receipt, command_succeeded="plugin_remove")
        else:
            return receipt, ("plugin_remove_failed",)
    progress = cast(dict[str, bool], receipt["command_progress"])
    if not progress["marketplace_remove"]:
        if not progress["marketplace_add"]:
            receipt = _transition_receipt(
                receipt_path, receipt, command_succeeded="marketplace_remove"
            )
        elif not run_codex_commands:
            return receipt, ("remove_marketplace_before_restoring_config",)
        elif _run_json_command(runner, list(commands[1]), codex_home=codex_home):
            receipt = _transition_receipt(
                receipt_path, receipt, command_succeeded="marketplace_remove"
            )
        else:
            return receipt, ("marketplace_remove_failed",)
    return receipt, ()


def _uninstall_config_position(
    *,
    receipt: dict[str, Any],
    document: Any,
    raw_config: bytes,
    config_exists: bool,
    changes: tuple[ConfigChange, ...],
) -> str | None:
    uninstall = cast(dict[str, Any], receipt["uninstall"])
    digest = hashlib.sha256(raw_config).hexdigest()
    if (
        digest == uninstall["config_before_sha256"]
        and config_exists is uninstall["config_existed_before"]
        and _required_config_matches(document)
    ):
        return "before"
    if digest == uninstall["config_after_sha256"] and _original_config_matches(document, changes):
        return "after"
    return None


def _unlink_receipt(path: Path, *, expected_sha256: str) -> None:
    if _sha256(path) != expected_sha256:
        raise CodexIntegrationError("integration_receipt_changed_during_operation")
    try:
        path.unlink()
    except OSError as exc:
        raise CodexIntegrationError("integration_receipt_cleanup_failed") from exc


def uninstall_codex(
    *,
    confirmed: bool = False,
    codex_home: Path | None = None,
    data_dir: Path | None = None,
    run_codex_commands: bool = True,
    runner: CommandRunner = _default_runner,
    _lock_acquired: bool = False,
) -> IntegrationResult:
    """Journal removal and resume each destructive phase from exact state."""

    resolved_home = _validated_root(
        codex_home if codex_home is not None else _default_codex_home(),
        label="codex_home",
    )
    resolved_data = _validated_root(
        data_dir if data_dir is not None else _default_data_dir(),
        label="verity_data_dir",
    )
    config_path = resolved_home / "config.toml"
    receipt_path = resolved_data / RECEIPT_FILENAME
    if not receipt_path.exists() and not receipt_path.is_symlink():
        raise CodexIntegrationError("integration_receipt_missing")
    receipt, changes = _read_receipt(receipt_path)
    state = _receipt_state(receipt)
    if state == "prepared":
        raise CodexIntegrationError("integration_install_recovery_required")
    marketplace_root, existing_backup, _ = _receipt_scope(
        receipt,
        config_path=config_path,
        data_dir=resolved_data,
    )
    (
        _,
        staging_root,
        retired_root,
        removal_root,
    ) = _marketplace_paths(resolved_data)
    target_digests = cast(dict[str, str], receipt["staged_digests"])
    active_exists = marketplace_root.exists() or marketplace_root.is_symlink()
    removal_exists = removal_root.exists() or removal_root.is_symlink()
    if state in {"installed", "uninstall_commands", "uninstall_config"}:
        if not _marketplace_matches(marketplace_root, target_digests):
            raise CodexIntegrationError("staged_plugin_drift")
        if removal_exists:
            raise CodexIntegrationError("marketplace_recovery_collision")
    elif state == "uninstall_tree":
        if active_exists and not _marketplace_matches(marketplace_root, target_digests):
            raise CodexIntegrationError("staged_plugin_drift")
        if active_exists and removal_exists:
            raise CodexIntegrationError("marketplace_recovery_collision")
        if removal_exists and not _marketplace_matches(removal_root, target_digests):
            raise CodexIntegrationError("removal_marketplace_drift")
    elif state == "uninstall_receipt":
        if any(
            path.exists() or path.is_symlink()
            for path in (marketplace_root, staging_root, retired_root, removal_root)
        ):
            raise CodexIntegrationError("marketplace_cleanup_incomplete")
    commands = _commands(marketplace_root, operation="uninstall")
    actions = (
        "Before confirmed removal, close every ChatGPT Desktop task, exit all "
        "Codex CLI TUI and IDE Codex sessions, and fully quit the ChatGPT desktop app.",
        "Restart Codex after removal.",
        "Review native-memory settings before re-enabling any Codex memory behavior.",
    )
    if not confirmed:
        return IntegrationResult(
            "uninstall",
            False,
            False,
            config_path,
            None,
            marketplace_root,
            changes,
            commands,
            False,
            False,
            (),
            actions,
        )
    if not _lock_acquired:
        with _operation_lock(resolved_data):
            return uninstall_codex(
                confirmed=True,
                codex_home=resolved_home,
                data_dir=resolved_data,
                run_codex_commands=run_codex_commands,
                runner=runner,
                _lock_acquired=True,
            )

    document, raw_config = _load_config(config_path)
    config_existed = config_path.exists()
    if state in {"installed", "uninstall_commands"} and not _required_config_matches(document):
        return IntegrationResult(
            "uninstall",
            True,
            False,
            config_path,
            None,
            marketplace_root,
            changes,
            commands,
            False,
            True,
            ("codex_config_drift_requires_review",),
            actions,
        )
    if receipt.get("schema_version") == LEGACY_RECEIPT_VERSION:
        runtime = _hook_runtime_identity(_verified_hook_python())
        upgraded = _receipt_payload(
            state="installed",
            preview_digest=_sha256(receipt_path),
            config_path=config_path,
            config_existed_before=config_existed,
            config_before_sha256=hashlib.sha256(raw_config).hexdigest(),
            config_after_sha256=hashlib.sha256(raw_config).hexdigest(),
            backup_path=existing_backup,
            backup_sha256=_backup_digest(existing_backup),
            marketplace_root=marketplace_root,
            marketplace_staging_root=staging_root,
            marketplace_retired_root=retired_root,
            marketplace_removal_root=removal_root,
            changes=changes,
            staged_digests=target_digests,
            previous_staged_digests=None,
            hook_runtime=runtime,
        )
        progress = cast(dict[str, bool], upgraded["command_progress"])
        progress["marketplace_add"] = True
        progress["plugin_add"] = True
        upgraded["install_strategy"] = "complete"
        _write_receipt(
            receipt_path,
            upgraded,
            expected_sha256=_sha256(receipt_path),
            expected_existed=True,
        )
        receipt = upgraded
        state = "installed"

    if state == "installed":
        receipt = _transition_receipt(receipt_path, receipt, state="uninstall_commands")
        state = "uninstall_commands"

    if state == "uninstall_commands":
        receipt, command_issues = _run_uninstall_commands(
            runner=runner,
            commands=commands,
            codex_home=resolved_home,
            receipt_path=receipt_path,
            receipt=receipt,
            run_codex_commands=run_codex_commands,
        )
        if command_issues:
            return IntegrationResult(
                "uninstall",
                True,
                False,
                config_path,
                None,
                marketplace_root,
                changes,
                commands,
                False,
                False,
                command_issues,
                actions,
            )
        document, raw_config = _load_config(config_path)
        config_existed = config_path.exists()
        if not _required_config_matches(document):
            return IntegrationResult(
                "uninstall",
                True,
                False,
                config_path,
                None,
                marketplace_root,
                changes,
                commands,
                False,
                False,
                ("codex_config_drift_requires_review",),
                actions,
            )
        restored = tomlkit.parse(raw_config.decode("utf-8")) if raw_config else tomlkit.document()
        _restore_config(restored, changes)
        restored_bytes = tomlkit.dumps(restored).encode("utf-8")
        uninstall_backup = _backup(config_path, raw_config, label="uninstall")
        uninstall_metadata = {
            "config_existed_before": config_existed,
            "config_before_sha256": hashlib.sha256(raw_config).hexdigest(),
            "config_after_sha256": hashlib.sha256(restored_bytes).hexdigest(),
            "backup_path": str(uninstall_backup) if uninstall_backup else None,
            "backup_sha256": _backup_digest(uninstall_backup),
        }
        try:
            receipt = _transition_receipt(
                receipt_path,
                receipt,
                state="uninstall_config",
                uninstall=uninstall_metadata,
            )
        except BaseException:
            bound = False
            try:
                observed, _ = _read_receipt(receipt_path)
                bound = observed.get("uninstall") == uninstall_metadata
            except (OSError, CodexIntegrationError):
                pass
            if not bound and uninstall_backup is not None:
                _cleanup_unbound_backup(
                    uninstall_backup,
                    cast(str, uninstall_metadata["backup_sha256"]),
                )
            raise
        state = "uninstall_config"

    if state == "uninstall_config":
        document, raw_config = _load_config(config_path)
        position = _uninstall_config_position(
            receipt=receipt,
            document=document,
            raw_config=raw_config,
            config_exists=config_path.exists(),
            changes=changes,
        )
        uninstall_metadata = cast(dict[str, Any], receipt["uninstall"])
        if position == "before":
            _restore_config(document, changes)
            restored_bytes = tomlkit.dumps(document).encode("utf-8")
            if (
                hashlib.sha256(restored_bytes).hexdigest()
                != uninstall_metadata["config_after_sha256"]
            ):
                raise CodexIntegrationError("uninstall_config_render_drift")
            _atomic_write(
                config_path,
                restored_bytes,
                expected_sha256=cast(str, uninstall_metadata["config_before_sha256"]),
                expected_existed=cast(bool, uninstall_metadata["config_existed_before"]),
            )
        elif position != "after":
            return IntegrationResult(
                "uninstall",
                True,
                False,
                config_path,
                None,
                marketplace_root,
                changes,
                commands,
                False,
                False,
                ("codex_config_drift_requires_review",),
                actions,
            )
        receipt = _transition_receipt(receipt_path, receipt, state="uninstall_tree")
        state = "uninstall_tree"

    if state == "uninstall_tree":
        document, raw_config = _load_config(config_path)
        if (
            _uninstall_config_position(
                receipt=receipt,
                document=document,
                raw_config=raw_config,
                config_exists=config_path.exists(),
                changes=changes,
            )
            != "after"
        ):
            raise CodexIntegrationError("uninstall_config_recovery_drift")
        for retained in (staging_root, retired_root):
            _safe_remove_marketplace_tree(retained)
        active_exists = marketplace_root.exists() or marketplace_root.is_symlink()
        removal_exists = removal_root.exists() or removal_root.is_symlink()
        if active_exists and removal_exists:
            raise CodexIntegrationError("marketplace_recovery_collision")
        if active_exists:
            if not _marketplace_matches(marketplace_root, target_digests):
                raise CodexIntegrationError("staged_plugin_drift")
            _rename_marketplace_tree(marketplace_root, removal_root)
        if (removal_root.exists() or removal_root.is_symlink()) and not _marketplace_matches(
            removal_root, target_digests
        ):
            raise CodexIntegrationError("removal_marketplace_drift")
        _safe_remove_marketplace_tree(removal_root)
        if any(
            path.exists() or path.is_symlink()
            for path in (marketplace_root, staging_root, retired_root, removal_root)
        ):
            raise CodexIntegrationError("marketplace_cleanup_incomplete")
        receipt = _transition_receipt(receipt_path, receipt, state="uninstall_receipt")
        state = "uninstall_receipt"

    if state != "uninstall_receipt":
        raise CodexIntegrationError("integration_receipt_state_invalid")
    document, raw_config = _load_config(config_path)
    if (
        _uninstall_config_position(
            receipt=receipt,
            document=document,
            raw_config=raw_config,
            config_exists=config_path.exists(),
            changes=changes,
        )
        != "after"
    ):
        raise CodexIntegrationError("uninstall_config_recovery_drift")
    if any(
        path.exists() or path.is_symlink()
        for path in (marketplace_root, staging_root, retired_root, removal_root)
    ):
        raise CodexIntegrationError("marketplace_cleanup_incomplete")
    uninstall_metadata = cast(dict[str, Any], receipt["uninstall"])
    backup_value = uninstall_metadata.get("backup_path")
    backup_path = Path(backup_value) if isinstance(backup_value, str) else None
    _unlink_receipt(receipt_path, expected_sha256=_sha256(receipt_path))
    return IntegrationResult(
        "uninstall",
        True,
        True,
        config_path,
        backup_path,
        marketplace_root,
        changes,
        commands,
        False,
        False,
        (),
        actions,
    )


def _staged_files_valid(receipt: dict[str, Any], marketplace_root: Path) -> bool:
    digests = receipt.get("staged_digests")
    return isinstance(digests, dict) and _marketplace_matches(
        marketplace_root, cast(dict[str, str], digests)
    )


def _plugin_state(value: Any) -> _PluginState | None:
    if isinstance(value, dict):
        name = value.get("name")
        marketplace = value.get("marketplace") or value.get("marketplaceName")
        if name == PLUGIN_NAME and marketplace == MARKETPLACE_NAME:
            source = value.get("source")
            source_path = source.get("path") if isinstance(source, dict) else None
            version = value.get("version")
            return _PluginState(
                installed=value.get("installed") is True,
                enabled=value.get("enabled") is True,
                version=version if isinstance(version, str) else None,
                source_path=Path(source_path) if isinstance(source_path, str) else None,
            )
        for item in value.values():
            found = _plugin_state(item)
            if found is not None:
                return found
    if isinstance(value, list):
        for item in value:
            found = _plugin_state(item)
            if found is not None:
                return found
    return None


def _cached_plugin_root(codex_home: Path, state: _PluginState) -> Path | None:
    version = state.version
    if version is None or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", version):
        return None
    root = codex_home / "plugins" / "cache" / MARKETPLACE_NAME / PLUGIN_NAME / version
    try:
        resolved = root.resolve()
        cache_base = (codex_home / "plugins" / "cache").resolve()
    except OSError:
        return None
    if cache_base not in resolved.parents or root.is_symlink() or not root.is_dir():
        return None
    return root


def _cached_files_valid(
    receipt: dict[str, Any],
    cache_root: Path,
) -> bool:
    digests = receipt.get("staged_digests")
    if not isinstance(digests, dict):
        return False
    try:
        _validate_secure_tree(cache_root)
    except CodexIntegrationError:
        return False
    for relative in STAGED_PLUGIN_FILES:
        expected = digests.get(relative)
        try:
            if (
                not isinstance(expected, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected)
                or _sha256(cache_root / relative) != expected
            ):
                return False
        except (OSError, CodexIntegrationError):
            return False
    return True


def _verify_cached_hook_runtime(
    *,
    interpreter: Path,
    expected_runtime: dict[str, Any],
    cache_root: Path,
    codex_home: Path,
) -> bool:
    hook = cache_root / "src" / "verity_cordon" / "codex" / "hooks.py"
    try:
        if not _runtime_identity_matches(interpreter, expected_runtime):
            return False
        completed = subprocess.run(  # noqa: S603 - receipt-bound local interpreter
            [str(interpreter), str(hook), "SessionStart"],
            input=b"{}",
            check=False,
            capture_output=True,
            env=_codex_environment(codex_home),
            timeout=3.0,
        )
        if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 4096:
            return False
        output = parse_one_object(completed.stdout, maximum_bytes=4096)
        return output == {"continue": True, "systemMessage": WARNING} and (
            _runtime_identity_matches(interpreter, expected_runtime)
        )
    except Exception:
        return False


def _effective_feature_controls(
    runner: CommandRunner,
    *,
    codex_home: Path,
) -> bool:
    try:
        result = runner(
            ["codex", "features", "list"],
            environment=_codex_environment(codex_home),
            timeout=10.0,
        )
        if result.returncode != 0 or len(result.stdout) > 262_144:
            return False
        text = result.stdout.decode("utf-8")
        states: dict[str, bool] = {}
        for line in text.splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[0] in {"hooks", "memories"}:
                if fields[-1] not in {"true", "false"}:
                    return False
                states[fields[0]] = fields[-1] == "true"
        return states == {"hooks": True, "memories": False}
    except Exception:
        return False


def doctor_codex(
    *,
    codex_home: Path | None = None,
    data_dir: Path | None = None,
    runner: CommandRunner = _default_runner,
    operator_confirmed_hook_trust: bool = False,
) -> CodexDoctorReport:
    """Inspect configured, enabled, cached, executable, and trust-confirmed state."""

    resolved_home = _validated_root(
        codex_home if codex_home is not None else _default_codex_home(),
        label="codex_home",
    )
    resolved_data = _validated_root(
        data_dir if data_dir is not None else _default_data_dir(),
        label="verity_data_dir",
    )
    config_path = resolved_home / "config.toml"
    receipt_path = resolved_data / RECEIPT_FILENAME
    marketplace_root = resolved_data / MARKETPLACE_DIRECTORY
    issues: list[str] = []
    config_valid = False
    required_active = False
    try:
        document, _ = _load_config(config_path)
        config_valid = True
        required_active = _required_config_matches(document)
        if not required_active:
            issues.append("required_codex_config_drift")
    except CodexIntegrationError:
        issues.append("codex_config_invalid")
    effective_features_valid = _effective_feature_controls(
        runner,
        codex_home=resolved_home,
    )
    if not effective_features_valid:
        issues.append("effective_codex_feature_drift")

    receipt_present = receipt_path.exists() or receipt_path.is_symlink()
    staged_files_intact = False
    receipt: dict[str, Any] | None = None
    hook_python: Path | None = None
    expected_runtime: dict[str, Any] | None = None
    runtime_identity_intact = False
    command_journal_complete = False
    if receipt_present:
        try:
            receipt, _ = _read_receipt(receipt_path)
            marketplace_root, _, hook_python = _receipt_scope(
                receipt,
                config_path=config_path,
                data_dir=resolved_data,
            )
            staged_files_intact = _staged_files_valid(receipt, marketplace_root)
            if _receipt_state(receipt) != "installed":
                issues.append("integration_recovery_required")
            elif receipt.get("schema_version") == LEGACY_RECEIPT_VERSION:
                issues.append("legacy_hook_runtime_identity_unverified")
            else:
                progress = cast(dict[str, bool], receipt["command_progress"])
                command_journal_complete = progress["marketplace_add"] and progress["plugin_add"]
                if not command_journal_complete:
                    issues.append("integration_command_recovery_required")
                runtime_identity_intact, hook_python = _receipt_runtime_matches_current(receipt)
                expected_runtime = cast(dict[str, Any], receipt["hook_runtime"])
                if not runtime_identity_intact:
                    issues.append("hook_runtime_identity_drift")
        except CodexIntegrationError:
            issues.append("integration_receipt_invalid")
    else:
        issues.append("integration_receipt_missing")
    marketplace_staged = marketplace_root.is_dir() and not marketplace_root.is_symlink()
    if not marketplace_staged:
        issues.append("marketplace_not_staged")
    elif not staged_files_intact:
        issues.append("staged_plugin_drift")

    installed = False
    enabled = False
    cache_intact = False
    runtime_verified = False
    try:
        result = runner(
            ["codex", "plugin", "list", "--json"],
            environment=_codex_environment(resolved_home),
            timeout=10.0,
        )
        if result.returncode == 0:
            parsed = parse_one_object(result.stdout, maximum_bytes=1_048_576)
            state = _plugin_state(parsed)
            if state is not None:
                installed = state.installed
                enabled = state.enabled
                expected_source = marketplace_root / "plugins" / PLUGIN_NAME
                source_matches = (
                    state.source_path is not None
                    and state.source_path.resolve() == expected_source.resolve()
                )
                if not source_matches:
                    issues.append("verity_plugin_source_drift")
                cache_root = _cached_plugin_root(resolved_home, state)
                if receipt is not None and cache_root is not None and source_matches:
                    cache_intact = _cached_files_valid(receipt, cache_root)
                    if (
                        cache_intact
                        and runtime_identity_intact
                        and hook_python is not None
                        and expected_runtime is not None
                    ):
                        runtime_verified = _verify_cached_hook_runtime(
                            interpreter=hook_python,
                            expected_runtime=expected_runtime,
                            cache_root=cache_root,
                            codex_home=resolved_home,
                        )
    except Exception:
        issues.append("codex_plugin_status_unavailable")
    if not installed:
        issues.append("verity_plugin_not_installed")
    elif not enabled:
        issues.append("verity_plugin_disabled")
    if installed and not cache_intact:
        issues.append("installed_plugin_cache_drift")
    if cache_intact and not runtime_verified:
        issues.append("installed_hook_runtime_failed")

    mechanically_ready = (
        config_valid
        and required_active
        and effective_features_valid
        and receipt_present
        and marketplace_staged
        and staged_files_intact
        and command_journal_complete
        and installed
        and enabled
        and cache_intact
        and runtime_verified
    )
    trust_review_required = not operator_confirmed_hook_trust
    if trust_review_required:
        issues.append("hook_trust_not_operator_confirmed")
    ready = mechanically_ready and operator_confirmed_hook_trust
    return CodexDoctorReport(
        config_path=config_path,
        config_valid=config_valid,
        required_config_active=required_active,
        effective_features_valid=effective_features_valid,
        marketplace_staged=marketplace_staged,
        staged_files_intact=staged_files_intact,
        plugin_installed=installed,
        plugin_enabled=enabled,
        installed_cache_intact=cache_intact,
        hook_runtime_verified=runtime_verified,
        receipt_present=receipt_present,
        mechanically_ready=mechanically_ready,
        trust_review_required=trust_review_required,
        ready=ready,
        issues=tuple(dict.fromkeys(issues)),
    )
