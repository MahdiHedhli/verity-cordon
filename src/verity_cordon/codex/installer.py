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
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol, cast

import tomlkit
from platformdirs import user_data_path

from verity_cordon.codex.hooks import SELECTED_EVENTS, WARNING, parse_one_object

PLUGIN_NAME: Final = "verity-cordon"
MARKETPLACE_NAME: Final = "verity-cordon-local"
RECEIPT_VERSION: Final = "1.0.0"
RECEIPT_FILENAME: Final = "codex-integration-receipt.json"
MARKETPLACE_DIRECTORY: Final = "codex-marketplace"
MAX_CONFIG_BYTES: Final = 4_194_304
MAX_RECEIPT_BYTES: Final = 65_536
STAGED_PLUGIN_FILES: Final = frozenset(
    {
        ".codex-plugin/plugin.json",
        "hooks/hooks.json",
        "src/verity_cordon/codex/hooks.py",
    }
)
STAGED_MARKETPLACE_FILE: Final = ".agents/plugins/marketplace.json"

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
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise CodexIntegrationError("unsafe_integration_directory")
    try:
        path.chmod(0o700)
    except OSError as exc:
        raise CodexIntegrationError("integration_directory_permissions_failed") from exc


def _assert_regular_file(path: Path, *, private: bool = False) -> None:
    details = path.lstat()
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise CodexIntegrationError("unsafe_integration_file")
    if private and os.name != "nt":
        if details.st_mode & 0o077 or details.st_uid != os.geteuid():
            raise CodexIntegrationError("unsafe_integration_file_permissions")


def _read_bounded(path: Path, maximum: int, *, private: bool = False) -> bytes:
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


def _atomic_write(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise CodexIntegrationError("unsafe_integration_write_target")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
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
        return tomlkit.document(), b""
    raw = _read_bounded(path, MAX_CONFIG_BYTES)
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


def _render_staged_hooks(source: Path, interpreter: Path) -> bytes:
    try:
        document = parse_one_object(_read_bounded(source, 262_144), maximum_bytes=262_144)
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


def _stage_marketplace(
    plugin_root: Path,
    marketplace_root: Path,
    *,
    interpreter: Path,
) -> dict[str, str]:
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

    _ensure_private_directory(marketplace_root.parent)
    staging = Path(tempfile.mkdtemp(prefix=".codex-marketplace-", dir=marketplace_root.parent))
    try:
        plugin_target = staging / "plugins" / PLUGIN_NAME
        for relative, source in sources.items():
            target = plugin_target / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative == "hooks/hooks.json":
                _atomic_write(target, _render_staged_hooks(source, interpreter))
            else:
                shutil.copyfile(source, target, follow_symlinks=False)
                target.chmod(0o600)
        marketplace_path = staging / ".agents" / "plugins" / "marketplace.json"
        marketplace_path.parent.mkdir(parents=True, exist_ok=True)
        marketplace_content = (
            json.dumps(_marketplace_document(), indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        _atomic_write(marketplace_path, marketplace_content)
        if marketplace_root.exists():
            if marketplace_root.is_symlink() or not marketplace_root.is_dir():
                raise CodexIntegrationError("unsafe_existing_marketplace")
            retired = marketplace_root.with_name(
                f".{marketplace_root.name}.retired-{uuid.uuid4().hex}"
            )
            os.replace(marketplace_root, retired)
            try:
                os.replace(staging, marketplace_root)
            except BaseException:
                os.replace(retired, marketplace_root)
                raise
            else:
                shutil.rmtree(retired)
        else:
            os.replace(staging, marketplace_root)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise

    digests = {
        relative: _sha256(marketplace_root / "plugins" / PLUGIN_NAME / relative)
        for relative in sources
    }
    digests[".agents/plugins/marketplace.json"] = _sha256(
        marketplace_root / ".agents" / "plugins" / "marketplace.json"
    )
    return digests


def _receipt_payload(
    *,
    config_path: Path,
    backup_path: Path | None,
    marketplace_root: Path,
    changes: tuple[ConfigChange, ...],
    staged_digests: dict[str, str],
    hook_python: Path,
) -> dict[str, Any]:
    return {
        "schema_version": RECEIPT_VERSION,
        "config_path": str(config_path),
        "backup_path": str(backup_path) if backup_path else None,
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
        "staged_digests": staged_digests,
        "hook_python": str(hook_python),
        "hook_python_version": [
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro,
        ],
    }


def _write_receipt(path: Path, payload: dict[str, Any]) -> None:
    content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(path, content)


def _read_receipt(path: Path) -> tuple[dict[str, Any], tuple[ConfigChange, ...]]:
    raw = _read_bounded(path, MAX_RECEIPT_BYTES, private=True)
    try:
        receipt = parse_one_object(raw, maximum_bytes=MAX_RECEIPT_BYTES)
    except Exception as exc:
        raise CodexIntegrationError("integration_receipt_invalid") from exc
    if receipt.get("schema_version") != RECEIPT_VERSION:
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
    return receipt, tuple(changes)


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


def _commands(marketplace_root: Path, *, operation: str) -> tuple[tuple[str, ...], ...]:
    if operation == "install":
        return (
            ("codex", "plugin", "marketplace", "add", str(marketplace_root), "--json"),
            ("codex", "plugin", "add", f"{PLUGIN_NAME}@{MARKETPLACE_NAME}", "--json"),
        )
    return (
        ("codex", "plugin", "remove", f"{PLUGIN_NAME}@{MARKETPLACE_NAME}", "--json"),
        ("codex", "plugin", "marketplace", "remove", MARKETPLACE_NAME, "--json"),
    )


def _receipt_scope(
    receipt: dict[str, Any],
    *,
    config_path: Path,
    data_dir: Path,
) -> tuple[Path, Path | None, Path]:
    recorded_config = receipt.get("config_path")
    recorded_marketplace = receipt.get("marketplace_root")
    recorded_backup = receipt.get("backup_path")
    recorded_python = receipt.get("hook_python")
    recorded_python_version = receipt.get("hook_python_version")
    expected_marketplace = data_dir / MARKETPLACE_DIRECTORY
    expected_python = _verified_hook_python()
    expected_python_version = (
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
    )
    if (
        not isinstance(recorded_config, str)
        or Path(recorded_config).resolve() != config_path.resolve()
        or not isinstance(recorded_marketplace, str)
        or Path(recorded_marketplace).resolve() != expected_marketplace.resolve()
        or (recorded_backup is not None and not isinstance(recorded_backup, str))
        or not isinstance(recorded_python, str)
        or not isinstance(recorded_python_version, list)
        or len(recorded_python_version) != 3
        or any(not isinstance(item, int) for item in recorded_python_version)
        or Path(recorded_python).resolve() != expected_python
        or tuple(recorded_python_version) != expected_python_version
    ):
        raise CodexIntegrationError("integration_receipt_scope_invalid")
    return (
        expected_marketplace,
        Path(recorded_backup) if recorded_backup else None,
        expected_python,
    )


def install_codex(
    plugin_root: Path,
    *,
    confirmed: bool = False,
    codex_home: Path | None = None,
    data_dir: Path | None = None,
    run_codex_commands: bool = True,
    runner: CommandRunner = _default_runner,
) -> IntegrationResult:
    """Preview or apply the documented local Codex integration."""

    resolved_home = (codex_home or _default_codex_home()).expanduser()
    resolved_data = (data_dir or _default_data_dir()).expanduser()
    config_path = resolved_home / "config.toml"
    marketplace_root = resolved_data / MARKETPLACE_DIRECTORY
    document, raw_config = _load_config(config_path)
    changes = _config_changes(document)
    receipt_path = resolved_data / RECEIPT_FILENAME
    existing_backup: Path | None = None
    receipt_exists = receipt_path.exists()
    if receipt_exists:
        receipt, original_changes = _read_receipt(receipt_path)
        marketplace_root, existing_backup, _ = _receipt_scope(
            receipt,
            config_path=config_path,
            data_dir=resolved_data,
        )
        changes = original_changes
        if not _required_config_matches(document) and not _original_config_matches(
            document, changes
        ):
            raise CodexIntegrationError("codex_config_drift_requires_review")
    commands = _commands(marketplace_root, operation="install")
    actions = (
        "Before confirmed installation, close every ChatGPT Desktop task, exit "
        "all Codex CLI TUI and IDE Codex sessions, and fully quit the ChatGPT "
        "desktop app.",
        "Start Codex CLI, use /hooks to review the staged Verity hook definitions, "
        "and trust their exact current hashes.",
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
        )

    resolved_home.mkdir(parents=True, exist_ok=True)
    if resolved_home.is_symlink():
        raise CodexIntegrationError("unsafe_codex_home")
    hook_python = _verified_hook_python()
    staged_digests = _stage_marketplace(
        plugin_root.resolve(),
        marketplace_root,
        interpreter=hook_python,
    )
    _ensure_private_directory(resolved_data)
    backup_path = existing_backup
    if not receipt_exists:
        backup_path = _backup(config_path, raw_config, label="install")
    receipt_payload = _receipt_payload(
        config_path=config_path,
        backup_path=backup_path,
        marketplace_root=marketplace_root,
        changes=changes,
        staged_digests=staged_digests,
        hook_python=hook_python,
    )
    # Persist restoration data before replacing any operator configuration.
    _write_receipt(
        receipt_path,
        receipt_payload,
    )
    if not _required_config_matches(document):
        _apply_required_config(document)
        rendered = tomlkit.dumps(document).encode("utf-8")
        _atomic_write(config_path, rendered)

    issues: list[str] = []
    marketplace_registered = False
    plugin_installed = False
    if run_codex_commands:
        marketplace_registered = _run_json_command(
            runner,
            list(commands[0]),
            codex_home=resolved_home,
        )
        if marketplace_registered:
            plugin_installed = _run_json_command(
                runner,
                list(commands[1]),
                codex_home=resolved_home,
            )
        else:
            issues.append("marketplace_registration_failed")
        if marketplace_registered and not plugin_installed:
            issues.append("plugin_install_failed")
    else:
        issues.append("codex_commands_require_operator_execution")

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
        tuple(issues),
        actions,
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


def uninstall_codex(
    *,
    confirmed: bool = False,
    codex_home: Path | None = None,
    data_dir: Path | None = None,
    run_codex_commands: bool = True,
    runner: CommandRunner = _default_runner,
) -> IntegrationResult:
    """Remove the plugin, then restore only config keys recorded by install."""

    resolved_home = (codex_home or _default_codex_home()).expanduser()
    resolved_data = (data_dir or _default_data_dir()).expanduser()
    config_path = resolved_home / "config.toml"
    receipt_path = resolved_data / RECEIPT_FILENAME
    if not receipt_path.exists():
        raise CodexIntegrationError("integration_receipt_missing")
    receipt, changes = _read_receipt(receipt_path)
    marketplace_root, _, _ = _receipt_scope(
        receipt,
        config_path=config_path,
        data_dir=resolved_data,
    )
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
    if not run_codex_commands:
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
            ("remove_plugin_before_restoring_config",),
            actions,
        )

    document, raw_config = _load_config(config_path)
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
            True,
            ("codex_config_drift_requires_review",),
            actions,
        )
    plugin_removed = _run_json_command(runner, list(commands[0]), codex_home=resolved_home)
    if not plugin_removed:
        return IntegrationResult(
            "uninstall",
            True,
            False,
            config_path,
            None,
            marketplace_root,
            changes,
            commands,
            True,
            True,
            ("plugin_remove_failed",),
            actions,
        )
    marketplace_removed = _run_json_command(
        runner,
        list(commands[1]),
        codex_home=resolved_home,
    )
    backup_path = _backup(config_path, raw_config, label="uninstall")
    _restore_config(document, changes)
    _atomic_write(config_path, tomlkit.dumps(document).encode("utf-8"))
    if marketplace_root.exists():
        resolved_marketplace = marketplace_root.resolve()
        if (
            marketplace_root.is_symlink()
            or resolved_data.resolve() not in resolved_marketplace.parents
            or marketplace_root.name != MARKETPLACE_DIRECTORY
        ):
            raise CodexIntegrationError("unsafe_marketplace_cleanup_target")
        shutil.rmtree(marketplace_root)
    receipt_path.unlink()
    issues = () if marketplace_removed else ("marketplace_remove_failed",)
    return IntegrationResult(
        "uninstall",
        True,
        True,
        config_path,
        backup_path,
        marketplace_root,
        changes,
        commands,
        marketplace_removed,
        False,
        issues,
        actions,
    )


def _staged_files_valid(receipt: dict[str, Any], marketplace_root: Path) -> bool:
    digests = receipt.get("staged_digests")
    if not isinstance(digests, dict) or set(digests) != {
        *STAGED_PLUGIN_FILES,
        STAGED_MARKETPLACE_FILE,
    }:
        return False
    plugin_root = marketplace_root / "plugins" / PLUGIN_NAME
    for relative, expected in digests.items():
        if not isinstance(relative, str) or not isinstance(expected, str):
            return False
        path = (
            marketplace_root / relative
            if relative == STAGED_MARKETPLACE_FILE
            else plugin_root / relative
        )
        try:
            if not re.fullmatch(r"[0-9a-f]{64}", expected) or _sha256(path) != expected:
                return False
        except (OSError, CodexIntegrationError):
            return False
    return True


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
    cache_root: Path,
    codex_home: Path,
) -> bool:
    hook = cache_root / "src" / "verity_cordon" / "codex" / "hooks.py"
    try:
        _assert_regular_file(interpreter)
        if not os.access(interpreter, os.X_OK):
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
        return output == {"continue": True, "systemMessage": WARNING}
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

    resolved_home = (codex_home or _default_codex_home()).expanduser()
    resolved_data = (data_dir or _default_data_dir()).expanduser()
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

    receipt_present = receipt_path.exists()
    staged_files_intact = False
    receipt: dict[str, Any] | None = None
    hook_python: Path | None = None
    if receipt_present:
        try:
            receipt, _ = _read_receipt(receipt_path)
            marketplace_root, _, hook_python = _receipt_scope(
                receipt,
                config_path=config_path,
                data_dir=resolved_data,
            )
            staged_files_intact = _staged_files_valid(receipt, marketplace_root)
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
                    if cache_intact and hook_python is not None:
                        runtime_verified = _verify_cached_hook_runtime(
                            interpreter=hook_python,
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
