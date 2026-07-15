"""Bounded configuration and restrictive local runtime paths."""

from __future__ import annotations

import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_data_path

from verity_cordon.core.errors import ConfigurationError

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
CODEX_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
SEMANTIC_PROVIDERS = frozenset({"fixture", "openai", "codex_subscription"})


def validate_loopback_host(host: str) -> str:
    if host not in LOOPBACK_HOSTS:
        raise ConfigurationError("Verity refuses a non-loopback bind address.")
    return host


def loopback_origin(host: str, port: int) -> str:
    validated = validate_loopback_host(host)
    rendered_host = f"[{validated}]" if ":" in validated else validated
    return f"http://{rendered_host}:{port}"


def _env_path(name: str, default: Path) -> Path:
    raw = os.getenv(name)
    selected = Path(raw).expanduser() if raw else default.expanduser()
    # ``resolve()`` would dereference a configured symlink before the security
    # boundary can inspect it. Make the path absolute without following links.
    return Path(os.path.abspath(selected))


def _optional_absolute_env_path(name: str) -> Path | None:
    raw = os.getenv(name)
    if raw is None:
        return None
    if not raw or "\x00" in raw:
        raise ConfigurationError(f"{name} must be a non-empty absolute path.")
    selected = Path(raw).expanduser()
    if not selected.is_absolute():
        raise ConfigurationError(f"{name} must be an absolute path.")
    # Preserve links for the subscription runner's no-follow trust inspection.
    return Path(os.path.abspath(selected))


def _validated_choice(name: str, value: str, choices: frozenset[str]) -> str:
    if value not in choices:
        supported = ", ".join(sorted(choices))
        raise ConfigurationError(f"{name} must be one of: {supported}.")
    return value


def _validated_codex_model(value: str) -> str:
    if not CODEX_MODEL_PATTERN.fullmatch(value):
        raise ConfigurationError(
            "VERITY_CODEX_MODEL must contain 1-128 safe model-identifier characters."
        )
    return value


def _bounded_env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer.") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}, inclusive.")
    return value


def ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ConfigurationError("A Verity data directory must not be a symbolic link.")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ConfigurationError("A Verity data path is not a directory.")
    if os.name != "nt" and metadata.st_uid != os.geteuid():
        raise ConfigurationError("A Verity data directory has an unexpected owner.")
    try:
        path.chmod(0o700)
    except OSError as exc:
        raise ConfigurationError("Unable to secure the Verity data directory.") from exc


def assert_private_file(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ConfigurationError("A Verity credential path is not a regular file.")
    if os.name != "nt" and metadata.st_uid != os.geteuid():
        raise ConfigurationError("A Verity credential file has an unexpected owner.")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o077:
        raise ConfigurationError("A Verity credential file has unsafe permissions.")


def load_or_create_capability(path: Path) -> str:
    if path.exists():
        assert_private_file(path)
        value = path.read_text(encoding="utf-8").strip()
        if len(value) < 32:
            raise ConfigurationError("The local mutation capability is invalid.")
        return value
    value = secrets.token_urlsafe(48)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path
    database_path: Path
    key_path: Path
    head_path: Path
    capability_path: Path
    policy_path: Path | None
    host: str
    port: int
    semantic_provider: str
    openai_model: str
    control_room_passphrase: str | None
    control_room_origin: str
    detector_plugins: tuple[str, ...] = ()
    control_room_dist: Path | None = None
    codex_model: str = "gpt-5.6-luna"
    codex_executable: Path | None = None
    codex_semantic_timeout_seconds: int = 30
    codex_auth_timeout_seconds: int = 5
    codex_max_input_bytes: int = 262_144
    codex_max_jsonl_bytes: int = 2_097_152
    codex_max_stderr_bytes: int = 262_144
    codex_max_final_bytes: int = 65_536
    codex_termination_grace_seconds: int = 1
    max_request_bytes: int = 1_048_576
    ui_passphrase_min_length: int = 12
    ui_challenge_ttl_seconds: int = 60
    ui_challenge_rate_per_minute: int = 20
    ui_failure_limit: int = 5
    ui_failure_window_seconds: int = 300
    ui_cooldown_seconds: int = 300
    ui_session_idle_seconds: int = 900
    pending_evidence_max_items: int = 256
    pending_evidence_max_bytes: int = 16_777_216
    pending_evidence_max_attempts: int = 3
    pending_evidence_max_age_seconds: int = 3600

    @classmethod
    def from_env(cls) -> Settings:
        default_dir = user_data_path("verity-cordon", "Verity Cordon", ensure_exists=False)
        data_dir = _env_path("VERITY_DATA_DIR", default_dir)
        database_path = _env_path("VERITY_DATABASE_PATH", data_dir / "verity.sqlite3")
        policy_raw = os.getenv("VERITY_POLICY_PATH")
        host = os.getenv("VERITY_HOST", "127.0.0.1")
        port = _bounded_env_int("VERITY_PORT", 8765, minimum=1, maximum=65535)
        detector_plugins = tuple(
            item.strip()
            for item in os.getenv("VERITY_DETECTOR_PLUGINS", "").split(",")
            if item.strip()
        )
        validate_loopback_host(host)
        return cls(
            data_dir=data_dir,
            database_path=database_path,
            key_path=data_dir / "signing-key.pem",
            head_path=data_dir / "ledger-head.json",
            capability_path=data_dir / "mutation-capability",
            policy_path=Path(policy_raw).expanduser().resolve() if policy_raw else None,
            host=host,
            port=port,
            semantic_provider=_validated_choice(
                "VERITY_SEMANTIC_PROVIDER",
                os.getenv("VERITY_SEMANTIC_PROVIDER", "fixture"),
                SEMANTIC_PROVIDERS,
            ),
            openai_model=os.getenv("VERITY_OPENAI_MODEL", "gpt-5.6"),
            control_room_passphrase=os.getenv("VERITY_CONTROL_ROOM_PASSPHRASE"),
            control_room_origin=loopback_origin(host, port),
            detector_plugins=detector_plugins,
            codex_model=_validated_codex_model(os.getenv("VERITY_CODEX_MODEL", "gpt-5.6-luna")),
            codex_executable=_optional_absolute_env_path("VERITY_CODEX_EXECUTABLE"),
            codex_semantic_timeout_seconds=_bounded_env_int(
                "VERITY_CODEX_SEMANTIC_TIMEOUT_SECONDS",
                30,
                minimum=1,
                maximum=120,
            ),
            codex_auth_timeout_seconds=_bounded_env_int(
                "VERITY_CODEX_AUTH_TIMEOUT_SECONDS",
                5,
                minimum=1,
                maximum=15,
            ),
            codex_max_input_bytes=_bounded_env_int(
                "VERITY_CODEX_MAX_INPUT_BYTES",
                262_144,
                minimum=1,
                maximum=1_048_576,
            ),
            codex_max_jsonl_bytes=_bounded_env_int(
                "VERITY_CODEX_MAX_JSONL_BYTES",
                2_097_152,
                minimum=1,
                maximum=4_194_304,
            ),
            codex_max_stderr_bytes=_bounded_env_int(
                "VERITY_CODEX_MAX_STDERR_BYTES",
                262_144,
                minimum=1,
                maximum=1_048_576,
            ),
            codex_max_final_bytes=_bounded_env_int(
                "VERITY_CODEX_MAX_FINAL_BYTES",
                65_536,
                minimum=1,
                maximum=262_144,
            ),
            codex_termination_grace_seconds=_bounded_env_int(
                "VERITY_CODEX_TERMINATION_GRACE_SECONDS",
                1,
                minimum=1,
                maximum=3,
            ),
            control_room_dist=(
                _env_path("VERITY_CONTROL_ROOM_DIST", data_dir / "unused")
                if os.getenv("VERITY_CONTROL_ROOM_DIST")
                else None
            ),
            pending_evidence_max_items=_bounded_env_int(
                "VERITY_PENDING_EVIDENCE_MAX_ITEMS",
                256,
                minimum=1,
                maximum=100_000,
            ),
            pending_evidence_max_bytes=_bounded_env_int(
                "VERITY_PENDING_EVIDENCE_MAX_BYTES",
                16_777_216,
                minimum=1,
                maximum=1_073_741_824,
            ),
            pending_evidence_max_attempts=_bounded_env_int(
                "VERITY_PENDING_EVIDENCE_MAX_ATTEMPTS",
                3,
                minimum=1,
                maximum=100,
            ),
            pending_evidence_max_age_seconds=_bounded_env_int(
                "VERITY_PENDING_EVIDENCE_MAX_AGE_SECONDS",
                3600,
                minimum=1,
                maximum=2_592_000,
            ),
        )

    def prepare(self) -> None:
        ensure_private_directory(self.data_dir)
        ensure_private_directory(self.database_path.parent)

    def validate_control_room_passphrase(self, value: str | None = None) -> str:
        passphrase = value or self.control_room_passphrase
        if passphrase is None or len(passphrase) < self.ui_passphrase_min_length:
            raise ConfigurationError(
                "Control Room passphrase must contain at least "
                f"{self.ui_passphrase_min_length} characters."
            )
        if len(passphrase) > 256:
            raise ConfigurationError("Control Room passphrase is too long.")
        return passphrase
