"""Bounded configuration and restrictive local runtime paths."""

from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_data_path

from verity_cordon.core.errors import ConfigurationError


def _env_path(name: str, default: Path) -> Path:
    raw = os.getenv(name)
    return Path(raw).expanduser().resolve() if raw else default


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError as exc:
        raise ConfigurationError("Unable to secure the Verity data directory.") from exc


def assert_private_file(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
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
    max_request_bytes: int = 1_048_576
    ui_passphrase_min_length: int = 12
    ui_challenge_ttl_seconds: int = 60
    ui_challenge_rate_per_minute: int = 20
    ui_failure_limit: int = 5
    ui_failure_window_seconds: int = 300
    ui_cooldown_seconds: int = 300
    ui_session_idle_seconds: int = 900

    @classmethod
    def from_env(cls) -> Settings:
        default_dir = user_data_path("verity-cordon", "Verity Cordon", ensure_exists=False)
        data_dir = _env_path("VERITY_DATA_DIR", default_dir)
        database_path = _env_path("VERITY_DATABASE_PATH", data_dir / "verity.sqlite3")
        policy_raw = os.getenv("VERITY_POLICY_PATH")
        host = os.getenv("VERITY_HOST", "127.0.0.1")
        port = int(os.getenv("VERITY_PORT", "8765"))
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ConfigurationError("Verity refuses a non-loopback bind address.")
        if not 1 <= port <= 65535:
            raise ConfigurationError("VERITY_PORT is outside the valid range.")
        return cls(
            data_dir=data_dir,
            database_path=database_path,
            key_path=data_dir / "signing-key.pem",
            head_path=data_dir / "ledger-head.json",
            capability_path=data_dir / "mutation-capability",
            policy_path=Path(policy_raw).expanduser().resolve() if policy_raw else None,
            host=host,
            port=port,
            semantic_provider=os.getenv("VERITY_SEMANTIC_PROVIDER", "fixture"),
            openai_model=os.getenv("VERITY_OPENAI_MODEL", "gpt-5.6"),
            control_room_passphrase=os.getenv("VERITY_CONTROL_ROOM_PASSPHRASE"),
            control_room_origin=f"http://127.0.0.1:{port}",
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
