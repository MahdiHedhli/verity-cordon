"""Bounded durable evidence queue configuration tests."""

from __future__ import annotations

import pytest

from verity_cordon.core.config import Settings, ensure_private_directory
from verity_cordon.core.errors import ConfigurationError, LedgerError
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.ledger.store import SQLiteEventStore


def test_queue_limits_load_from_bounded_environment(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VERITY_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VERITY_PENDING_EVIDENCE_MAX_ITEMS", "17")
    monkeypatch.setenv("VERITY_PENDING_EVIDENCE_MAX_BYTES", "4096")
    monkeypatch.setenv("VERITY_PENDING_EVIDENCE_MAX_ATTEMPTS", "4")
    monkeypatch.setenv("VERITY_PENDING_EVIDENCE_MAX_AGE_SECONDS", "120")

    settings = Settings.from_env()

    assert settings.pending_evidence_max_items == 17
    assert settings.pending_evidence_max_bytes == 4096
    assert settings.pending_evidence_max_attempts == 4
    assert settings.pending_evidence_max_age_seconds == 120


@pytest.mark.parametrize("value", ["0", "not-an-integer", "100001"])
def test_invalid_queue_item_limit_fails_configuration(monkeypatch, tmp_path, value) -> None:
    monkeypatch.setenv("VERITY_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VERITY_PENDING_EVIDENCE_MAX_ITEMS", value)

    with pytest.raises(ConfigurationError, match="VERITY_PENDING_EVIDENCE_MAX_ITEMS"):
        Settings.from_env()


@pytest.mark.parametrize("value", ["0", "not-an-integer", "65536"])
def test_invalid_daemon_port_fails_configuration(monkeypatch, tmp_path, value) -> None:
    monkeypatch.setenv("VERITY_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VERITY_PORT", value)

    with pytest.raises(ConfigurationError, match="VERITY_PORT"):
        Settings.from_env()


def test_private_data_directory_rejects_symbolic_links(tmp_path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)

    with pytest.raises(ConfigurationError, match="symbolic link"):
        ensure_private_directory(linked)


def test_settings_preserve_data_directory_symlink_for_rejection(monkeypatch, tmp_path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    monkeypatch.setenv("VERITY_DATA_DIR", str(linked))

    settings = Settings.from_env()

    assert settings.data_dir == linked
    assert settings.data_dir.is_symlink()
    with pytest.raises(ConfigurationError, match="symbolic link"):
        settings.prepare()


@pytest.mark.asyncio
async def test_settings_preserve_database_symlink_for_store_rejection(
    monkeypatch,
    tmp_path,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    target = tmp_path / "unrelated.txt"
    target.write_text("must remain unchanged", encoding="utf-8")
    linked_database = data_dir / "verity.sqlite3"
    linked_database.symlink_to(target)
    monkeypatch.setenv("VERITY_DATA_DIR", str(data_dir))
    monkeypatch.setenv("VERITY_DATABASE_PATH", str(linked_database))
    settings = Settings.from_env()
    settings.prepare()
    provider = FileKeyProvider.generate(settings.key_path)
    store = SQLiteEventStore(settings.database_path, provider, settings.head_path)

    with pytest.raises(LedgerError, match="symbolic link"):
        await store.initialize()

    assert target.read_text(encoding="utf-8") == "must remain unchanged"
