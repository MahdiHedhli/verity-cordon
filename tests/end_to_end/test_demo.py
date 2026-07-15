"""End-to-end acceptance tests for explicit offline and live demo modes."""

from __future__ import annotations

from pathlib import Path

import pytest

from verity_cordon.core.config import Settings
from verity_cordon.core.errors import ConfigurationError
from verity_cordon.demo import run_live_demo, run_offline_demo


def demo_settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "verity.sqlite3",
        key_path=tmp_path / "signing-key.pem",
        head_path=tmp_path / "ledger-head.json",
        capability_path=tmp_path / "mutation-capability",
        policy_path=None,
        host="127.0.0.1",
        port=8765,
        semantic_provider="fixture",
        openai_model="gpt-5.6",
        control_room_passphrase="synthetic-demo-passphrase",
        control_room_origin="http://127.0.0.1:8765",
    )


@pytest.mark.asyncio
async def test_offline_demo_runs_real_shadow_enforce_revoke_and_verify(tmp_path) -> None:
    run = await run_offline_demo(demo_settings(tmp_path))

    assert run.summary["semantic_provider"] == "recorded_fixture"
    assert run.summary["shadow"]["actual_action"] == "allow"
    assert run.summary["shadow"]["would_have_action"] == "quarantine"
    assert "quarantine" in run.summary["enforcement"]["actions"]
    assert run.summary["enforcement"]["poisoned_memory_active"] is False
    assert run.summary["fixture"] == {
        "server_name": "verity-cordon-poisoned-docs-fixture",
        "tool_name": "get_release_guidance",
        "transport": "stdio",
        "external_transmission_performed": False,
    }
    assert run.summary["rescan"]["actual_action"] == "quarantine"
    assert run.summary["rescan"]["revoked"] is True
    assert run.summary["simulated_session_start"]["approved_memory_present"] is True
    assert run.summary["simulated_session_start"]["poisoned_memory_absent"] is True
    assert run.summary["simulated_session_start"]["injection_state"] == "approved_only"
    assert run.summary["ledger_verified"] is True
    assert run.summary["view_consistent"] is True
    active = await run.runtime.memory_view.list_active()
    assert active
    assert all("demo_artifact_sink" not in item.safe_statement for item in active)


@pytest.mark.asyncio
async def test_live_demo_never_substitutes_fixture_without_api_key(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(ConfigurationError, match="OPENAI_API_KEY"):
        await run_live_demo(demo_settings(tmp_path))

    assert not (tmp_path / "signing-key.pem").exists()


@pytest.mark.asyncio
async def test_demo_fails_closed_when_reviewed_fixture_is_missing(tmp_path) -> None:
    with pytest.raises(ConfigurationError, match="fixture source is unavailable"):
        await run_offline_demo(demo_settings(tmp_path), fixture_root=tmp_path)

    assert not (tmp_path / "signing-key.pem").exists()
