"""CLI boundary tests that must fail before any network service starts."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from typer.testing import CliRunner

from verity_cordon.cli import main as cli_main
from verity_cordon.cli.main import app
from verity_cordon.codex import DesktopDemoError, DesktopDemoStatus


def test_serve_rejects_non_loopback_host_override() -> None:
    result = CliRunner().invoke(app, ["serve", "--host", "0.0.0.0"])  # noqa: S104

    assert result.exit_code == 1
    assert "non-loopback" in result.output


def test_serve_rejects_invalid_port_override() -> None:
    result = CliRunner().invoke(app, ["serve", "--port", "70000"])

    assert result.exit_code == 1
    assert "valid range" in result.output


def test_status_reports_subscription_unavailable_without_a_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = SimpleNamespace(
        mode=SimpleNamespace(value="enforce"),
        policy_id="default-policy",
        version="1.0.0",
    )
    runtime = SimpleNamespace(
        event_store=SimpleNamespace(
            verify=AsyncMock(
                return_value=SimpleNamespace(
                    verified=True,
                    materialized_view_consistent=True,
                )
            )
        ),
        queries=SimpleNamespace(statistics=AsyncMock(return_value={"counts": {}})),
        memory_service=SimpleNamespace(
            policy_engine=SimpleNamespace(policy=policy),
            semantic_adjudicator=SimpleNamespace(provider_label="live_codex_subscription"),
        ),
        subscription_runner=None,
    )
    monkeypatch.setattr(cli_main, "build_runtime", AsyncMock(return_value=runtime))

    result = CliRunner().invoke(app, ["status"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["semantic_provider"] == "live_codex_subscription"
    assert payload["semantic_provider_isolation"] == "agentic_sandboxed"
    assert payload["semantic_provider_ready"] is False
    assert payload["semantic_provider_failure_class"] == "unavailable"


def test_status_normalizes_unknown_provider_and_does_not_probe_stray_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = SimpleNamespace(
        mode=SimpleNamespace(value="enforce"),
        policy_id="default-policy",
        version="1.0.0",
    )
    runner = SimpleNamespace(
        check_chatgpt_auth=AsyncMock(side_effect=RuntimeError("must not be probed"))
    )
    runtime = SimpleNamespace(
        event_store=SimpleNamespace(
            verify=AsyncMock(
                return_value=SimpleNamespace(
                    verified=True,
                    materialized_view_consistent=True,
                )
            )
        ),
        queries=SimpleNamespace(statistics=AsyncMock(return_value={"counts": {}})),
        memory_service=SimpleNamespace(
            policy_engine=SimpleNamespace(policy=policy),
            semantic_adjudicator=SimpleNamespace(provider_label="mistyped_provider"),
        ),
        subscription_runner=runner,
    )
    monkeypatch.setattr(cli_main, "build_runtime", AsyncMock(return_value=runtime))

    result = CliRunner().invoke(app, ["status"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["semantic_provider"] == "failed"
    assert payload["semantic_provider_isolation"] == "failed"
    assert payload["semantic_provider_ready"] is False
    assert payload["semantic_provider_failure_class"] == "unsupported_provider"
    runner.check_chatgpt_auth.assert_not_awaited()


class _HealthyResponse:
    status = 200

    def read(self, _: int) -> bytes:
        return b'{"schema_version":"1.0.0","status":"alive"}'


class _HealthyConnection:
    def request(self, *_: Any, **__: Any) -> None:
        return None

    def getresponse(self) -> _HealthyResponse:
        return _HealthyResponse()

    def close(self) -> None:
        return None


@pytest.mark.parametrize(
    ("policy_state", "view_consistent", "expected_exit"),
    [
        ("valid", True, 0),
        ("invalid", True, 1),
        ("valid", False, 1),
    ],
)
def test_doctor_exit_requires_valid_policy_and_consistent_view(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    policy_state: str,
    view_consistent: bool,
    expected_exit: int,
) -> None:
    data_dir = tmp_path / "data"
    dist = tmp_path / "dist"
    data_dir.mkdir()
    dist.mkdir()
    key_path = data_dir / "signing.key"
    key_path.write_bytes(b"synthetic-key-presence-only")
    (dist / "index.html").write_text("fixture", encoding="utf-8")
    settings = SimpleNamespace(
        data_dir=data_dir,
        database_path=data_dir / "verity.db",
        key_path=key_path,
        host="127.0.0.1",
        port=8765,
        control_room_dist=dist,
        prepare=lambda: None,
    )
    verification = SimpleNamespace(
        verified=True,
        materialized_view_consistent=view_consistent,
    )
    runtime = SimpleNamespace(
        event_store=SimpleNamespace(verify=AsyncMock(return_value=verification)),
        memory_service=SimpleNamespace(
            policy_engine=SimpleNamespace(policy=SimpleNamespace(policy_id="verity.default")),
            semantic_adjudicator=SimpleNamespace(provider_label="recorded_fixture"),
        ),
        subscription_runner=None,
        policy_validation_state=policy_state,
    )
    monkeypatch.setattr(
        cli_main.Settings,
        "from_env",
        classmethod(lambda _: settings),
    )
    monkeypatch.setattr(cli_main, "build_runtime", AsyncMock(return_value=runtime))
    monkeypatch.setattr(
        cli_main,
        "doctor_codex",
        lambda **_: SimpleNamespace(ready=True, issues=()),
    )
    monkeypatch.setattr(
        cli_main.http.client,
        "HTTPConnection",
        lambda *_args, **_kwargs: _HealthyConnection(),
    )

    result = CliRunner().invoke(app, ["doctor", "--confirm-hook-trust"])

    assert result.exit_code == expected_exit


def test_doctor_subscription_failure_is_exit_critical_and_content_safe(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class SafeFailure(RuntimeError):
        failure_class = "unsupported_auth"

    data_dir = tmp_path / "data"
    dist = tmp_path / "dist"
    data_dir.mkdir()
    dist.mkdir()
    key_path = data_dir / "signing.key"
    key_path.write_bytes(b"synthetic-key-presence-only")
    (dist / "index.html").write_text("fixture", encoding="utf-8")
    settings = SimpleNamespace(
        data_dir=data_dir,
        database_path=data_dir / "verity.db",
        key_path=key_path,
        host="127.0.0.1",
        port=8765,
        control_room_dist=dist,
        prepare=lambda: None,
    )
    runtime = SimpleNamespace(
        event_store=SimpleNamespace(
            verify=AsyncMock(
                return_value=SimpleNamespace(
                    verified=True,
                    materialized_view_consistent=True,
                )
            )
        ),
        memory_service=SimpleNamespace(
            policy_engine=SimpleNamespace(policy=SimpleNamespace(policy_id="verity.default")),
            semantic_adjudicator=SimpleNamespace(provider_label="live_codex_subscription"),
        ),
        subscription_runner=SimpleNamespace(
            check_chatgpt_auth=AsyncMock(
                side_effect=SafeFailure("raw authentication detail must stay private")
            )
        ),
        policy_validation_state="valid",
    )
    monkeypatch.setattr(
        cli_main.Settings,
        "from_env",
        classmethod(lambda _: settings),
    )
    monkeypatch.setattr(cli_main, "build_runtime", AsyncMock(return_value=runtime))
    monkeypatch.setattr(
        cli_main,
        "doctor_codex",
        lambda **_: SimpleNamespace(ready=True, issues=()),
    )
    monkeypatch.setattr(
        cli_main.http.client,
        "HTTPConnection",
        lambda *_args, **_kwargs: _HealthyConnection(),
    )

    result = CliRunner().invoke(app, ["doctor", "--confirm-hook-trust"])

    assert result.exit_code == 1
    assert "unsupported_auth" in result.output
    assert "raw authentication detail" not in result.output


def test_memory_rescan_requires_explicit_confirmation() -> None:
    result = CliRunner().invoke(
        app,
        [
            "memory",
            "rescan",
            "019bffff-ffff-7fff-bfff-ffffffffffff",
            "--reason",
            "Routine policy review.",
        ],
    )

    assert result.exit_code == 2
    assert "requires --yes" in result.output


def test_policy_activate_refuses_before_append_when_daemon_is_reachable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = SimpleNamespace(
        host="127.0.0.1",
        port=8765,
        prepare=lambda: None,
    )
    runtime_builder = AsyncMock()
    policy_loader = Mock()
    monkeypatch.setattr(
        cli_main.Settings,
        "from_env",
        classmethod(lambda _: settings),
    )
    monkeypatch.setattr(cli_main, "_daemon_reachable", lambda _: True)
    monkeypatch.setattr(cli_main, "build_runtime", runtime_builder)
    monkeypatch.setattr(cli_main, "load_policy", policy_loader)

    result = CliRunner().invoke(
        app,
        [
            "policy",
            "activate",
            str(tmp_path / "synthetic-policy.yaml"),
            "--reason",
            "Synthetic activation guard test.",
            "--yes",
        ],
    )

    assert result.exit_code == 1
    assert "Refusing CLI policy activation" in result.output
    assert "Control Room" in result.output
    runtime_builder.assert_not_awaited()
    policy_loader.assert_not_called()


def test_policy_activate_offline_appends_activation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = SimpleNamespace(
        host="127.0.0.1",
        port=8765,
        prepare=lambda: None,
    )
    policy = SimpleNamespace(
        policy_id="verity.synthetic",
        version="1.0.0",
        content_digest="a" * 64,
        mode=SimpleNamespace(value="enforce"),
    )
    activate = AsyncMock(return_value=policy)
    runtime_builder = AsyncMock(
        return_value=SimpleNamespace(
            policy_repository=SimpleNamespace(activate=activate),
        )
    )
    monkeypatch.setattr(
        cli_main.Settings,
        "from_env",
        classmethod(lambda _: settings),
    )
    monkeypatch.setattr(cli_main, "_daemon_reachable", lambda _: False)
    monkeypatch.setattr(cli_main, "build_runtime", runtime_builder)
    monkeypatch.setattr(cli_main, "load_policy", lambda _: policy)

    result = CliRunner().invoke(
        app,
        [
            "policy",
            "activate",
            str(tmp_path / "synthetic-policy.yaml"),
            "--reason",
            "Synthetic offline activation.",
            "--yes",
        ],
    )

    assert result.exit_code == 0
    runtime_builder.assert_awaited_once_with(settings)
    activate.assert_awaited_once_with(
        policy,
        actor_id="operator.local",
        reason="Synthetic offline activation.",
    )


def test_desktop_setup_confirmation_requires_a_separately_reviewed_digest() -> None:
    result = CliRunner().invoke(app, ["demo", "desktop-setup", "--yes"])

    assert result.exit_code == 2
    assert "requires --expected-preview-digest" in result.output


def test_codex_install_confirmation_requires_a_separately_reviewed_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preview = SimpleNamespace(
        operation="install",
        confirmed=False,
        applied=False,
        config_path=Path("/synthetic/codex/config.toml"),
        backup_path=None,
        marketplace_root=Path("/synthetic/verity/codex-marketplace"),
        changes=(),
        commands=(),
        marketplace_registered=False,
        plugin_installed=False,
        preview_digest="a" * 64,
        artifacts=(),
        hook_manifest={"hooks": {}},
        hook_runtime={
            "path": "/synthetic/python",
            "sha256": "b" * 64,
            "size_bytes": 1,
            "version": [3, 12, 0],
        },
        issues=(),
        operator_actions=(),
    )
    calls: list[bool] = []

    def fake_install(*_: Any, confirmed: bool, **__: Any) -> Any:
        calls.append(confirmed)
        return preview

    monkeypatch.setattr(cli_main, "install_codex", fake_install)

    result = CliRunner().invoke(app, ["install-codex", "--yes"])

    assert result.exit_code == 2
    assert "requires --expected-preview-digest" in result.output
    assert calls == [False]


def test_codex_install_forwards_the_separately_reviewed_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    result_model = SimpleNamespace(
        operation="install",
        confirmed=False,
        applied=False,
        config_path=Path("/synthetic/codex/config.toml"),
        backup_path=None,
        marketplace_root=Path("/synthetic/verity/codex-marketplace"),
        changes=(),
        commands=(),
        marketplace_registered=False,
        plugin_installed=False,
        preview_digest=digest,
        artifacts=(),
        hook_manifest={"hooks": {}},
        hook_runtime={
            "path": "/synthetic/python",
            "sha256": "b" * 64,
            "size_bytes": 1,
            "version": [3, 12, 0],
        },
        issues=(),
        operator_actions=(),
    )
    calls: list[tuple[bool, str | None]] = []

    def fake_install(
        *_: Any,
        confirmed: bool,
        expected_preview_digest: str | None = None,
        **__: Any,
    ) -> Any:
        calls.append((confirmed, expected_preview_digest))
        return result_model

    monkeypatch.setattr(cli_main, "install_codex", fake_install)

    result = CliRunner().invoke(
        app,
        ["install-codex", "--expected-preview-digest", digest, "--yes"],
    )

    assert result.exit_code == 0
    assert calls == [(False, None), (True, digest)]


def test_desktop_teardown_confirmation_requires_a_separately_reviewed_digest() -> None:
    result = CliRunner().invoke(app, ["demo", "desktop-teardown", "--yes"])

    assert result.exit_code == 2
    assert "requires --expected-preview-digest" in result.output


def test_desktop_expected_failure_renders_content_safe_issue_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_safely(*_: Any, **__: Any) -> Any:
        raise DesktopDemoError("normal_integration_not_ready")

    monkeypatch.setattr(cli_main, "setup_desktop_demo", fail_safely)

    result = CliRunner().invoke(app, ["demo", "desktop-setup"])

    assert result.exit_code == 1
    assert "desktop_demo_error" in result.output
    assert "normal_integration_not_ready" in result.output
    assert "unexpected_error" not in result.output


def test_desktop_status_json_separates_fixture_and_system_readiness(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report = DesktopDemoStatus(
        ready=True,
        fixture_ready=True,
        system_ready=True,
        state="installed",
        receipt_valid=True,
        managed_entry_intact=True,
        artifacts_intact=True,
        runtimes_intact=True,
        normal_integration_ready=True,
        fixture_probe_ready=True,
        daemon_ready=True,
        ledger_verified=True,
        policy_valid=True,
        memory_view_consistent=True,
        control_room_ready=True,
        control_room_headers_ready=True,
        issues=(),
    )
    monkeypatch.setattr(
        cli_main,
        "_desktop_demo_paths",
        lambda: (tmp_path / "codex", tmp_path / "data"),
    )
    monkeypatch.setattr(
        cli_main.Settings,
        "from_env",
        classmethod(lambda _: SimpleNamespace(host="127.0.0.1", port=8765)),
    )

    def status_stub(*_: Any, **kwargs: Any) -> DesktopDemoStatus:
        assert kwargs["daemon_host"] == "127.0.0.1"
        assert kwargs["daemon_port"] == 8765
        return report

    monkeypatch.setattr(cli_main, "status_desktop_demo", status_stub)

    result = CliRunner().invoke(app, ["demo", "desktop-status", "--confirm-hook-trust"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ready"] is True
    assert payload["fixture_ready"] is True
    assert payload["system_ready"] is True
    assert payload["daemon_ready"] is True
    assert payload["control_room_headers_ready"] is True
    assert payload["configuration_scope"] == "user_wide_codex_home"
    assert "close every ChatGPT Desktop task" in payload["operator_warning"]
    assert "CLI TUI and IDE Codex sessions" in payload["operator_warning"]
    assert "fully quit" in payload["operator_warning"]
    assert "user-wide demo fixture" in payload["operator_warning"]
    assert "workspace" not in payload["operator_warning"].lower()
