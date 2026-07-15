"""CLI boundary tests that must fail before any network service starts."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

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


def test_desktop_setup_confirmation_requires_a_separately_reviewed_digest() -> None:
    result = CliRunner().invoke(app, ["demo", "desktop-setup", "--yes"])

    assert result.exit_code == 2
    assert "requires --expected-preview-digest" in result.output


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
    assert "Close all other Codex Desktop tasks" in payload["operator_warning"]
    assert "workspace" not in payload["operator_warning"].lower()
