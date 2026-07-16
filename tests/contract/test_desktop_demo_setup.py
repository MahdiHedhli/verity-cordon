"""Security contract for reversible Codex Desktop demonstration setup."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from tests.contract.test_codex_hooks import SuccessfulCodexRunner
from verity_cordon.codex.installer import install_codex

from .test_desktop_demo_receipt import SCHEMA_PATH

REPOSITORY_ROOT = Path(__file__).parents[2]
MANAGED_NAME = "verity_cordon_poisoned_docs"
DEMO_RECEIPT = "desktop-demo-receipt.json"
NORMAL_RECEIPT = "codex-integration-receipt.json"
FIXTURE_RELATIVE = Path("examples/poisoned-docs-mcp/src/poisoned_docs_mcp/server.py")


@dataclass(slots=True)
class ReadyContext:
    repository_root: Path
    codex_home: Path
    data_dir: Path
    runner: SuccessfulCodexRunner
    codex_executable: Path
    python_executable: Path

    @property
    def config_path(self) -> Path:
        return self.codex_home / "config.toml"

    @property
    def receipt_path(self) -> Path:
        return self.data_dir / DEMO_RECEIPT


def _api() -> Any:
    return importlib.import_module("verity_cordon.codex.demo_installer")


def _ready_context(tmp_path: Path, *, repository_root: Path = REPOSITORY_ROOT) -> ReadyContext:
    codex_home = tmp_path / "codex-home"
    data_dir = tmp_path / "verity-data"
    runner = SuccessfulCodexRunner()
    preview = install_codex(
        REPOSITORY_ROOT,
        confirmed=False,
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
    )
    install_codex(
        REPOSITORY_ROOT,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
    )
    return ReadyContext(
        repository_root=repository_root,
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        codex_executable=Path(sys.executable).resolve(),
        python_executable=Path(sys.executable).resolve(),
    )


def _setup(context: ReadyContext, **overrides: Any) -> Any:
    values: dict[str, Any] = {
        "confirmed": False,
        "expected_preview_digest": None,
        "codex_home": context.codex_home,
        "data_dir": context.data_dir,
        "codex_executable": context.codex_executable,
        "python_executable": context.python_executable,
        "runner": context.runner,
        "operator_confirmed_hook_trust": True,
    }
    values.update(overrides)
    return _api().setup_desktop_demo(context.repository_root, **values)


def _healthy_system_probe(**_: Any) -> Any:
    return _api().DesktopSystemReadiness(
        ready=True,
        daemon_ready=True,
        ledger_verified=True,
        policy_valid=True,
        memory_view_consistent=True,
        control_room_ready=True,
        control_room_headers_ready=True,
        issues=(),
    )


def _invalid_ledger_system_probe(**_: Any) -> Any:
    return _api().DesktopSystemReadiness(
        ready=False,
        daemon_ready=True,
        ledger_verified=False,
        policy_valid=True,
        memory_view_consistent=False,
        control_room_ready=True,
        control_room_headers_ready=True,
        issues=("ledger_invalid", "materialized_view_stale"),
    )


def _status(context: ReadyContext, **overrides: Any) -> Any:
    values: dict[str, Any] = {
        "codex_home": context.codex_home,
        "data_dir": context.data_dir,
        "runner": context.runner,
        "operator_confirmed_hook_trust": True,
        "probe": True,
        "system_probe": _healthy_system_probe,
    }
    values.update(overrides)
    return _api().status_desktop_demo(context.repository_root, **values)


def _teardown(context: ReadyContext, **overrides: Any) -> Any:
    values: dict[str, Any] = {
        "confirmed": False,
        "expected_preview_digest": None,
        "codex_home": context.codex_home,
        "data_dir": context.data_dir,
        "runner": context.runner,
        "operator_confirmed_hook_trust": True,
    }
    values.update(overrides)
    return _api().teardown_desktop_demo(context.repository_root, **values)


def _tree_snapshot(root: Path) -> dict[str, tuple[str, int]]:
    if not root.exists():
        return {}
    snapshot: dict[str, tuple[str, int]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            snapshot[relative] = (f"symlink:{os.readlink(path)}", 0)
        elif path.is_file():
            snapshot[relative] = (
                hashlib.sha256(path.read_bytes()).hexdigest(),
                stat.S_IMODE(path.stat().st_mode),
            )
        elif path.is_dir():
            snapshot[relative] = ("directory", stat.S_IMODE(path.stat().st_mode))
    return snapshot


def _managed_config(context: ReadyContext) -> dict[str, Any]:
    document = tomllib.loads(context.config_path.read_text(encoding="utf-8"))
    return document["mcp_servers"][MANAGED_NAME]


def _installed_context(tmp_path: Path) -> tuple[ReadyContext, Any]:
    context = _ready_context(tmp_path)
    preview = _setup(context)
    installed = _setup(
        context,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
    )
    assert installed.applied
    return context, installed


def _rewrite_removed_receipt_as_legacy(
    context: ReadyContext,
    *,
    version: str,
) -> dict[str, Any]:
    receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    assert receipt["state"] == "removed"
    receipt["receipt_version"] = version
    receipt.pop("artifact_removals")
    if version == "1.0.0":
        for field in ("config_mode_before", "config_unrelated_sha256", "failure_class"):
            receipt.pop(field)
    context.receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    context.receipt_path.chmod(0o600)
    return receipt


def _rewrite_installed_receipt_as_v1_1_failed(context: ReadyContext) -> dict[str, Any]:
    with context.config_path.open("a", encoding="utf-8") as handle:
        handle.write('\n[legacy_failed_projection]\nmarker = "synthetic-v1.1-failure"\n')
    receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    assert receipt["state"] == "installed"
    receipt["receipt_version"] = "1.1.0"
    receipt["state"] = "failed"
    receipt["config_after_sha256"] = hashlib.sha256(context.config_path.read_bytes()).hexdigest()
    receipt["failure_class"] = "config_projection_mismatch"
    receipt.pop("artifact_removals")
    context.receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    context.receipt_path.chmod(0o600)
    return receipt


def _leave_prepared_before_config(
    context: ReadyContext,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    api = _api()
    preview = _setup(context)
    real_atomic_write = api._atomic_write
    failed = False

    def interrupt_config(
        path: Path,
        content: bytes,
        *,
        mode: int = 0o600,
        expected_sha256: str | None = None,
        **kwargs: Any,
    ) -> Any:
        nonlocal failed
        if path == context.config_path and not failed:
            failed = True
            raise OSError("synthetic prepared-state interruption")
        return real_atomic_write(
            path,
            content,
            mode=mode,
            expected_sha256=expected_sha256,
            **kwargs,
        )

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "_atomic_write", interrupt_config)
        with pytest.raises(api.DesktopDemoError, match="setup_interrupted"):
            _setup(
                context,
                confirmed=True,
                expected_preview_digest=preview.preview_digest,
            )
    assert failed is True
    assert json.loads(context.receipt_path.read_text(encoding="utf-8"))["state"] == "prepared"
    return preview


def test_preview_is_read_only_and_apply_installs_one_strict_private_entry(
    tmp_path: Path,
) -> None:
    context = _ready_context(tmp_path)
    before_home = _tree_snapshot(context.codex_home)
    before_data = _tree_snapshot(context.data_dir)
    before_config = tomllib.loads(context.config_path.read_text(encoding="utf-8"))
    before_commands = list(context.runner.commands)

    preview = _setup(context)

    assert preview.operation == "desktop_setup"
    assert preview.confirmed is False
    assert preview.applied is False
    assert preview.normal_integration_ready is True
    assert preview.managed_entry["name"] == MANAGED_NAME
    assert preview.managed_entry["enabled_tools"] == [
        "get_release_guidance",
        "demo_artifact_sink",
    ]
    assert preview.managed_entry["tool_overrides"] == {
        "demo_artifact_sink": {"approval_mode": "prompt"}
    }
    assert any("/mcp" in action and "canary" in action for action in preview.operator_actions)
    assert any(
        "fully quit" in action and "confirmed setup" in action
        for action in preview.operator_actions
    )
    assert _tree_snapshot(context.codex_home) == before_home
    assert _tree_snapshot(context.data_dir) == before_data
    assert not context.receipt_path.exists()
    new_commands = context.runner.commands[len(before_commands) :]
    assert all(MANAGED_NAME not in " ".join(command) for command in new_commands)

    installed = _setup(
        context,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
    )

    assert installed.applied is True
    assert installed.state == "installed"
    assert context.receipt_path.is_file() and not context.receipt_path.is_symlink()
    assert stat.S_IMODE(context.receipt_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(installed.staging_root.stat().st_mode) == 0o700
    staged = installed.staging_root / "poisoned_docs_server.py"
    assert staged.is_file() and not staged.is_symlink()
    assert stat.S_IMODE(staged.stat().st_mode) == 0o600
    managed = _managed_config(context)
    assert managed == {
        "command": str(context.python_executable),
        "args": ["-I", str(staged)],
        "cwd": str(installed.staging_root),
        "enabled": True,
        "required": True,
        "startup_timeout_sec": 5.0,
        "tool_timeout_sec": 5.0,
        "enabled_tools": ["get_release_guidance", "demo_artifact_sink"],
        "default_tools_approval_mode": "writes",
        "tools": {"demo_artifact_sink": {"approval_mode": "prompt"}},
    }
    assert not ({"env", "env_vars", "url", "headers", "oauth"} & set(managed))
    after_config = tomllib.loads(context.config_path.read_text(encoding="utf-8"))
    del after_config["mcp_servers"][MANAGED_NAME]
    if not after_config["mcp_servers"]:
        del after_config["mcp_servers"]
    assert after_config == before_config
    receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(receipt)
    assert receipt["state"] == "installed"
    assert receipt["managed_entry_original"] == {
        "present": False,
        "digest": None,
        "parent_table_present": "mcp_servers" in before_config,
    }


def test_demo_setup_never_copies_unrelated_codex_config_secrets(
    tmp_path: Path,
) -> None:
    context = _ready_context(tmp_path)
    synthetic_secret = "synthetic-unrelated-mcp-token-must-not-be-backed-up"
    with context.config_path.open("a", encoding="utf-8") as handle:
        handle.write(
            "\n[mcp_servers.operator_owned]\n"
            'command = "/usr/bin/false"\n'
            f'env = {{ TOKEN = "{synthetic_secret}" }}\n'
        )
    preview = _setup(context)

    installed = _setup(
        context,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
    )

    assert installed.applied is True
    assert synthetic_secret in context.config_path.read_text(encoding="utf-8")
    receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    assert receipt["backup_path"] is None
    assert receipt["backup_sha256"] is None
    assert not (context.data_dir / "desktop-demo" / "backups").exists()
    for path in (context.data_dir / "desktop-demo").rglob("*"):
        if path.is_file() and not path.is_symlink():
            assert synthetic_secret.encode("utf-8") not in path.read_bytes()


def test_setup_requires_ready_normal_integration_and_explicit_confirmation(
    tmp_path: Path,
) -> None:
    context = _ready_context(tmp_path)
    context.runner.effective_features = False

    preview = _setup(context)

    assert preview.applied is False
    assert preview.normal_integration_ready is False
    assert "normal_integration_not_ready" in preview.issues
    with pytest.raises(_api().DesktopDemoError, match="normal_integration_not_ready"):
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )
    assert not context.receipt_path.exists()
    assert MANAGED_NAME not in context.config_path.read_text(encoding="utf-8")


def test_setup_preview_directs_missing_normal_integration_without_mutation(
    tmp_path: Path,
) -> None:
    context = _ready_context(tmp_path)
    (context.data_dir / NORMAL_RECEIPT).unlink()
    before_home = _tree_snapshot(context.codex_home)
    before_data = _tree_snapshot(context.data_dir)

    preview = _setup(context)

    assert preview.applied is False
    assert preview.normal_integration_ready is False
    assert preview.issues == ("normal_integration_not_ready",)
    assert any("verity install-codex" in action for action in preview.operator_actions)
    assert _tree_snapshot(context.codex_home) == before_home
    assert _tree_snapshot(context.data_dir) == before_data
    with pytest.raises(_api().DesktopDemoError, match="normal_integration_not_ready"):
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )
    assert not context.receipt_path.exists()


def test_programmatic_setup_does_not_assume_hook_trust(tmp_path: Path) -> None:
    context = _ready_context(tmp_path)

    preview = _api().setup_desktop_demo(
        context.repository_root,
        codex_home=context.codex_home,
        data_dir=context.data_dir,
        codex_executable=context.codex_executable,
        python_executable=context.python_executable,
        runner=context.runner,
    )

    assert preview.normal_integration_ready is False
    assert "normal_integration_not_ready" in preview.issues


def test_reserved_name_collision_is_refused_without_echo_or_receipt(
    tmp_path: Path,
) -> None:
    context = _ready_context(tmp_path)
    secret = "synthetic-existing-bearer-must-not-echo"
    with context.config_path.open("a", encoding="utf-8") as handle:
        handle.write(
            f'\n[mcp_servers.{MANAGED_NAME}]\nurl = "https://example.invalid"\n'
            f'env = {{ TOKEN = "{secret}" }}\n'
        )

    with pytest.raises(_api().DesktopDemoError, match="reserved_name_exists") as captured:
        _setup(context)

    assert secret not in str(captured.value)
    assert not context.receipt_path.exists()
    assert secret in context.config_path.read_text(encoding="utf-8")


def test_apply_rejects_any_config_change_after_preview_without_partial_setup(
    tmp_path: Path,
) -> None:
    context = _ready_context(tmp_path)
    preview = _setup(context)
    with context.config_path.open("a", encoding="utf-8") as handle:
        handle.write('\n[unrelated_after_preview]\nvalue = "preserve"\n')

    with pytest.raises(_api().DesktopDemoError, match="config_changed_after_preview"):
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )

    assert not context.receipt_path.exists()
    assert MANAGED_NAME not in tomllib.loads(context.config_path.read_text(encoding="utf-8")).get(
        "mcp_servers", {}
    )


def test_unrelated_post_install_change_is_not_drift_and_survives_teardown(
    tmp_path: Path,
) -> None:
    context, _ = _installed_context(tmp_path)
    ledger_sentinel = context.data_dir / "verity.sqlite3"
    key_sentinel = context.data_dir / "signing-key.pem"
    ledger_sentinel.write_bytes(b"synthetic-ledger-sentinel")
    key_sentinel.write_bytes(b"synthetic-key-sentinel")
    key_sentinel.chmod(0o600)
    with context.config_path.open("a", encoding="utf-8") as handle:
        handle.write('\n[unrelated_after_demo]\nowner = "operator"\n')

    status = _status(context)
    assert status.ready is True
    assert status.managed_entry_intact is True
    preview = _teardown(context)
    assert any("/mcp" in action and "absent" in action for action in preview.operator_actions)
    assert any(
        "fully quit" in action and "confirmed teardown" in action
        for action in preview.operator_actions
    )
    removed = _teardown(
        context,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
    )

    assert removed.applied is True
    assert removed.state == "removed"
    document = tomllib.loads(context.config_path.read_text(encoding="utf-8"))
    assert document["unrelated_after_demo"] == {"owner": "operator"}
    assert MANAGED_NAME not in document.get("mcp_servers", {})
    assert (context.data_dir / NORMAL_RECEIPT).exists()
    assert context.runner.installed is True
    assert ledger_sentinel.read_bytes() == b"synthetic-ledger-sentinel"
    assert key_sentinel.read_bytes() == b"synthetic-key-sentinel"


def test_preexisting_empty_mcp_parent_and_comment_survive_teardown(tmp_path: Path) -> None:
    context = _ready_context(tmp_path)
    with context.config_path.open("a", encoding="utf-8") as handle:
        handle.write("\n# operator-owned empty table\n[mcp_servers]\n")
    preview = _setup(context)
    _setup(context, confirmed=True, expected_preview_digest=preview.preview_digest)
    removal_preview = _teardown(context)

    _teardown(
        context,
        confirmed=True,
        expected_preview_digest=removal_preview.preview_digest,
    )

    rendered = context.config_path.read_text(encoding="utf-8")
    assert "# operator-owned empty table" in rendered
    assert "[mcp_servers]" in rendered


def test_managed_entry_drift_blocks_readiness_and_automatic_teardown(
    tmp_path: Path,
) -> None:
    context, _ = _installed_context(tmp_path)
    secret = "synthetic-drift-token-must-not-echo"
    with context.config_path.open("a", encoding="utf-8") as handle:
        handle.write(f'\n[mcp_servers.{MANAGED_NAME}.env]\nTOKEN = "{secret}"\n')

    status = _status(context, probe=False)

    assert status.ready is False
    assert status.managed_entry_intact is False
    assert "managed_entry_drift" in status.issues
    preview = _teardown(context)
    with pytest.raises(_api().DesktopDemoError, match="managed_entry_drift") as captured:
        _teardown(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )
    assert secret not in str(captured.value)
    assert secret in context.config_path.read_text(encoding="utf-8")
    assert context.receipt_path.exists()


@pytest.mark.parametrize(
    ("expected", "drifted"),
    [
        ("enabled = true", "enabled = 1"),
        ("startup_timeout_sec = 5.0", "startup_timeout_sec = 5"),
    ],
)
def test_managed_entry_comparison_rejects_equal_but_different_toml_types(
    tmp_path: Path,
    expected: str,
    drifted: str,
) -> None:
    context, _ = _installed_context(tmp_path)
    config = context.config_path.read_text(encoding="utf-8")
    assert expected in config
    context.config_path.write_text(config.replace(expected, drifted, 1), encoding="utf-8")
    context.config_path.chmod(0o600)

    status = _status(context)
    teardown = _teardown(context)

    assert status.ready is False
    assert status.managed_entry_intact is False
    assert "managed_entry_drift" in status.issues
    assert "managed_entry_drift" in teardown.issues
    with pytest.raises(_api().DesktopDemoError, match="managed_entry_drift"):
        _teardown(
            context,
            confirmed=True,
            expected_preview_digest=teardown.preview_digest,
        )


def test_receipt_and_staged_artifact_tamper_disable_status_without_echo(
    tmp_path: Path,
) -> None:
    context, installed = _installed_context(tmp_path)
    secret = "synthetic-receipt-content-must-not-echo"
    receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    receipt["unexpected_secret"] = secret
    context.receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    context.receipt_path.chmod(0o600)

    status = _status(context, probe=False)

    assert status.ready is False
    assert status.receipt_valid is False
    assert secret not in repr(status)

    context.receipt_path.unlink()
    context.receipt_path.write_text(
        json.dumps({key: value for key, value in receipt.items() if key != "unexpected_secret"}),
        encoding="utf-8",
    )
    context.receipt_path.chmod(0o600)
    staged = installed.staging_root / "poisoned_docs_server.py"
    staged.write_text("raise SystemExit(9)\n", encoding="utf-8")
    staged.chmod(0o600)

    artifact_status = _status(context, probe=False)
    assert artifact_status.ready is False
    assert artifact_status.artifacts_intact is False
    assert "staged_artifact_drift" in artifact_status.issues


@pytest.mark.parametrize(
    "failure_boundary",
    ["prepared_receipt", "config", "installed_receipt"],
)
def test_interrupted_setup_is_reconcilable_at_each_write_ahead_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_boundary: str,
) -> None:
    context = _ready_context(tmp_path)
    api = _api()
    preview = _setup(context)
    original_config = context.config_path.read_bytes()
    real_atomic_write = api._atomic_write
    failed = False

    def fail_config(
        path: Path,
        content: bytes,
        *,
        mode: int = 0o600,
        expected_sha256: str | None = None,
        **kwargs: Any,
    ) -> Any:
        nonlocal failed
        receipt_exists = context.receipt_path.exists()
        should_fail = (
            (
                failure_boundary == "prepared_receipt"
                and path == context.receipt_path
                and not receipt_exists
            )
            or (failure_boundary == "config" and path == context.config_path)
            or (
                failure_boundary == "installed_receipt"
                and path == context.receipt_path
                and receipt_exists
            )
        )
        if should_fail and not failed:
            failed = True
            raise OSError("synthetic config interruption must not escape")
        return real_atomic_write(
            path,
            content,
            mode=mode,
            expected_sha256=expected_sha256,
            **kwargs,
        )

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "_atomic_write", fail_config)
        with pytest.raises(api.DesktopDemoError, match="setup_interrupted") as captured:
            _setup(
                context,
                confirmed=True,
                expected_preview_digest=preview.preview_digest,
            )
    assert failed is True
    assert "synthetic config interruption" not in str(captured.value)
    if failure_boundary == "prepared_receipt":
        assert context.config_path.read_bytes() == original_config
        assert not context.receipt_path.exists()
        assert not (preview.staging_root / "poisoned_docs_server.py").exists()
    else:
        prepared = json.loads(context.receipt_path.read_text(encoding="utf-8"))
        assert prepared["state"] == "prepared"
        document = tomllib.loads(context.config_path.read_text(encoding="utf-8"))
        if failure_boundary == "config":
            assert context.config_path.read_bytes() == original_config
            assert MANAGED_NAME not in document.get("mcp_servers", {})
        else:
            assert MANAGED_NAME in document["mcp_servers"]

    recovered = _setup(
        context,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
    )
    assert recovered.applied is True
    assert recovered.state == "installed"


def test_prepared_recovery_restages_a_missing_receipt_bound_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _ready_context(tmp_path)
    preview = _leave_prepared_before_config(context, monkeypatch)
    staged = preview.staging_root / "poisoned_docs_server.py"
    staged.unlink()

    recovered = _setup(
        context,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
    )

    receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    assert recovered.applied is True
    assert recovered.state == "installed"
    assert hashlib.sha256(staged.read_bytes()).hexdigest() == receipt["artifacts"][0]["sha256"]


@pytest.mark.parametrize(
    ("drift", "expected_error"),
    [
        ("config", "config_projection_drift"),
        ("managed", "managed_entry_drift"),
    ],
)
def test_prepared_recovery_rejects_config_drift_before_restaging_missing_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
    expected_error: str,
) -> None:
    context = _ready_context(tmp_path)
    preview = _leave_prepared_before_config(context, monkeypatch)
    staged = preview.staging_root / "poisoned_docs_server.py"
    staged.unlink()
    synthetic_marker = "synthetic-recovery-drift-must-not-echo"
    with context.config_path.open("a", encoding="utf-8") as handle:
        if drift == "config":
            handle.write(f'\n[operator_change_after_prepared]\nmarker = "{synthetic_marker}"\n')
        else:
            handle.write(
                f"\n[mcp_servers.{MANAGED_NAME}]\n"
                'command = "/usr/bin/false"\n'
                f'marker = "{synthetic_marker}"\n'
            )
    config_before = context.config_path.read_bytes()
    receipt_before = context.receipt_path.read_bytes()

    with pytest.raises(_api().DesktopDemoError, match=expected_error) as captured:
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )

    assert synthetic_marker not in str(captured.value)
    assert not staged.exists()
    assert context.config_path.read_bytes() == config_before
    assert context.receipt_path.read_bytes() == receipt_before


def test_prepared_recovery_refuses_a_present_drifted_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _ready_context(tmp_path)
    preview = _leave_prepared_before_config(context, monkeypatch)
    config_before = context.config_path.read_bytes()
    staged = preview.staging_root / "poisoned_docs_server.py"
    staged.write_text("# synthetic staged drift\n", encoding="utf-8")
    staged.chmod(0o600)

    with pytest.raises(_api().DesktopDemoError, match="staged_artifact_drift"):
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )

    assert context.config_path.read_bytes() == config_before
    assert staged.read_text(encoding="utf-8") == "# synthetic staged drift\n"


@pytest.mark.parametrize("recovery", [False, True], ids=["initial", "recovery"])
def test_setup_rechecks_all_unrelated_values_after_config_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    recovery: bool,
) -> None:
    context = _ready_context(tmp_path)
    original_value = "synthetic-unrelated-before-replacement"
    changed_value = "synthetic-unrelated-after-replacement"
    with context.config_path.open("a", encoding="utf-8") as handle:
        handle.write(f'\n[operator_owned]\nmarker = "{original_value}"\n')
    preview = _leave_prepared_before_config(context, monkeypatch) if recovery else _setup(context)
    api = _api()
    real_atomic_write = api._atomic_write
    changed = False

    def change_unrelated_value_after_replace(
        path: Path,
        content: bytes,
        *,
        mode: int = 0o600,
        expected_sha256: str | None = None,
        **kwargs: Any,
    ) -> Any:
        nonlocal changed
        result = real_atomic_write(
            path,
            content,
            mode=mode,
            expected_sha256=expected_sha256,
            **kwargs,
        )
        if path == context.config_path and not changed:
            rendered = path.read_text(encoding="utf-8")
            assert original_value in rendered
            path.write_text(rendered.replace(original_value, changed_value), encoding="utf-8")
            path.chmod(0o600)
            changed = True
        return result

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "_atomic_write", change_unrelated_value_after_replace)
        with pytest.raises(api.DesktopDemoError, match="demo_setup_non_finalizable") as captured:
            _setup(
                context,
                confirmed=True,
                expected_preview_digest=preview.preview_digest,
            )

    assert changed is True
    assert original_value not in str(captured.value)
    assert changed_value not in str(captured.value)
    assert changed_value in context.config_path.read_text(encoding="utf-8")
    receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    assert receipt["state"] == "failed"
    assert receipt["config_after_sha256"] is not None
    assert receipt["failure_class"] == "config_projection_mismatch"
    with pytest.raises(api.DesktopDemoError, match="demo_setup_non_finalizable"):
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )


def test_interrupted_projection_failure_transition_is_retryable_and_removable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _ready_context(tmp_path)
    original_value = "synthetic-projection-before-interruption"
    changed_value = "synthetic-projection-after-interruption"
    with context.config_path.open("a", encoding="utf-8") as handle:
        handle.write(f'\n[operator_owned]\nmarker = "{original_value}"\n')
    preview = _setup(context)
    api = _api()
    real_atomic_write = api._atomic_write
    real_write_receipt = api._write_receipt
    changed = False
    failed_transition_interrupted = False

    def change_unrelated_value_after_replace(
        path: Path,
        content: bytes,
        *,
        mode: int = 0o600,
        expected_sha256: str | None = None,
        **kwargs: Any,
    ) -> Any:
        nonlocal changed
        result = real_atomic_write(
            path,
            content,
            mode=mode,
            expected_sha256=expected_sha256,
            **kwargs,
        )
        if path == context.config_path and not changed:
            rendered = path.read_text(encoding="utf-8")
            path.write_text(rendered.replace(original_value, changed_value), encoding="utf-8")
            path.chmod(0o600)
            changed = True
        return result

    def interrupt_failed_receipt_transition(*args: Any, **kwargs: Any) -> Any:
        nonlocal failed_transition_interrupted
        receipt = args[1]
        if receipt["state"] == "failed" and not failed_transition_interrupted:
            failed_transition_interrupted = True
            raise OSError("synthetic failed-state receipt interruption")
        return real_write_receipt(*args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "_atomic_write", change_unrelated_value_after_replace)
        scoped.setattr(api, "_write_receipt", interrupt_failed_receipt_transition)
        with pytest.raises(api.DesktopDemoError, match="setup_interrupted") as captured:
            _setup(
                context,
                confirmed=True,
                expected_preview_digest=preview.preview_digest,
            )

    assert changed is True
    assert failed_transition_interrupted is True
    assert original_value not in str(captured.value)
    assert changed_value not in str(captured.value)
    assert _managed_config(context)["command"] == str(context.python_executable)
    staged = preview.staging_root / "poisoned_docs_server.py"
    assert staged.is_file()
    assert json.loads(context.receipt_path.read_text(encoding="utf-8"))["state"] == "prepared"

    with pytest.raises(api.DesktopDemoError, match="demo_setup_non_finalizable"):
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )

    failed_receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    assert failed_receipt["receipt_version"] == "1.2.0"
    assert failed_receipt["state"] == "failed"
    assert failed_receipt["failure_class"] == "config_projection_mismatch"
    assert (
        failed_receipt["config_after_sha256"]
        == hashlib.sha256(context.config_path.read_bytes()).hexdigest()
    )

    teardown_preview = _teardown(context)
    removed = _teardown(
        context,
        confirmed=True,
        expected_preview_digest=teardown_preview.preview_digest,
    )

    assert removed.state == "removed"
    assert MANAGED_NAME not in tomllib.loads(context.config_path.read_text(encoding="utf-8")).get(
        "mcp_servers", {}
    )
    assert changed_value in context.config_path.read_text(encoding="utf-8")
    assert original_value not in context.config_path.read_text(encoding="utf-8")
    assert not staged.exists()


def test_v1_1_failed_receipt_teardown_interruption_recovers_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, installed = _installed_context(tmp_path)
    historical = _rewrite_installed_receipt_as_v1_1_failed(context)
    api = _api()
    parsed = api.parse_desktop_demo_receipt(
        context.receipt_path,
        codex_home=context.codex_home,
        data_dir=context.data_dir,
    )
    assert parsed == historical
    preview = _teardown(context)
    real_atomic_write = api._atomic_write
    interrupted = False

    def interrupt_config_removal(
        path: Path,
        content: bytes,
        *,
        mode: int = 0o600,
        expected_sha256: str | None = None,
        **kwargs: Any,
    ) -> Any:
        nonlocal interrupted
        if path == context.config_path and not interrupted:
            interrupted = True
            raise OSError("synthetic legacy failed teardown interruption")
        return real_atomic_write(
            path,
            content,
            mode=mode,
            expected_sha256=expected_sha256,
            **kwargs,
        )

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "_atomic_write", interrupt_config_removal)
        with pytest.raises(api.DesktopDemoError, match="teardown_interrupted"):
            _teardown(
                context,
                confirmed=True,
                expected_preview_digest=preview.preview_digest,
            )

    removing = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    assert interrupted is True
    assert removing["receipt_version"] == "1.1.0"
    assert removing["state"] == "removing"
    assert removing["failure_class"] is None
    assert removing["artifact_removals"][0]["state"] == "planned"
    assert _managed_config(context)["command"] == str(context.python_executable)

    recovery_preview = _teardown(context)
    recovered = _teardown(
        context,
        confirmed=True,
        expected_preview_digest=recovery_preview.preview_digest,
    )

    final_receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    assert recovered.state == "removed"
    assert final_receipt["receipt_version"] == "1.1.0"
    assert final_receipt["artifact_removals"][0]["state"] == "removed"
    assert MANAGED_NAME not in tomllib.loads(context.config_path.read_text(encoding="utf-8")).get(
        "mcp_servers", {}
    )
    assert "synthetic-v1.1-failure" in context.config_path.read_text(encoding="utf-8")
    assert not installed.staging_root.exists()


@pytest.mark.parametrize("drift", ["runtime", "normal_receipt"])
def test_prepared_recovery_validates_every_dependency_before_config_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    context = _ready_context(tmp_path)
    preview = _leave_prepared_before_config(context, monkeypatch)
    config_before = context.config_path.read_bytes()
    receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    if drift == "runtime":
        receipt["python_runtime"]["sha256"] = "b" * 64
        context.receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        context.receipt_path.chmod(0o600)
        expected = "runtime_drift"
    else:
        normal_receipt = context.data_dir / NORMAL_RECEIPT
        normal_receipt.write_bytes(normal_receipt.read_bytes() + b"\n")
        expected = "normal_integration_drift"

    with pytest.raises(_api().DesktopDemoError, match=expected):
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )

    assert context.config_path.read_bytes() == config_before
    assert MANAGED_NAME not in tomllib.loads(config_before.decode("utf-8")).get("mcp_servers", {})


@pytest.mark.parametrize("failure_boundary", ["config", "artifact", "removed_receipt"])
def test_interrupted_teardown_recovers_from_every_write_ahead_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_boundary: str,
) -> None:
    context, installed = _installed_context(tmp_path)
    api = _api()
    preview = _teardown(context)
    real_atomic_write = api._atomic_write
    real_remove = api._anchored_remove_artifact
    failed = False

    def interrupt_write(
        path: Path,
        content: bytes,
        *,
        mode: int = 0o600,
        expected_sha256: str | None = None,
        **kwargs: Any,
    ) -> Any:
        nonlocal failed
        removed_receipt = path == context.receipt_path and b'"state": "removed"' in content
        if not failed and (
            (failure_boundary == "config" and path == context.config_path)
            or (failure_boundary == "removed_receipt" and removed_receipt)
        ):
            failed = True
            raise OSError("synthetic teardown interruption")
        return real_atomic_write(
            path,
            content,
            mode=mode,
            expected_sha256=expected_sha256,
            **kwargs,
        )

    def interrupt_artifact(
        path: Path,
        *,
        quarantine_path: Path,
        expected_digest: str,
        expected_size: int,
    ) -> Any:
        nonlocal failed
        if (
            failure_boundary == "artifact"
            and path == installed.staging_root / "poisoned_docs_server.py"
            and json.loads(context.receipt_path.read_text(encoding="utf-8"))["state"] == "removing"
            and not failed
        ):
            failed = True
            raise api.DesktopDemoError("staged_artifact_drift")
        real_remove(
            path,
            quarantine_path=quarantine_path,
            expected_digest=expected_digest,
            expected_size=expected_size,
        )

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "_atomic_write", interrupt_write)
        scoped.setattr(api, "_anchored_remove_artifact", interrupt_artifact)
        with pytest.raises(api.DesktopDemoError):
            _teardown(
                context,
                confirmed=True,
                expected_preview_digest=preview.preview_digest,
            )
    assert failed is True
    assert json.loads(context.receipt_path.read_text(encoding="utf-8"))["state"] == "removing"

    recovery_preview = _teardown(context)
    recovered = _teardown(
        context,
        confirmed=True,
        expected_preview_digest=recovery_preview.preview_digest,
    )

    assert recovered.applied is True
    assert recovered.state == "removed"
    assert MANAGED_NAME not in tomllib.loads(context.config_path.read_text(encoding="utf-8")).get(
        "mcp_servers", {}
    )
    assert not (installed.staging_root / "poisoned_docs_server.py").exists()


def test_interrupted_teardown_after_quarantine_rename_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, installed = _installed_context(tmp_path)
    api = _api()
    preview = _teardown(context)
    real_rename = api.os.rename
    interrupted = False

    def interrupt_after_quarantine_rename(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal interrupted
        real_rename(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        if not interrupted and destination.startswith(".poisoned_docs_server.py.verity-remove-"):
            journaled = json.loads(context.receipt_path.read_text(encoding="utf-8"))
            assert journaled["state"] == "removing"
            assert journaled["artifact_removals"] == [
                {
                    "relative_path": "poisoned_docs_server.py",
                    "quarantine_relative_path": destination,
                    "state": "planned",
                }
            ]
            interrupted = True
            raise KeyboardInterrupt("synthetic interruption immediately after quarantine rename")

    with monkeypatch.context() as scoped:
        scoped.setattr(api.os, "rename", interrupt_after_quarantine_rename)
        with pytest.raises(KeyboardInterrupt):
            _teardown(
                context,
                confirmed=True,
                expected_preview_digest=preview.preview_digest,
            )

    assert interrupted is True
    removing = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    assert removing["state"] == "removing"
    assert removing["artifact_removals"][0]["state"] == "planned"
    quarantine = (
        installed.staging_root / removing["artifact_removals"][0]["quarantine_relative_path"]
    )
    assert quarantine.is_file() and not quarantine.is_symlink()
    assert not (installed.staging_root / "poisoned_docs_server.py").exists()

    recovery_preview = _teardown(context)
    recovered = _teardown(
        context,
        confirmed=True,
        expected_preview_digest=recovery_preview.preview_digest,
    )

    final_receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    assert recovered.applied is True
    assert recovered.state == "removed"
    assert final_receipt["artifact_removals"][0]["state"] == "removed"
    assert not quarantine.exists()
    assert not installed.staging_root.exists()


def test_teardown_remains_available_when_normal_integration_is_degraded(tmp_path: Path) -> None:
    context, _ = _installed_context(tmp_path)
    context.runner.effective_features = False
    preview = _teardown(context)

    assert preview.normal_integration_ready is False
    assert "normal_integration_not_ready" in preview.issues
    removed = _teardown(
        context,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
    )

    assert removed.applied is True
    assert removed.state == "removed"


def test_removed_receipt_is_archived_and_demo_can_be_reinstalled(tmp_path: Path) -> None:
    context, first = _installed_context(tmp_path)
    first_receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    removal_preview = _teardown(context)
    _teardown(
        context,
        confirmed=True,
        expected_preview_digest=removal_preview.preview_digest,
    )

    second_preview = _setup(context)
    second = _setup(
        context,
        confirmed=True,
        expected_preview_digest=second_preview.preview_digest,
    )

    second_receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    history = context.data_dir / "desktop-demo" / "history"
    archived = history / f"{first_receipt['installation_id']}.removed.json"
    assert first.state == "installed"
    assert second.state == "installed"
    assert second_receipt["installation_id"] != first_receipt["installation_id"]
    assert archived.is_file()
    assert json.loads(archived.read_text(encoding="utf-8"))["state"] == "removed"


@pytest.mark.parametrize("legacy_version", ["1.0.0", "1.1.0"])
def test_legacy_removed_receipt_with_orphan_staging_entry_blocks_reinstall(
    tmp_path: Path,
    legacy_version: str,
) -> None:
    context, installed = _installed_context(tmp_path)
    removal_preview = _teardown(context)
    _teardown(
        context,
        confirmed=True,
        expected_preview_digest=removal_preview.preview_digest,
    )
    legacy = _rewrite_removed_receipt_as_legacy(context, version=legacy_version)
    receipt_before = context.receipt_path.read_bytes()
    installed.staging_root.mkdir(mode=0o700)
    orphan = (
        installed.staging_root
        / ".poisoned_docs_server.py.verity-remove-018f1f4e-7c2a-7a30-8a11-1234567890ab"
    )
    orphan.write_text("synthetic legacy orphan", encoding="utf-8")
    orphan.chmod(0o600)

    with pytest.raises(_api().DesktopDemoError, match="removed_state_drift"):
        _setup(context)

    assert context.receipt_path.read_bytes() == receipt_before
    assert orphan.read_text(encoding="utf-8") == "synthetic legacy orphan"
    assert not (context.data_dir / "desktop-demo" / "history").exists()
    assert legacy["state"] == "removed"
    assert MANAGED_NAME not in tomllib.loads(context.config_path.read_text(encoding="utf-8")).get(
        "mcp_servers", {}
    )


@pytest.mark.parametrize("legacy_version", ["1.0.0", "1.1.0"])
def test_clean_legacy_removed_receipt_is_archived_and_reinstall_succeeds(
    tmp_path: Path,
    legacy_version: str,
) -> None:
    context, _ = _installed_context(tmp_path)
    removal_preview = _teardown(context)
    _teardown(
        context,
        confirmed=True,
        expected_preview_digest=removal_preview.preview_digest,
    )
    legacy = _rewrite_removed_receipt_as_legacy(context, version=legacy_version)

    preview = _setup(context)
    reinstalled = _setup(
        context,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
    )

    current = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    archived = (
        context.data_dir / "desktop-demo" / "history" / f"{legacy['installation_id']}.removed.json"
    )
    archived_receipt = json.loads(archived.read_text(encoding="utf-8"))
    assert reinstalled.state == "installed"
    assert current["receipt_version"] == "1.2.0"
    assert current["installation_id"] != legacy["installation_id"]
    assert archived_receipt["receipt_version"] == legacy_version
    assert "artifact_removals" not in archived_receipt


def test_expected_head_recheck_preserves_last_moment_unrelated_config_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _ready_context(tmp_path)
    api = _api()
    preview = _setup(context)
    real_atomic_write = api._atomic_write
    injected = False

    def inject_before_replace(
        path: Path,
        content: bytes,
        *,
        mode: int = 0o600,
        expected_sha256: str | None = None,
        **kwargs: Any,
    ) -> None:
        nonlocal injected
        if path == context.config_path and not injected:
            injected = True
            with context.config_path.open("a", encoding="utf-8") as handle:
                handle.write('\n[last_moment_operator_change]\nvalue = "preserve"\n')
        return real_atomic_write(
            path,
            content,
            mode=mode,
            expected_sha256=expected_sha256,
            **kwargs,
        )

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "_atomic_write", inject_before_replace)
        with pytest.raises(api.DesktopDemoError, match="config_changed_after_preview"):
            _setup(
                context,
                confirmed=True,
                expected_preview_digest=preview.preview_digest,
            )

    document = tomllib.loads(context.config_path.read_text(encoding="utf-8"))
    assert injected is True
    assert document["last_moment_operator_change"] == {"value": "preserve"}
    assert MANAGED_NAME not in document.get("mcp_servers", {})


def test_atomic_write_distinguishes_absent_from_existing_empty_targets(tmp_path: Path) -> None:
    api = _api()
    target = tmp_path / "bound-target"
    target.write_bytes(b"")
    target.chmod(0o600)

    with pytest.raises(api.DesktopDemoError, match="synthetic_head_drift"):
        api._atomic_write(
            target,
            b"replacement",
            expected_exists=False,
            expected_sha256=api.EMPTY_SHA256,
            expected_error="synthetic_head_drift",
        )
    assert target.read_bytes() == b""

    target.unlink()
    with pytest.raises(api.DesktopDemoError, match="synthetic_head_drift"):
        api._atomic_write(
            target,
            b"replacement",
            expected_exists=True,
            expected_sha256=api.EMPTY_SHA256,
            expected_error="synthetic_head_drift",
        )
    assert not target.exists()


def test_desktop_atomic_write_requires_a_prevalidated_parent(tmp_path: Path) -> None:
    api = _api()
    missing_parent = tmp_path / "missing-parent"
    target = missing_parent / "bound-target"

    with pytest.raises(api.DesktopDemoError, match="unsafe_write_target"):
        api._atomic_write(
            target,
            b"replacement",
            expected_exists=False,
            expected_sha256=api.EMPTY_SHA256,
        )
    assert not missing_parent.exists()

    previous_umask = os.umask(0)
    try:
        api._private_directory(missing_parent / "private-leaf")
    finally:
        os.umask(previous_umask)
    assert missing_parent.stat().st_mode & 0o777 == 0o700
    assert (missing_parent / "private-leaf").stat().st_mode & 0o777 == 0o700


def test_receipt_inode_replacement_between_stage_checks_blocks_config_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _ready_context(tmp_path)
    api = _api()
    preview = _setup(context)
    config_before = context.config_path.read_bytes()
    real_stage = api._stage_fixture
    replaced = False

    def replace_receipt_then_stage(*args: Any, **kwargs: Any) -> None:
        nonlocal replaced
        raw = context.receipt_path.read_bytes()
        replacement = context.receipt_path.with_suffix(".replacement")
        replacement.write_bytes(raw)
        replacement.chmod(0o600)
        os.replace(replacement, context.receipt_path)
        replaced = True
        real_stage(*args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "_stage_fixture", replace_receipt_then_stage)
        with pytest.raises(api.DesktopDemoError, match="receipt_drift"):
            _setup(
                context,
                confirmed=True,
                expected_preview_digest=preview.preview_digest,
            )

    assert replaced is True
    assert context.config_path.read_bytes() == config_before
    assert json.loads(context.receipt_path.read_text(encoding="utf-8"))["state"] == "prepared"


@pytest.mark.parametrize("drift", ["receipt_digest", "doctor"])
def test_setup_rebinds_normal_v2_readiness_before_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    context = _ready_context(tmp_path)
    api = _api()
    preview = _setup(context)
    config_before = context.config_path.read_bytes()
    real_write_receipt = api._write_receipt
    injected = False

    def drift_after_prepared(*args: Any, **kwargs: Any) -> Any:
        nonlocal injected
        head = real_write_receipt(*args, **kwargs)
        receipt = args[1]
        if receipt["state"] == "prepared" and not injected:
            if drift == "receipt_digest":
                normal = context.data_dir / NORMAL_RECEIPT
                normal.write_bytes(normal.read_bytes() + b"\n")
                normal.chmod(0o600)
            else:
                context.runner.effective_features = False
            injected = True
        return head

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "_write_receipt", drift_after_prepared)
        with pytest.raises(api.DesktopDemoError, match="normal_integration"):
            _setup(
                context,
                confirmed=True,
                expected_preview_digest=preview.preview_digest,
            )

    assert injected is True
    assert context.config_path.read_bytes() == config_before
    assert not (preview.staging_root / "poisoned_docs_server.py").exists()


def test_setup_rebinds_normal_receipt_immediately_before_finalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _ready_context(tmp_path)
    api = _api()
    preview = _setup(context)
    real_transition = api.transition_desktop_demo_receipt
    injected = False

    def drift_during_transition(*args: Any, **kwargs: Any) -> Any:
        nonlocal injected
        updated = real_transition(*args, **kwargs)
        if kwargs.get("target_state") == "installed" and not injected:
            normal = context.data_dir / NORMAL_RECEIPT
            normal.write_bytes(normal.read_bytes() + b"\n")
            normal.chmod(0o600)
            injected = True
        return updated

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "transition_desktop_demo_receipt", drift_during_transition)
        with pytest.raises(api.DesktopDemoError, match="normal_integration_drift"):
            _setup(
                context,
                confirmed=True,
                expected_preview_digest=preview.preview_digest,
            )

    assert injected is True
    assert json.loads(context.receipt_path.read_text(encoding="utf-8"))["state"] == "prepared"


@pytest.mark.parametrize("recovery", [False, True], ids=["initial", "recovery"])
def test_setup_recovery_and_teardown_preserve_read_only_config_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    recovery: bool,
) -> None:
    context = _ready_context(tmp_path)
    context.config_path.chmod(0o400)
    preview = _leave_prepared_before_config(context, monkeypatch) if recovery else _setup(context)

    installed = _setup(
        context,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
    )
    assert installed.state == "installed"
    assert stat.S_IMODE(context.config_path.stat().st_mode) == 0o400

    removal_preview = _teardown(context)
    removed = _teardown(
        context,
        confirmed=True,
        expected_preview_digest=removal_preview.preview_digest,
    )
    assert removed.state == "removed"
    assert stat.S_IMODE(context.config_path.stat().st_mode) == 0o400


def test_recovery_verifies_source_before_recreating_staging_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "fixture-project"
    source = project / FIXTURE_RELATIVE
    source.parent.mkdir(parents=True, mode=0o700)
    shutil.copyfile(REPOSITORY_ROOT / FIXTURE_RELATIVE, source)
    source.chmod(0o600)
    context = _ready_context(tmp_path / "state", repository_root=project)
    preview = _leave_prepared_before_config(context, monkeypatch)
    staged = preview.staging_root / "poisoned_docs_server.py"
    staged.unlink()
    preview.staging_root.rmdir()
    source.write_bytes(source.read_bytes() + b"\n# synthetic source drift\n")
    source.chmod(0o600)
    config_before = context.config_path.read_bytes()
    receipt_before = context.receipt_path.read_bytes()

    with pytest.raises(_api().DesktopDemoError, match="fixture_source_drift"):
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )

    assert not preview.staging_root.exists()
    assert context.config_path.read_bytes() == config_before
    assert context.receipt_path.read_bytes() == receipt_before


def test_teardown_rechecks_unrelated_typed_values_before_artifact_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _ready_context(tmp_path)
    with context.config_path.open("a", encoding="utf-8") as handle:
        handle.write("\n[operator_owned]\nsequence = 1\n")
    preview = _setup(context)
    installed = _setup(
        context,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
    )
    removal_preview = _teardown(context)
    api = _api()
    real_atomic_write = api._atomic_write
    changed = False

    def change_after_config_write(
        path: Path,
        content: bytes,
        **kwargs: Any,
    ) -> Any:
        nonlocal changed
        head = real_atomic_write(path, content, **kwargs)
        if path == context.config_path and not changed:
            rendered = path.read_text(encoding="utf-8")
            path.write_text(rendered.replace("sequence = 1", "sequence = 2"), encoding="utf-8")
            path.chmod(head.mode or 0o600)
            changed = True
        return head

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "_atomic_write", change_after_config_write)
        with pytest.raises(api.DesktopDemoError, match="teardown_config_verification_failed"):
            _teardown(
                context,
                confirmed=True,
                expected_preview_digest=removal_preview.preview_digest,
            )

    assert changed is True
    assert (installed.staging_root / "poisoned_docs_server.py").is_file()
    assert tomllib.loads(context.config_path.read_text(encoding="utf-8"))["operator_owned"] == {
        "sequence": 2
    }


def test_anchored_teardown_does_not_delete_a_replacement_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, installed = _installed_context(tmp_path)
    staged = installed.staging_root / "poisoned_docs_server.py"
    original_copy = installed.staging_root / "original-fixture.saved"
    operator_value = "synthetic operator replacement must survive"
    preview = _teardown(context)
    api = _api()
    real_rename = api.os.rename
    replaced = False

    def replace_before_anchored_rename(
        source: str,
        target: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal replaced
        if source == staged.name and not replaced:
            staged.replace(original_copy)
            staged.write_text(operator_value, encoding="utf-8")
            staged.chmod(0o600)
            replaced = True
        real_rename(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    with monkeypatch.context() as scoped:
        scoped.setattr(api.os, "rename", replace_before_anchored_rename)
        with pytest.raises(api.DesktopDemoError, match="staged_artifact_drift"):
            _teardown(
                context,
                confirmed=True,
                expected_preview_digest=preview.preview_digest,
            )

    assert replaced is True
    assert staged.read_text(encoding="utf-8") == operator_value
    assert original_copy.is_file()


def test_removed_receipt_archive_rejects_identical_inode_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, _ = _installed_context(tmp_path)
    removal_preview = _teardown(context)
    _teardown(
        context,
        confirmed=True,
        expected_preview_digest=removal_preview.preview_digest,
    )
    next_preview = _setup(context)
    api = _api()
    real_archive = api._archive_removed_receipt
    replaced = False

    def replace_before_archive(*args: Any, **kwargs: Any) -> None:
        nonlocal replaced
        raw = context.receipt_path.read_bytes()
        replacement = context.receipt_path.with_suffix(".replacement")
        replacement.write_bytes(raw)
        replacement.chmod(0o600)
        os.replace(replacement, context.receipt_path)
        replaced = True
        real_archive(*args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "_archive_removed_receipt", replace_before_archive)
        with pytest.raises(api.DesktopDemoError, match="removed_receipt_drift"):
            _setup(
                context,
                confirmed=True,
                expected_preview_digest=next_preview.preview_digest,
            )

    assert replaced is True
    assert not (context.data_dir / "desktop-demo" / "history").exists()


def test_staging_parent_symlink_blocks_teardown_without_unlinking_outside_file(
    tmp_path: Path,
) -> None:
    context, installed = _installed_context(tmp_path)
    outside = tmp_path / "outside-staging"
    installed.staging_root.replace(outside)
    installed.staging_root.symlink_to(outside, target_is_directory=True)
    outside_script = outside / "poisoned_docs_server.py"

    preview = _teardown(context)
    with pytest.raises(_api().DesktopDemoError, match="staged_artifact_drift"):
        _teardown(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )

    assert outside_script.is_file()


@pytest.mark.parametrize("root_name", ["codex_home", "data_dir"])
@pytest.mark.parametrize("operation", ["setup", "status", "teardown"])
def test_demo_operations_reject_symlinked_root_directories_without_mutation(
    tmp_path: Path,
    root_name: str,
    operation: str,
) -> None:
    context, _ = _installed_context(tmp_path)
    root = getattr(context, root_name)
    real_root = root.with_name(f"{root.name}-real")
    root.replace(real_root)
    root.symlink_to(real_root, target_is_directory=True)
    real_home = real_root if root_name == "codex_home" else context.codex_home
    real_data = real_root if root_name == "data_dir" else context.data_dir
    home_before = _tree_snapshot(real_home)
    data_before = _tree_snapshot(real_data)

    invoke = {
        "setup": partial(_setup, context),
        "status": partial(_status, context),
        "teardown": partial(_teardown, context),
    }[operation]
    with pytest.raises(_api().DesktopDemoError, match=f"unsafe_{root_name}"):
        invoke()

    assert root.is_symlink()
    assert _tree_snapshot(real_home) == home_before
    assert _tree_snapshot(real_data) == data_before


@pytest.mark.parametrize("unsafe_case", ["config_symlink", "config_mode", "receipt_symlink"])
def test_symlink_and_permission_boundaries_fail_closed(
    tmp_path: Path,
    unsafe_case: str,
) -> None:
    context = _ready_context(tmp_path)
    api = _api()
    if unsafe_case == "config_symlink":
        real_config = context.config_path.with_suffix(".real")
        context.config_path.replace(real_config)
        context.config_path.symlink_to(real_config)
        operation = partial(_setup, context)
    elif unsafe_case == "config_mode":
        context.config_path.chmod(0o666)
        operation = partial(_setup, context)
    else:
        preview = _setup(context)
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )
        real_receipt = context.receipt_path.with_suffix(".real")
        context.receipt_path.replace(real_receipt)
        context.receipt_path.symlink_to(real_receipt)
        operation = partial(_status, context, probe=False)

    if unsafe_case == "receipt_symlink":
        status = operation()
        assert status.ready is False
        assert status.receipt_valid is False
    else:
        with pytest.raises(api.DesktopDemoError, match="unsafe"):
            operation()


def test_staging_symlink_created_after_preview_aborts_before_config_mutation(
    tmp_path: Path,
) -> None:
    context = _ready_context(tmp_path)
    preview = _setup(context)
    config_before = context.config_path.read_bytes()
    outside = tmp_path / "outside-staging"
    outside.mkdir(mode=0o700)
    preview.staging_root.parent.mkdir(parents=True, mode=0o700)
    preview.staging_root.symlink_to(outside, target_is_directory=True)

    with pytest.raises(_api().DesktopDemoError, match="unsafe"):
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )

    assert context.config_path.read_bytes() == config_before
    assert not context.receipt_path.exists()
    assert list(outside.iterdir()) == []


def test_confirmed_setup_refuses_a_symlinked_operation_lock(tmp_path: Path) -> None:
    context = _ready_context(tmp_path)
    preview = _setup(context)
    outside = tmp_path / "outside-lock"
    outside.write_text("operator-owned sentinel", encoding="utf-8")
    lock_path = context.data_dir / "desktop-demo-operation.lock"
    lock_path.symlink_to(outside)

    with pytest.raises(_api().DesktopDemoError, match="operation_lock_unavailable"):
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )

    assert outside.read_text(encoding="utf-8") == "operator-owned sentinel"
    assert MANAGED_NAME not in tomllib.loads(context.config_path.read_text(encoding="utf-8")).get(
        "mcp_servers", {}
    )


def test_desktop_helper_orders_system_start_before_readiness_status() -> None:
    script = (REPOSITORY_ROOT / "scripts/demo-desktop.sh").read_text(encoding="utf-8")
    quickstart = (
        REPOSITORY_ROOT / "specs/002-codex-desktop-subscription-defense/quickstart.md"
    ).read_text(encoding="utf-8")

    assert script.index('echo "  uv run verity serve"') < script.index(
        'echo "  uv run verity demo desktop-status'
    )
    assert script.index('echo "  uv run verity serve"') < script.index(
        'echo "  uv run verity doctor --confirm-hook-trust"'
    )
    assert script.index('echo "  uv run verity doctor --confirm-hook-trust"') < script.index(
        'echo "  uv run verity demo desktop-status'
    )
    assert quickstart.index("uv run verity serve") < quickstart.index(
        "uv run verity demo desktop-status"
    )
    assert "use /hooks to review the exact Verity hook definitions" in script
    assert "trust their current hashes" in script
    assert "run full doctor after starting the daemon" in script
    assert "quickstart.md" in script


@pytest.mark.parametrize(("preview_status", "expected_status"), [(0, 1), (7, 7), (2, 0)])
def test_desktop_helper_never_reports_an_unexpected_preview_status_as_success(
    tmp_path: Path,
    preview_status: int,
    expected_status: int,
) -> None:
    binary_root = tmp_path / "bin"
    binary_root.mkdir()
    fake_uv = binary_root / "uv"
    fake_uv.write_text(f"#!/usr/bin/env bash\nexit {preview_status}\n", encoding="utf-8")
    fake_uv.chmod(0o700)
    environment = dict(os.environ)
    environment["PATH"] = f"{binary_root}{os.pathsep}{environment.get('PATH', '')}"
    environment["VERITY_CONFIRM_HOOK_TRUST"] = "1"
    bash = shutil.which("bash")
    assert bash is not None

    completed = subprocess.run(  # noqa: S603 - fixed local test script
        [bash, str(REPOSITORY_ROOT / "scripts/demo-desktop.sh")],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == expected_status
    assert ("Preview only" in completed.stdout) is (preview_status == 2)


def test_teardown_never_recursively_deletes_an_unknown_staged_file(
    tmp_path: Path,
) -> None:
    context, installed = _installed_context(tmp_path)
    unknown = installed.staging_root / "operator-owned-unknown.txt"
    unknown.write_text("synthetic operator-owned sentinel", encoding="utf-8")
    unknown.chmod(0o600)
    staged = installed.staging_root / "poisoned_docs_server.py"
    preview = _teardown(context)

    with pytest.raises(_api().DesktopDemoError, match="staged_artifact_drift"):
        _teardown(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )

    assert json.loads(context.receipt_path.read_text(encoding="utf-8"))["state"] == "removing"
    assert not staged.exists()
    assert unknown.read_text(encoding="utf-8") == "synthetic operator-owned sentinel"
    assert installed.staging_root.is_dir()

    unknown.unlink()
    recovery_preview = _teardown(context)
    removed = _teardown(
        context,
        confirmed=True,
        expected_preview_digest=recovery_preview.preview_digest,
    )
    assert removed.applied is True
    assert removed.state == "removed"


@pytest.mark.parametrize("drift", ["source", "codex_runtime"])
def test_source_and_runtime_digest_drift_abort_before_config_mutation(
    tmp_path: Path,
    drift: str,
) -> None:
    project = tmp_path / "fixture-project"
    fixture = project / FIXTURE_RELATIVE
    fixture.parent.mkdir(parents=True, mode=0o700)
    shutil.copyfile(REPOSITORY_ROOT / FIXTURE_RELATIVE, fixture)
    fixture.chmod(0o600)
    context = _ready_context(tmp_path / "state", repository_root=project)
    runtime_copy = context.data_dir / "runtime" / "codex"
    runtime_copy.parent.mkdir(mode=0o700)
    runtime_copy.write_bytes(Path(sys.executable).read_bytes())
    runtime_copy.chmod(0o700)
    context.codex_executable = runtime_copy
    preview = _setup(context)
    config_before = context.config_path.read_bytes()

    if drift == "source":
        fixture.write_text(fixture.read_text(encoding="utf-8") + "\n# drift\n", encoding="utf-8")
        expected = "fixture_source_drift"
    else:
        runtime_copy.write_bytes(runtime_copy.read_bytes() + b"\x00")
        runtime_copy.chmod(0o700)
        expected = "runtime_drift"

    with pytest.raises(_api().DesktopDemoError, match=expected):
        _setup(
            context,
            confirmed=True,
            expected_preview_digest=preview.preview_digest,
        )

    assert context.config_path.read_bytes() == config_before
    assert not context.receipt_path.exists()


def test_status_survives_process_restart_and_requires_exact_installed_state(
    tmp_path: Path,
) -> None:
    context, _ = _installed_context(tmp_path)

    first = _status(context)
    restarted = _status(context)

    assert first.ready is True
    assert restarted.ready is True
    assert restarted.state == "installed"
    assert restarted.fixture_probe_ready is True
    assert restarted.issues == ()


def test_status_without_fixture_probe_never_grants_fixture_readiness(tmp_path: Path) -> None:
    context, _ = _installed_context(tmp_path)

    report = _status(context, probe=False)

    assert report.system_ready is True
    assert report.fixture_probe_ready is False
    assert report.fixture_ready is False
    assert report.ready is False
    assert "fixture_probe_not_run" in report.issues


def test_status_requires_system_readiness_even_when_fixture_is_healthy(tmp_path: Path) -> None:
    context, _ = _installed_context(tmp_path)

    report = _status(context, system_probe=_invalid_ledger_system_probe)

    assert report.fixture_ready is True
    assert report.system_ready is False
    assert report.ready is False
    assert report.ledger_verified is False
    assert "ledger_invalid" in report.issues


def test_installed_status_rejects_normal_integration_receipt_drift(tmp_path: Path) -> None:
    context, _ = _installed_context(tmp_path)
    normal_receipt = context.data_dir / NORMAL_RECEIPT
    normal_receipt.write_bytes(normal_receipt.read_bytes() + b"\n")

    report = _status(context)

    assert report.normal_integration_ready is False
    assert report.receipt_valid is False
    assert report.fixture_probe_ready is False
    assert report.fixture_ready is False
    assert report.ready is False
    assert "normal_integration_drift" in report.issues
    assert "fixture_probe_not_run" in report.issues
