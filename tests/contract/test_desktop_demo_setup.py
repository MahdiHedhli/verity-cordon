"""Security contract for reversible Codex Desktop demonstration setup."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import stat
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
    install_codex(
        REPOSITORY_ROOT,
        confirmed=True,
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
    ) -> None:
        nonlocal failed
        if path == context.config_path and not failed:
            failed = True
            raise OSError("synthetic prepared-state interruption")
        real_atomic_write(
            path,
            content,
            mode=mode,
            expected_sha256=expected_sha256,
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
    ) -> None:
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
        real_atomic_write(
            path,
            content,
            mode=mode,
            expected_sha256=expected_sha256,
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


@pytest.mark.parametrize("drift", ["missing_artifact", "runtime", "normal_receipt"])
def test_prepared_recovery_validates_every_dependency_before_config_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    context = _ready_context(tmp_path)
    preview = _leave_prepared_before_config(context, monkeypatch)
    config_before = context.config_path.read_bytes()
    receipt = json.loads(context.receipt_path.read_text(encoding="utf-8"))
    if drift == "missing_artifact":
        (preview.staging_root / "poisoned_docs_server.py").unlink()
        expected = "staged_artifact_drift"
    elif drift == "runtime":
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
    real_hash = api._hash_regular
    failed = False

    def interrupt_write(
        path: Path,
        content: bytes,
        *,
        mode: int = 0o600,
        expected_sha256: str | None = None,
    ) -> None:
        nonlocal failed
        removed_receipt = path == context.receipt_path and b'"state": "removed"' in content
        if not failed and (
            (failure_boundary == "config" and path == context.config_path)
            or (failure_boundary == "removed_receipt" and removed_receipt)
        ):
            failed = True
            raise OSError("synthetic teardown interruption")
        real_atomic_write(
            path,
            content,
            mode=mode,
            expected_sha256=expected_sha256,
        )

    def interrupt_artifact(path: Path, maximum: int, **kwargs: bool) -> tuple[str, int]:
        nonlocal failed
        if (
            failure_boundary == "artifact"
            and path == installed.staging_root / "poisoned_docs_server.py"
            and json.loads(context.receipt_path.read_text(encoding="utf-8"))["state"] == "removing"
            and not failed
        ):
            failed = True
            raise api.DesktopDemoError("staged_artifact_drift")
        return real_hash(path, maximum, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(api, "_atomic_write", interrupt_write)
        scoped.setattr(api, "_hash_regular", interrupt_artifact)
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
    ) -> None:
        nonlocal injected
        if path == context.config_path and not injected:
            injected = True
            with context.config_path.open("a", encoding="utf-8") as handle:
                handle.write('\n[last_moment_operator_change]\nvalue = "preserve"\n')
        real_atomic_write(
            path,
            content,
            mode=mode,
            expected_sha256=expected_sha256,
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
    assert quickstart.index("uv run verity serve") < quickstart.index(
        "uv run verity demo desktop-status"
    )


def test_teardown_never_recursively_deletes_an_unknown_staged_file(
    tmp_path: Path,
) -> None:
    context, installed = _installed_context(tmp_path)
    unknown = installed.staging_root / "operator-owned-unknown.txt"
    unknown.write_text("synthetic operator-owned sentinel", encoding="utf-8")
    unknown.chmod(0o600)
    staged = installed.staging_root / "poisoned_docs_server.py"
    preview = _teardown(context)

    removed = _teardown(
        context,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
    )

    assert removed.applied is True
    assert removed.state == "removed"
    assert not staged.exists()
    assert unknown.read_text(encoding="utf-8") == "synthetic operator-owned sentinel"
    assert installed.staging_root.is_dir()


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
