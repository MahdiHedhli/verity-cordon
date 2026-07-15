"""Contract tests for the private Codex Desktop demonstration receipt."""

from __future__ import annotations

import copy
import importlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

REPOSITORY_ROOT = Path(__file__).parents[2]
SCHEMA_PATH = (
    REPOSITORY_ROOT
    / "specs/002-codex-desktop-subscription-defense/contracts/desktop-demo-receipt.schema.json"
)
SHA256 = "a" * 64
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
CREATED_AT = "2026-07-15T12:00:00Z"
REMOVING_AT = "2026-07-15T12:05:00Z"
REMOVED_AT = "2026-07-15T12:06:00Z"


def _schema() -> dict[str, Any]:
    value = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def receipt_sample(root: Path, *, state: str = "prepared") -> dict[str, Any]:
    """Return one synthetic, schema-valid receipt for cross-test reuse."""

    codex_home = (root / "codex-home").resolve()
    data_dir = (root / "verity-data").resolve()
    staging_root = data_dir / "desktop-demo" / "fixture"
    config_after = None if state == "prepared" else SHA256
    teardown: dict[str, Any] = {
        "requested_at": None,
        "completed_at": None,
        "config_after_teardown_sha256": None,
    }
    if state == "removing":
        teardown["requested_at"] = REMOVING_AT
    elif state == "removed":
        teardown = {
            "requested_at": REMOVING_AT,
            "completed_at": REMOVED_AT,
            "config_after_teardown_sha256": SHA256,
        }
    return {
        "receipt_version": "1.0.0",
        "installation_id": "018f1f4e-7c2a-7a30-8a11-1234567890ab",
        "state": state,
        "operator_confirmed": True,
        "confirmation_method": "cli_yes",
        "preview_digest": SHA256,
        "confirmed_at": CREATED_AT,
        "created_at": CREATED_AT,
        "updated_at": (
            REMOVED_AT if state == "removed" else REMOVING_AT if state == "removing" else CREATED_AT
        ),
        "digest_algorithm": "SHA-256",
        "codex_home": str(codex_home),
        "config_path": str(codex_home / "config.toml"),
        "staging_root": str(staging_root),
        "config_existed_before": True,
        "config_before_sha256": SHA256,
        "config_after_sha256": config_after,
        "backup_path": None,
        "backup_sha256": None,
        "managed_entry_original": {
            "present": False,
            "digest": None,
            "parent_table_present": False,
        },
        "managed_entry": {
            "name": "verity_cordon_poisoned_docs",
            "canonicalization": "VC-TOML-MANAGED-1",
            "sha256": SHA256,
            "transport": "stdio",
            "command": str(Path(sys.executable).resolve()),
            "args": ["-I", str(staging_root / "poisoned_docs_server.py")],
            "cwd": str(staging_root),
            "enabled": True,
            "required": True,
            "startup_timeout_sec": 5,
            "tool_timeout_sec": 5,
            "enabled_tools": ["get_release_guidance", "demo_artifact_sink"],
            "default_tools_approval_mode": "writes",
            "tool_overrides": {"demo_artifact_sink": {"approval_mode": "prompt"}},
        },
        "codex_runtime": {
            "path": str(Path(sys.executable).resolve()),
            "sha256": SHA256,
            "version": "codex-cli 0.144.4",
            "size_bytes": 1024,
        },
        "python_runtime": {
            "path": str(Path(sys.executable).resolve()),
            "sha256": SHA256,
            "version": "Python 3.12.10",
            "size_bytes": 1024,
        },
        "artifacts": [
            {
                "relative_path": "poisoned_docs_server.py",
                "sha256": SHA256,
                "size_bytes": 4096,
                "file_mode": "0600",
            }
        ],
        "normal_integration": {
            "receipt_version": "1.0.0",
            "receipt_path": str(data_dir / "codex-integration-receipt.json"),
            "receipt_sha256": SHA256,
            "doctor_ready": True,
        },
        "teardown": teardown,
    }


@pytest.mark.parametrize("state", ["prepared", "installed", "removing", "removed"])
def test_receipt_schema_accepts_each_valid_write_ahead_state(
    tmp_path: Path,
    state: str,
) -> None:
    Draft202012Validator(
        _schema(),
        format_checker=FormatChecker(),
    ).validate(receipt_sample(tmp_path, state=state))


@pytest.mark.parametrize(
    ("state", "mutation"),
    [
        ("prepared", {"config_after_sha256": SHA256}),
        ("installed", {"config_after_sha256": None}),
        (
            "removing",
            {
                "teardown": {
                    "requested_at": None,
                    "completed_at": None,
                    "config_after_teardown_sha256": None,
                }
            },
        ),
        (
            "removed",
            {
                "teardown": {
                    "requested_at": REMOVING_AT,
                    "completed_at": None,
                    "config_after_teardown_sha256": None,
                }
            },
        ),
    ],
)
def test_receipt_schema_rejects_state_field_mismatches(
    tmp_path: Path,
    state: str,
    mutation: dict[str, Any],
) -> None:
    payload = receipt_sample(tmp_path, state=state)
    payload.update(mutation)
    errors = list(Draft202012Validator(_schema()).iter_errors(payload))
    assert errors


def test_receipt_schema_excludes_credentials_and_arbitrary_prior_mcp_content(
    tmp_path: Path,
) -> None:
    payload = receipt_sample(tmp_path, state="installed")
    payload["raw_existing_mcp_entry"] = {"env": {"TOKEN": "synthetic-must-not-persist"}}

    errors = list(Draft202012Validator(_schema()).iter_errors(payload))

    assert errors
    assert payload["managed_entry_original"] == {
        "present": False,
        "digest": None,
        "parent_table_present": False,
    }


def _demo_api() -> Any:
    return importlib.import_module("verity_cordon.codex.demo_installer")


def test_runtime_receipt_parser_rejects_duplicates_scope_escape_and_unsafe_mode(
    tmp_path: Path,
) -> None:
    api = _demo_api()
    data_dir = (tmp_path / "verity-data").resolve()
    codex_home = (tmp_path / "codex-home").resolve()
    data_dir.mkdir(mode=0o700)
    codex_home.mkdir(mode=0o700)
    receipt_path = data_dir / "desktop-demo-receipt.json"
    payload = receipt_sample(tmp_path, state="installed")
    raw = json.dumps(payload, separators=(",", ":")).encode()
    receipt_path.write_bytes(raw)
    receipt_path.chmod(0o600)

    parsed = api.parse_desktop_demo_receipt(
        receipt_path,
        codex_home=codex_home,
        data_dir=data_dir,
    )
    assert parsed == payload

    duplicate = raw[:-1] + b',"state":"removed"}'
    receipt_path.write_bytes(duplicate)
    with pytest.raises(api.DesktopDemoError, match="receipt_invalid"):
        api.parse_desktop_demo_receipt(
            receipt_path,
            codex_home=codex_home,
            data_dir=data_dir,
        )

    escaped = copy.deepcopy(payload)
    escaped["staging_root"] = str((tmp_path / "outside").resolve())
    receipt_path.write_text(json.dumps(escaped), encoding="utf-8")
    with pytest.raises(api.DesktopDemoError, match="receipt_scope_invalid"):
        api.parse_desktop_demo_receipt(
            receipt_path,
            codex_home=codex_home,
            data_dir=data_dir,
        )

    traversed_path = copy.deepcopy(payload)
    traversed_path["staging_root"] = str(
        data_dir / "desktop-demo" / ".." / "desktop-demo" / "fixture"
    )
    receipt_path.write_text(json.dumps(traversed_path), encoding="utf-8")
    with pytest.raises(api.DesktopDemoError, match="receipt_scope_invalid"):
        api.parse_desktop_demo_receipt(
            receipt_path,
            codex_home=codex_home,
            data_dir=data_dir,
        )

    receipt_path.write_bytes(raw)
    receipt_path.chmod(0o644)
    with pytest.raises(api.DesktopDemoError, match="receipt_permissions"):
        api.parse_desktop_demo_receipt(
            receipt_path,
            codex_home=codex_home,
            data_dir=data_dir,
        )


def test_runtime_receipt_state_machine_allows_only_forward_bound_transitions(
    tmp_path: Path,
) -> None:
    api = _demo_api()
    prepared = receipt_sample(tmp_path, state="prepared")

    installed = api.transition_desktop_demo_receipt(
        prepared,
        target_state="installed",
        occurred_at=CREATED_AT,
        config_sha256=SHA256,
    )
    removing = api.transition_desktop_demo_receipt(
        installed,
        target_state="removing",
        occurred_at=REMOVING_AT,
    )
    removed = api.transition_desktop_demo_receipt(
        removing,
        target_state="removed",
        occurred_at=REMOVED_AT,
        config_sha256=SHA256,
    )

    assert [installed["state"], removing["state"], removed["state"]] == [
        "installed",
        "removing",
        "removed",
    ]
    assert installed["installation_id"] == prepared["installation_id"]
    assert removing["teardown"]["requested_at"] == REMOVING_AT
    assert removed["teardown"] == {
        "requested_at": REMOVING_AT,
        "completed_at": REMOVED_AT,
        "config_after_teardown_sha256": SHA256,
    }
    Draft202012Validator(_schema(), format_checker=FormatChecker()).validate(removed)

    for source, target in (
        (prepared, "removed"),
        (installed, "prepared"),
        (removing, "installed"),
        (removed, "installed"),
    ):
        with pytest.raises(api.DesktopDemoError, match="receipt_transition_invalid"):
            api.transition_desktop_demo_receipt(
                source,
                target_state=target,
                occurred_at=REMOVED_AT,
                config_sha256=SHA256,
            )


def test_new_config_receipt_uses_empty_digest_and_no_backup(tmp_path: Path) -> None:
    payload = receipt_sample(tmp_path, state="prepared")
    payload.update(
        {
            "config_existed_before": False,
            "config_before_sha256": EMPTY_SHA256,
            "backup_path": None,
            "backup_sha256": None,
        }
    )

    Draft202012Validator(_schema(), format_checker=FormatChecker()).validate(payload)


@pytest.mark.parametrize(
    "invalid_time",
    [
        "2026-07-15T12:00:00",
        "2026-07-15T12:00:00+00:00",
        "2026-07-15T13:00:00+01:00",
    ],
)
def test_runtime_receipt_requires_utc_timestamps(tmp_path: Path, invalid_time: str) -> None:
    api = _demo_api()
    data_dir = (tmp_path / "verity-data").resolve()
    codex_home = (tmp_path / "codex-home").resolve()
    data_dir.mkdir(mode=0o700)
    codex_home.mkdir(mode=0o700)
    receipt_path = data_dir / "desktop-demo-receipt.json"
    payload = receipt_sample(tmp_path, state="installed")
    payload["confirmed_at"] = invalid_time
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")
    receipt_path.chmod(0o600)

    with pytest.raises(api.DesktopDemoError, match="receipt_invalid"):
        api.parse_desktop_demo_receipt(
            receipt_path,
            codex_home=codex_home,
            data_dir=data_dir,
        )
