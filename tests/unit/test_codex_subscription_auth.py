"""Authentication-readiness tests for subscription-backed semantic review."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest

from tests.unit.test_codex_subscription_runner import (
    _fail_cleanup_after_removal,
    _fake_codex,
    _homes,
    _path_exists,
    _records,
    _secure_tree,
)
from verity_cordon.core.errors import SemanticProviderError
from verity_cordon.semantic.codex_subscription import CodexSubscriptionRunner


def _auth_runner(
    root: Any,
    *,
    version: str = "codex-cli 0.144.4\n",
    version_stderr: str = "",
    version_exit: int = 0,
    status: str = "Logged in using ChatGPT\n",
    status_stderr: str = "",
    status_exit: int = 0,
    status_sleep: float = 0.0,
    **overrides: Any,
) -> tuple[CodexSubscriptionRunner, Any]:
    executable, monitor, _ = _fake_codex(
        root,
        version=version,
        version_stderr=version_stderr,
        version_exit=version_exit,
        status=status,
        status_stderr=status_stderr,
        status_exit=status_exit,
        status_sleep=status_sleep,
    )
    home, codex_home = _homes(root)
    values: dict[str, Any] = {
        "executable": executable,
        "model": "gpt-5.6",
        "home": home,
        "codex_home": codex_home,
    }
    values.update(overrides)
    return CodexSubscriptionRunner(**values), monitor


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [
        "Logged in using ChatGPT",
        "Logged in using ChatGPT\n",
        "  Logged in using ChatGPT\r\n",
    ],
)
async def test_only_exact_normalized_chatgpt_status_is_ready(status: str) -> None:
    with _secure_tree() as root:
        runner, monitor = _auth_runner(root, status=status)

        assert await runner.check_chatgpt_auth() == "ready_chatgpt"
        assert _records(monitor)[0]["argv"] == ["login", "status"]


@pytest.mark.asyncio
async def test_exact_chatgpt_marker_on_stderr_matches_the_supported_cli() -> None:
    with _secure_tree() as root:
        runner, monitor = _auth_runner(
            root,
            status="",
            status_stderr="Logged in using ChatGPT\n",
        )

        assert await runner.check_chatgpt_auth() == "ready_chatgpt"
        assert _records(monitor)[0]["argv"] == ["login", "status"]


@pytest.mark.asyncio
async def test_readiness_checks_current_executable_version_and_fresh_auth_each_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        runner, monitor = _auth_runner(root)
        version_probe = AsyncMock(wraps=runner._check_codex_version)
        monkeypatch.setattr(runner, "_check_codex_version", version_probe)

        assert await runner.check_chatgpt_auth() == "ready_chatgpt"
        assert await runner.check_chatgpt_auth() == "ready_chatgpt"

        assert version_probe.await_count == 2
        assert runner.codex_version == "codex-cli 0.144.4"
        assert [record["kind"] for record in _records(monitor)] == ["status", "status"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("version", "version_stderr", "version_exit"),
    [
        ("codex-cli 0.144.3\n", "", 0),
        ("codex-cli 1.0.0\n", "", 0),
        ("codex-cli 0.144.4-beta\n", "", 0),
        ("Codex 0.144.4\n", "", 0),
        ("codex-cli 0.144.4\nextra\n", "", 0),
        ("codex-cli 0.144.4\n", "synthetic detail", 0),
        ("codex-cli 0.144.4\n", "", 7),
    ],
)
async def test_malformed_unsupported_or_failed_version_is_not_ready(
    version: str,
    version_stderr: str,
    version_exit: int,
) -> None:
    with _secure_tree() as root:
        runner, monitor = _auth_runner(
            root,
            version=version,
            version_stderr=version_stderr,
            version_exit=version_exit,
        )

        with pytest.raises(SemanticProviderError) as captured:
            await runner.check_chatgpt_auth()

        assert captured.value.failure_class == "unavailable"
        assert runner.codex_version is None
        assert runner.last_auth_state == "codex_unavailable"
        assert runner.last_failure_class == "unavailable"
        assert _records(monitor) == []
        assert "synthetic detail" not in str(captured.value)


@pytest.mark.asyncio
async def test_oversized_version_output_is_bounded_and_content_safe() -> None:
    with _secure_tree() as root:
        marker = "SYNTHETIC-VERSION-MUST-NOT-ECHO"
        runner, monitor = _auth_runner(root, version="codex-cli 0.144.4" + marker * 300)

        with pytest.raises(SemanticProviderError) as captured:
            await runner.check_chatgpt_auth()

        assert captured.value.failure_class == "output_limit"
        assert runner.codex_version is None
        assert runner.last_auth_state == "codex_unavailable"
        assert _records(monitor) == []
        assert marker not in str(captured.value)


@pytest.mark.asyncio
async def test_auth_temp_cleanup_failure_invalidates_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        runner, monitor = _auth_runner(root)
        _fail_cleanup_after_removal(monkeypatch, prefix="verity-codex-auth-")

        with pytest.raises(SemanticProviderError) as captured:
            await runner.check_chatgpt_auth()

        assert captured.value.failure_class == "cleanup_failure"
        assert runner.last_cleanup_failure == "temporary_artifacts"
        assert runner.last_auth_state == "status_failed"
        assert runner.last_failure_class == "cleanup_failure"
        assert not _path_exists(_records(monitor)[0]["env"]["TMPDIR"])
        assert "synthetic cleanup failure" not in str(captured.value)

        with pytest.raises(SemanticProviderError) as repeated:
            await runner.check_chatgpt_auth()
        assert repeated.value.failure_class == "cleanup_failure"
        assert len(_records(monitor)) == 1


@pytest.mark.asyncio
async def test_auth_temp_cleanup_failure_does_not_mask_auth_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        runner, _ = _auth_runner(root, status="Not logged in\n")
        _fail_cleanup_after_removal(monkeypatch, prefix="verity-codex-auth-")

        with pytest.raises(SemanticProviderError) as captured:
            await runner.check_chatgpt_auth()

        assert captured.value.failure_class == "unsupported_auth"
        assert runner.last_cleanup_failure == "temporary_artifacts"
        assert runner.last_auth_state == "unsupported_auth"
        assert runner.last_failure_class == "unsupported_auth"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [
        "Logged in using an API key\n",
        "Logged in using CODEX_API_KEY\n",
        "Logged in using access token\n",
        "Not logged in\n",
        "",
        "ChatGPT\n",
        "Logged in using ChatGPT Enterprise\n",
        "Logged in using ChatGPT\nLogged in using an API key\n",
        "Prefix: Logged in using ChatGPT\n",
    ],
)
async def test_api_key_absent_and_ambiguous_statuses_are_not_subscription_ready(
    status: str,
) -> None:
    with _secure_tree() as root:
        runner, _ = _auth_runner(root, status=status)

        with pytest.raises(SemanticProviderError, match="subscription authentication"):
            await runner.check_chatgpt_auth()


@pytest.mark.asyncio
async def test_status_output_over_4k_is_rejected_without_echo() -> None:
    with _secure_tree() as root:
        marker = "SYNTHETIC-STATUS-MUST-NOT-ECHO"
        runner, _ = _auth_runner(root, status="Logged in using ChatGPT" + marker * 300)

        with pytest.raises(SemanticProviderError) as captured:
            await runner.check_chatgpt_auth()

        assert marker not in str(captured.value)


@pytest.mark.asyncio
async def test_status_stderr_over_4k_is_rejected_without_echo() -> None:
    with _secure_tree() as root:
        marker = "SYNTHETIC-STDERR-MUST-NOT-ECHO"
        runner, _ = _auth_runner(
            root,
            status="Logged in using ChatGPT\n",
            status_stderr=marker * 300,
        )

        with pytest.raises(SemanticProviderError) as captured:
            await runner.check_chatgpt_auth()

        assert marker not in str(captured.value)


@pytest.mark.asyncio
async def test_nonzero_status_exit_is_rejected_even_with_the_valid_marker() -> None:
    with _secure_tree() as root:
        runner, _ = _auth_runner(
            root,
            status="Logged in using ChatGPT\n",
            status_stderr="SYNTHETIC-UPSTREAM-DETAIL-MUST-NOT-ECHO",
            status_exit=7,
        )

        with pytest.raises(SemanticProviderError) as captured:
            await runner.check_chatgpt_auth()

        assert "SYNTHETIC-UPSTREAM-DETAIL-MUST-NOT-ECHO" not in str(captured.value)


@pytest.mark.asyncio
async def test_status_timeout_is_bounded_and_content_safe() -> None:
    with _secure_tree() as root:
        runner, _ = _auth_runner(
            root,
            status_sleep=1.0,
            auth_timeout_seconds=0.05,
        )

        with pytest.raises(SemanticProviderError, match="timed out"):
            await runner.check_chatgpt_auth()


@pytest.mark.asyncio
async def test_status_never_reads_auth_files_or_inherits_a_bearer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        runner, monitor = _auth_runner(root)
        auth_file = runner.codex_home / "auth.json"
        synthetic_secret = "synthetic-auth-file-value-must-not-be-read"
        auth_file.write_text(json.dumps({"token": synthetic_secret}), encoding="utf-8")
        auth_file.chmod(0o000)
        monkeypatch.setenv("CODEX_ACCESS_TOKEN", synthetic_secret)
        try:
            assert await runner.check_chatgpt_auth() == "ready_chatgpt"
        finally:
            auth_file.chmod(0o600)

        environment = _records(monitor)[0]["env"]
        assert "CODEX_ACCESS_TOKEN" not in environment
        assert synthetic_secret not in json.dumps(environment)
