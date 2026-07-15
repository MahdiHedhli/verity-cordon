"""Authentication-readiness tests for subscription-backed semantic review."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.unit.test_codex_subscription_runner import (
    _fake_codex,
    _homes,
    _records,
    _secure_tree,
)
from verity_cordon.core.errors import SemanticProviderError
from verity_cordon.semantic.codex_subscription import CodexSubscriptionRunner


def _auth_runner(
    root: Any,
    *,
    status: str = "Logged in using ChatGPT\n",
    status_stderr: str = "",
    status_exit: int = 0,
    status_sleep: float = 0.0,
    **overrides: Any,
) -> tuple[CodexSubscriptionRunner, Any]:
    executable, monitor, _ = _fake_codex(
        root,
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
