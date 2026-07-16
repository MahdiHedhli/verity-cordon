"""Fail-closed semantic-provider readiness behavior."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from verity_cordon.semantic.readiness import semantic_provider_readiness


class _Runner:
    def __init__(
        self,
        error: BaseException | None = None,
        result: Any = "ready_chatgpt",
    ) -> None:
        self.calls = 0
        self.error = error
        self.result = result

    async def check_chatgpt_auth(self) -> Any:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["live_openai", "recorded_fixture"])
async def test_non_subscription_providers_ignore_stray_subscription_runner(
    provider: str,
) -> None:
    runner = _Runner(RuntimeError("must not be probed"))

    result = await semantic_provider_readiness(provider, runner)

    assert result.provider.value == provider
    assert result.ready is True
    assert result.failure_class is None
    assert runner.calls == 0


@pytest.mark.asyncio
async def test_subscription_provider_requires_and_probes_runner() -> None:
    missing = await semantic_provider_readiness("live_codex_subscription", None)
    runner = _Runner()
    ready = await semantic_provider_readiness("live_codex_subscription", runner)

    assert missing.ready is False
    assert missing.failure_class == "unavailable"
    assert ready.ready is True
    assert ready.failure_class is None
    assert runner.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("auth_state", [None, "not_logged_in", "ready_chatgpt ", 1])
async def test_subscription_provider_rejects_unexpected_auth_state(auth_state: Any) -> None:
    result = await semantic_provider_readiness(
        "live_codex_subscription",
        _Runner(result=auth_state),
    )

    assert result.ready is False
    assert result.failure_class == "unsupported_auth"


@pytest.mark.asyncio
async def test_subscription_failure_class_is_content_safe() -> None:
    class SafeFailure(RuntimeError):
        failure_class: Any = "unsupported_auth"

    result = await semantic_provider_readiness(
        "live_codex_subscription",
        _Runner(SafeFailure("raw provider detail")),
    )
    malformed = await semantic_provider_readiness(
        "live_codex_subscription",
        _Runner(type("UnsafeFailure", (RuntimeError,), {"failure_class": "bad detail!"})()),
    )
    secret_like = await semantic_provider_readiness(
        "live_codex_subscription",
        _Runner(type("UnsafeFailure", (RuntimeError,), {"failure_class": "password123"})()),
    )

    assert result.ready is False
    assert result.failure_class == "unsupported_auth"
    assert malformed.failure_class == "unavailable"
    assert secret_like.failure_class == "unavailable"


@pytest.mark.asyncio
async def test_subscription_provider_preserves_cancellation() -> None:
    with pytest.raises(asyncio.CancelledError):
        await semantic_provider_readiness(
            "live_codex_subscription",
            _Runner(error=asyncio.CancelledError()),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["failed", "deterministic_only", "typo_provider"])
async def test_non_configured_or_unknown_provider_fails_closed(provider: str) -> None:
    runner = _Runner()

    result = await semantic_provider_readiness(provider, runner)

    assert result.provider.value == "failed"
    assert result.isolation.value == "failed"
    assert result.ready is False
    assert result.failure_class == "unsupported_provider"
    assert runner.calls == 0
