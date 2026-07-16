"""Content-safe semantic-provider readiness shared by operator surfaces."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any

from verity_cordon.core.models import (
    ProviderIsolation,
    ProviderSummaryState,
    provider_isolation_for,
)

_SAFE_FAILURE_CLASSES = frozenset(
    {
        "cancelled",
        "cleanup_failure",
        "executable_drift",
        "incomplete",
        "internal_error",
        "invalid_response",
        "invalid_schema",
        "output_limit",
        "process_exit",
        "refusal",
        "timeout",
        "tool_activity",
        "unavailable",
        "unsupported_auth",
        "unsupported_provider",
    }
)


@dataclass(frozen=True, slots=True)
class SemanticProviderReadiness:
    """Normalized provider state that is safe to expose through local APIs."""

    provider: ProviderSummaryState
    isolation: ProviderIsolation
    ready: bool
    failure_class: str | None = None


def _failure_class(error: Exception) -> str:
    value = getattr(error, "failure_class", "unavailable")
    if isinstance(value, str) and value in _SAFE_FAILURE_CLASSES:
        return value
    return "unavailable"


async def semantic_provider_readiness(
    provider_label: str,
    subscription_runner: Any | None,
) -> SemanticProviderReadiness:
    """Evaluate only recognized configured providers and fail closed otherwise."""

    if provider_label in {
        ProviderSummaryState.LIVE_OPENAI.value,
        ProviderSummaryState.RECORDED_FIXTURE.value,
    }:
        provider = ProviderSummaryState(provider_label)
        return SemanticProviderReadiness(
            provider=provider,
            isolation=provider_isolation_for(provider.value),
            ready=True,
        )

    if provider_label == ProviderSummaryState.LIVE_CODEX_SUBSCRIPTION.value:
        provider = ProviderSummaryState.LIVE_CODEX_SUBSCRIPTION
        if subscription_runner is None:
            return SemanticProviderReadiness(
                provider=provider,
                isolation=provider_isolation_for(provider.value),
                ready=False,
                failure_class="unavailable",
            )
        try:
            auth_state = await subscription_runner.check_chatgpt_auth()
        except Exception as error:
            return SemanticProviderReadiness(
                provider=provider,
                isolation=provider_isolation_for(provider.value),
                ready=False,
                failure_class=_failure_class(error),
            )
        if not isinstance(auth_state, str) or not hmac.compare_digest(
            auth_state,
            "ready_chatgpt",
        ):
            return SemanticProviderReadiness(
                provider=provider,
                isolation=provider_isolation_for(provider.value),
                ready=False,
                failure_class="unsupported_auth",
            )
        return SemanticProviderReadiness(
            provider=provider,
            isolation=provider_isolation_for(provider.value),
            ready=True,
        )

    provider = ProviderSummaryState.FAILED
    return SemanticProviderReadiness(
        provider=provider,
        isolation=provider_isolation_for(provider.value),
        ready=False,
        failure_class="unsupported_provider",
    )
