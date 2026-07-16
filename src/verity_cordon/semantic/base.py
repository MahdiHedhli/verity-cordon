"""Bounded semantic-provider execution with explicit failed assessments."""

from __future__ import annotations

import asyncio
from time import perf_counter
from typing import Any

from pydantic import ValidationError

from verity_cordon.core.models import (
    MemoryCandidate,
    PersistenceIntent,
    ProviderState,
    RequestedProvider,
    SemanticAssessment,
    SemanticFailure,
    Signal,
    format_utc,
    new_id,
)
from verity_cordon.core.protocols import SemanticAdjudicator
from verity_cordon.telemetry.instrumentation import span


def failed_assessment(
    candidate: MemoryCandidate,
    *,
    failure_class: str,
    retryable: bool,
    latency_ms: int,
    requested_provider: RequestedProvider,
    requested_model: str | None = None,
    prompt_version: str = "semantic-risk-v1",
) -> SemanticAssessment:
    return SemanticAssessment(
        assessment_id=new_id(),
        candidate_id=candidate.candidate_id,
        provider_state=ProviderState.FAILED,
        requested_provider=requested_provider,
        requested_model=requested_model,
        returned_model=None,
        prompt_version=prompt_version,
        risk_score=None,
        categories=[],
        persistence_intent=PersistenceIntent.UNKNOWN,
        authority_claim=Signal.UNKNOWN,
        exfiltration_risk=None,
        tool_hijack_risk=None,
        cross_task_risk=None,
        secret_risk=None,
        rationale=None,
        recommended_disposition=None,
        sanitized_content_digest=candidate.content_digest,
        latency_ms=latency_ms,
        failure=SemanticFailure(class_name=failure_class, retryable=retryable),
        assessed_at=format_utc(),
    )


def _requested_provider_metadata(adjudicator: Any) -> RequestedProvider | None:
    configured = getattr(adjudicator, "requested_provider", None)
    if configured is not None:
        try:
            return RequestedProvider(configured)
        except (TypeError, ValueError):
            return None
    return {
        ProviderState.RECORDED_FIXTURE.value: RequestedProvider.FIXTURE,
        ProviderState.LIVE_OPENAI.value: RequestedProvider.OPENAI,
        ProviderState.LIVE_CODEX_SUBSCRIPTION.value: RequestedProvider.CODEX_SUBSCRIPTION,
    }.get(getattr(adjudicator, "provider_label", ""))


def _bounded_metadata(value: Any) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= 128 else None


def _requested_model_metadata(adjudicator: Any) -> str | None:
    requested = getattr(adjudicator, "requested_model", None)
    if requested is None:
        requested = getattr(adjudicator, "model", None)
    if requested is None:
        requested = getattr(getattr(adjudicator, "runner", None), "model", None)
    return _bounded_metadata(requested)


async def run_semantic_assessment(
    adjudicator: SemanticAdjudicator | Any,
    candidate: MemoryCandidate,
    *,
    timeout_ms: int,
) -> SemanticAssessment:
    async with span(
        "verity.semantic.assess",
        candidate_id=candidate.candidate_id,
        semantic_provider=getattr(adjudicator, "provider_label", "unknown"),
    ) as timing:
        result = await _run_semantic_assessment_untraced(
            adjudicator,
            candidate,
            timeout_ms=timeout_ms,
        )
    return result.model_copy(
        update={"latency_ms": max(result.latency_ms, int(timing["latency_ms"]))}
    )


async def _run_semantic_assessment_untraced(
    adjudicator: SemanticAdjudicator | Any,
    candidate: MemoryCandidate,
    *,
    timeout_ms: int,
) -> SemanticAssessment:
    started = perf_counter()
    requested_provider = _requested_provider_metadata(adjudicator)
    if requested_provider is None:
        raise ValueError("semantic adjudicator must declare a supported requested provider")
    requested_model = _requested_model_metadata(adjudicator)
    if (
        requested_provider
        in {
            RequestedProvider.OPENAI,
            RequestedProvider.CODEX_SUBSCRIPTION,
        }
        and requested_model is None
    ):
        raise ValueError("live semantic adjudicator must declare a valid requested model")
    prompt_version = _bounded_metadata(getattr(adjudicator, "prompt_version", None))
    failure_prompt_version = prompt_version or "semantic-risk-v1"
    try:
        async with asyncio.timeout(timeout_ms / 1000):
            raw = await adjudicator.assess(candidate)
        result = (
            raw if isinstance(raw, SemanticAssessment) else SemanticAssessment.model_validate(raw)
        )
        if result.candidate_id != candidate.candidate_id:
            raise ValueError("semantic candidate identity mismatch")
        if result.sanitized_content_digest != candidate.content_digest:
            raise ValueError("semantic candidate digest mismatch")
        if result.requested_model != requested_model:
            raise ValueError("semantic requested model identity mismatch")
        if result.provider_state is ProviderState.FAILED and result.returned_model is not None:
            raise ValueError("failed semantic assessment must not assert a returned model")
        updates: dict[str, Any] = {
            "schema_version": "1.0.1",
            "requested_provider": requested_provider,
            "requested_model": requested_model,
        }
        normalized = result.model_dump(mode="python")
        normalized.update(updates)
        return SemanticAssessment.model_validate(normalized)
    except TimeoutError:
        failure_class, retryable = "timeout", True
    except (ValidationError, TypeError, ValueError):
        failure_class, retryable = "invalid_schema", False
    except asyncio.CancelledError:
        raise
    except Exception:
        failure_class, retryable = "internal_error", True
    latency_ms = max(0, int((perf_counter() - started) * 1000))
    return failed_assessment(
        candidate,
        failure_class=failure_class,
        retryable=retryable,
        latency_ms=latency_ms,
        requested_provider=requested_provider,
        requested_model=requested_model,
        prompt_version=failure_prompt_version,
    )
