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
    SemanticAssessment,
    SemanticFailure,
    Signal,
    format_utc,
    new_id,
)
from verity_cordon.core.protocols import SemanticAdjudicator


def _failed_assessment(
    candidate: MemoryCandidate,
    *,
    failure_class: str,
    retryable: bool,
    latency_ms: int,
) -> SemanticAssessment:
    return SemanticAssessment(
        assessment_id=new_id(),
        candidate_id=candidate.candidate_id,
        provider_state=ProviderState.FAILED,
        requested_model=None,
        returned_model=None,
        prompt_version="semantic-risk-v1",
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


async def run_semantic_assessment(
    adjudicator: SemanticAdjudicator | Any,
    candidate: MemoryCandidate,
    *,
    timeout_ms: int,
) -> SemanticAssessment:
    started = perf_counter()
    try:
        async with asyncio.timeout(timeout_ms / 1000):
            raw = await adjudicator.assess(candidate)
        result = (
            raw
            if isinstance(raw, SemanticAssessment)
            else SemanticAssessment.model_validate(raw)
        )
        if result.candidate_id != candidate.candidate_id:
            raise ValueError("semantic candidate identity mismatch")
        return result
    except TimeoutError:
        failure_class, retryable = "timeout", True
    except (ValidationError, TypeError, ValueError):
        failure_class, retryable = "invalid_schema", False
    except asyncio.CancelledError:
        raise
    except Exception:
        failure_class, retryable = "internal_error", True
    latency_ms = max(0, int((perf_counter() - started) * 1000))
    return _failed_assessment(
        candidate,
        failure_class=failure_class,
        retryable=retryable,
        latency_ms=latency_ms,
    )
