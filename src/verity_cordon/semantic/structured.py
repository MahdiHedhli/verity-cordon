"""Shared strict schemas and bounds for semantic provider output.

Provider transports remain separate. This module contains only local schema,
identifier, sanitization, and resource-boundary logic so fixture, direct API,
and subscription-backed implementations cannot drift on accepted model output.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import Field

from verity_cordon.core.models import (
    Action,
    MemoryKind,
    PersistenceIntent,
    Sensitivity,
    Signal,
    StrictModel,
)
from verity_cordon.detectors.builtin import SecretSanitizer

SemanticCategory = Literal[
    "persistent_instruction",
    "privilege_escalation",
    "tool_hijack",
    "data_exfiltration",
    "cross_task_contamination",
    "self_reinforcement",
    "secret_material",
    "protected_namespace",
    "concealed_instruction",
    "benign_fact",
    "benign_preference",
    "ambiguous",
]

MAX_CANDIDATES = 16
MAX_DURABILITY_RATIONALE_CHARACTERS = 1_000
MAX_DURABILITY_RATIONALE_BYTES = 4_096
MAX_SEMANTIC_CATEGORIES = 12
MAX_SEMANTIC_CATEGORY_CHARACTERS = 64
MAX_SEMANTIC_CATEGORY_BYTES = 256
MAX_SEMANTIC_RATIONALE_CHARACTERS = 2_000
MAX_SEMANTIC_RATIONALE_BYTES = 8_192
MODEL_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class InvalidModelOutput(ValueError):
    """Structured model output crossed a schema or resource boundary."""


def raw_field(value: Any, field: str) -> Any:
    if isinstance(value, dict):
        return value.get(field)
    return getattr(value, field, None)


def bounded_model_text(
    sanitizer: SecretSanitizer,
    value: Any,
    *,
    max_characters: int,
    max_bytes: int,
) -> str:
    if not isinstance(value, str) or not value or len(value) > max_characters:
        raise InvalidModelOutput
    try:
        if len(value.encode("utf-8", errors="strict")) > max_bytes:
            raise InvalidModelOutput
    except UnicodeEncodeError as exc:
        raise InvalidModelOutput from exc
    sanitized = sanitizer.sanitize(value).text
    try:
        if (
            not sanitized
            or len(sanitized) > max_characters
            or len(sanitized.encode("utf-8", errors="strict")) > max_bytes
        ):
            raise InvalidModelOutput
    except UnicodeEncodeError as exc:
        raise InvalidModelOutput from exc
    return sanitized


def model_identifier(sanitizer: SecretSanitizer, value: Any) -> str:
    """Accept a bounded provider identifier only when sanitization is a no-op."""

    if not isinstance(value, str) or MODEL_IDENTIFIER.fullmatch(value) is None:
        raise InvalidModelOutput
    sanitized = sanitizer.sanitize(value).text
    if sanitized != value:
        raise InvalidModelOutput
    return value


def validate_candidate_output_shape(parsed: Any) -> None:
    candidates = raw_field(parsed, "candidates")
    if not isinstance(candidates, list) or len(candidates) > MAX_CANDIDATES:
        raise InvalidModelOutput
    for candidate in candidates:
        rationale = raw_field(candidate, "durability_rationale")
        if (
            not isinstance(rationale, str)
            or not rationale
            or len(rationale) > MAX_DURABILITY_RATIONALE_CHARACTERS
        ):
            raise InvalidModelOutput
        try:
            if len(rationale.encode("utf-8", errors="strict")) > MAX_DURABILITY_RATIONALE_BYTES:
                raise InvalidModelOutput
        except UnicodeEncodeError as exc:
            raise InvalidModelOutput from exc


def validate_semantic_output_shape(parsed: Any) -> None:
    categories = raw_field(parsed, "categories")
    rationale = raw_field(parsed, "rationale")
    if (
        not isinstance(categories, list)
        or not categories
        or len(categories) > MAX_SEMANTIC_CATEGORIES
    ):
        raise InvalidModelOutput
    if len(categories) != len(set(categories)):
        raise InvalidModelOutput
    for category in categories:
        if (
            not isinstance(category, str)
            or not category
            or len(category) > MAX_SEMANTIC_CATEGORY_CHARACTERS
        ):
            raise InvalidModelOutput
        try:
            if len(category.encode("utf-8", errors="strict")) > MAX_SEMANTIC_CATEGORY_BYTES:
                raise InvalidModelOutput
        except UnicodeEncodeError as exc:
            raise InvalidModelOutput from exc
    if (
        not isinstance(rationale, str)
        or not rationale
        or len(rationale) > MAX_SEMANTIC_RATIONALE_CHARACTERS
    ):
        raise InvalidModelOutput
    try:
        if len(rationale.encode("utf-8", errors="strict")) > MAX_SEMANTIC_RATIONALE_BYTES:
            raise InvalidModelOutput
    except UnicodeEncodeError as exc:
        raise InvalidModelOutput from exc


class ExtractedCandidate(StrictModel):
    namespace: str = Field(
        pattern=r"^(facts|preferences|project|instructions|policies|tool_results|scratch|credentials)(\.[a-z0-9][a-z0-9_-]*)*$",
        max_length=160,
    )
    kind: MemoryKind
    statement: str = Field(min_length=1, max_length=8192)
    confidence: float = Field(ge=0, le=1)
    durability_rationale: str = Field(min_length=1, max_length=1000)
    sensitivity: Sensitivity
    requested_ttl_seconds: int | None = Field(default=None, ge=60, le=31_536_000)
    persistence_requested: bool
    authority_signal: Signal
    secrecy_signal: Signal


class CandidateExtractionOutput(StrictModel):
    candidates: list[ExtractedCandidate] = Field(max_length=MAX_CANDIDATES)


class SemanticRiskOutput(StrictModel):
    risk_score: float = Field(ge=0, le=1)
    categories: list[SemanticCategory] = Field(min_length=1, max_length=MAX_SEMANTIC_CATEGORIES)
    persistence_intent: PersistenceIntent
    authority_claim: Signal
    exfiltration_risk: float = Field(ge=0, le=1)
    tool_hijack_risk: float = Field(ge=0, le=1)
    cross_task_risk: float = Field(ge=0, le=1)
    secret_risk: float = Field(ge=0, le=1)
    rationale: str = Field(min_length=1, max_length=MAX_SEMANTIC_RATIONALE_CHARACTERS)
    recommended_disposition: Action
