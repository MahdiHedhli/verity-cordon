"""Pydantic v2 models for the deterministic local policy document."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, field_validator, model_validator

from verity_cordon.core.models import (
    Action,
    MemoryKind,
    Mode,
    PolicyIdentifier,
    Sensitivity,
    Severity,
    SourceClass,
    StrictModel,
)
from verity_cordon.crypto.canonical import canonical_sha256_hex

NamespacePattern = Annotated[
    str,
    StringConstraints(
        pattern=r"^(facts|preferences|project|instructions|policies|tool_results|scratch|credentials)(?:\.[a-z0-9*][a-z0-9_*-]*)*$",
        max_length=160,
    ),
]
RuleIdentifier = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{2,63}$"),
]
SemanticVersion = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$"),
]

DetectorCategory = Literal[
    "credential_material",
    "pii",
    "persistent_instruction",
    "protected_namespace",
    "cross_task_contamination",
    "self_reinforcement",
    "untrusted_authority",
    "anomalous_size",
    "concealed_instruction",
    "encoded_content",
    "structural_invalidity",
]
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


def _require_unique(values: list[object], label: str) -> list[object]:
    serialized = [str(value) for value in values]
    if len(serialized) != len(set(serialized)):
        raise ValueError(f"{label} must contain unique values")
    return values


class RuleMatch(StrictModel):
    source_classes: list[SourceClass] | None = Field(default=None, min_length=1)
    namespace_patterns: list[NamespacePattern] | None = Field(default=None, min_length=1)
    memory_kinds: list[MemoryKind] | None = Field(default=None, min_length=1)
    sensitivities: list[Sensitivity] | None = Field(default=None, min_length=1)
    detector_categories_any: list[DetectorCategory] | None = Field(default=None, min_length=1)
    minimum_detector_severity: Severity | None = None
    semantic_categories_any: list[SemanticCategory] | None = Field(default=None, min_length=1)
    minimum_semantic_risk: float | None = Field(default=None, ge=0, le=1)
    persistence_requested: bool | None = None
    semantic_required: bool | None = None

    @model_validator(mode="after")
    def validate_nonempty_and_unique(self) -> Self:
        populated = self.model_dump(exclude_none=True)
        if not populated:
            raise ValueError("Policy rule match must contain at least one predicate")
        for name, value in populated.items():
            if isinstance(value, list):
                _require_unique(value, name)
        return self


class PolicyRule(StrictModel):
    rule_id: RuleIdentifier
    priority: int = Field(ge=0, le=1_000_000)
    description: str = Field(min_length=1, max_length=500)
    match: RuleMatch
    action: Action
    manual_review_required: bool
    ttl_seconds: int | None = Field(default=None, ge=60, le=31_536_000)


class FailureBehavior(StrictModel):
    detector_failure_high_risk: Literal[Action.QUARANTINE, Action.BLOCK]
    detector_failure_lower_risk: Action
    semantic_timeout_high_risk: Literal[Action.QUARANTINE, Action.BLOCK]
    semantic_timeout_lower_risk: Action
    semantic_invalid_high_risk: Literal[Action.QUARANTINE, Action.BLOCK]
    semantic_invalid_lower_risk: Action
    ledger_unavailable: Literal["refuse_commits_and_disable_injection"]
    ledger_corrupt: Literal["refuse_commits_and_disable_injection"]
    invalid_policy: Literal["refuse_new_commits"]
    daemon_unavailable: Literal["continue_without_verity_memory"]
    codex_hook_failure: Literal["continue_without_verity_memory"]


class ManualReviewPolicy(StrictModel):
    required_actions: list[Literal["approve", "block", "revoke"]]
    reason_required: Literal[True]
    actor_id_required: Literal[True]
    confirmation_required: Literal[True]

    @field_validator("required_actions")
    @classmethod
    def validate_unique_actions(cls, value: list[str]) -> list[str]:
        _require_unique(list(value), "required_actions")
        return value


class PolicyLimits(StrictModel):
    max_candidate_bytes: int = Field(ge=256, le=1_048_576)
    max_evidence_bytes: int = Field(ge=1024, le=10_485_760)
    max_stream_bytes: int = Field(ge=1024, le=10_485_760)
    max_stream_chunks: int = Field(ge=1, le=10_000)
    detector_timeout_ms: int = Field(ge=1, le=60_000)
    semantic_timeout_ms: int = Field(ge=100, le=300_000)
    injection_token_budget: int = Field(ge=0, le=32_768)
    default_ttl_seconds: int | None = Field(default=None, ge=60, le=31_536_000)


class PolicyDocument(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    engine_profile: Literal["VC-POLICY-1"] = "VC-POLICY-1"
    policy_id: PolicyIdentifier
    version: SemanticVersion
    mode: Mode
    default_action: Action
    shadow_action: Literal[Action.ALLOW, Action.REDACT]
    protected_namespaces: list[NamespacePattern]
    rules: list[PolicyRule] = Field(min_length=1, max_length=256)
    failure_behavior: FailureBehavior
    manual_review: ManualReviewPolicy
    limits: PolicyLimits
    created_at: datetime

    @model_validator(mode="after")
    def validate_unique_identifiers(self) -> Self:
        _require_unique(list(self.protected_namespaces), "protected_namespaces")
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("Duplicate policy rule ID")
        return self

    @property
    def content_digest(self) -> str:
        return canonical_sha256_hex(self.model_dump(mode="json"))
