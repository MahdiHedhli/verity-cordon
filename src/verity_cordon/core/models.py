"""Strict domain models shared by the daemon, ledger, policy, and adapters."""

from __future__ import annotations

import secrets
import time
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

Identifier = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$"),
]
PolicyIdentifier = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{2,63}$"),
]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        validate_assignment=True,
    )


class Action(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    QUARANTINE = "quarantine"
    BLOCK = "block"


class Mode(StrEnum):
    ENFORCE = "enforce"
    SHADOW = "shadow"


class SourceClass(StrEnum):
    USER_INPUT = "user_input"
    TOOL_OUTPUT = "tool_output"
    AGENT_OUTPUT = "agent_output"
    IMPORTED_FILE = "imported_file"
    PRIOR_MEMORY = "prior_memory"
    COMPACTION = "compaction"
    SESSION_SUMMARY = "session_summary"
    EXTERNAL_EVENT = "external_event"


class EventSourceClass(StrEnum):
    USER_INPUT = "user_input"
    TOOL_OUTPUT = "tool_output"
    AGENT_OUTPUT = "agent_output"
    IMPORTED_FILE = "imported_file"
    PRIOR_MEMORY = "prior_memory"
    COMPACTION = "compaction"
    SESSION_SUMMARY = "session_summary"
    EXTERNAL_EVENT = "external_event"
    OPERATOR_ACTION = "operator_action"
    SYSTEM = "system"


class MemoryKind(StrEnum):
    FACT = "fact"
    USER_PREFERENCE = "user_preference"
    PROJECT_CONVENTION = "project_convention"
    OPERATIONAL_INSTRUCTION = "operational_instruction"
    TOOL_OBSERVATION = "tool_observation"
    TASK_SUMMARY = "task_summary"
    IDENTITY_ASSERTION = "identity_assertion"
    POLICY_STATEMENT = "policy_statement"
    CREDENTIAL_MATERIAL = "credential_material"
    UNKNOWN = "unknown"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"
    CREDENTIAL = "credential"


class Signal(StrEnum):
    NONE = "none"
    IMPLIED = "implied"
    EXPLICIT = "explicit"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class DetectorStatus(StrEnum):
    OK = "ok"
    TIMEOUT = "timeout"
    ERROR = "error"
    CANCELLED = "cancelled"
    MALFORMED = "malformed"


class ProviderState(StrEnum):
    LIVE_OPENAI = "live_openai"
    LIVE_CODEX_SUBSCRIPTION = "live_codex_subscription"
    RECORDED_FIXTURE = "recorded_fixture"
    FAILED = "failed"


class RequestedProvider(StrEnum):
    FIXTURE = "fixture"
    OPENAI = "openai"
    CODEX_SUBSCRIPTION = "codex_subscription"


class ProviderSummaryState(StrEnum):
    LIVE_OPENAI = "live_openai"
    LIVE_CODEX_SUBSCRIPTION = "live_codex_subscription"
    RECORDED_FIXTURE = "recorded_fixture"
    DETERMINISTIC_ONLY = "deterministic_only"
    FAILED = "failed"
    NOT_REQUIRED = "not_required"


class ProviderIsolation(StrEnum):
    TOOL_FREE_API = "tool_free_api"
    AGENTIC_SANDBOXED = "agentic_sandboxed"
    RECORDED_FIXTURE = "recorded_fixture"
    LOCAL_DETERMINISTIC = "local_deterministic"
    FAILED = "failed"


def provider_isolation_for(provider_state: str) -> ProviderIsolation:
    """Return the documented presentation boundary for a semantic provider state."""

    return {
        ProviderSummaryState.LIVE_OPENAI.value: ProviderIsolation.TOOL_FREE_API,
        ProviderSummaryState.LIVE_CODEX_SUBSCRIPTION.value: ProviderIsolation.AGENTIC_SANDBOXED,
        ProviderSummaryState.RECORDED_FIXTURE.value: ProviderIsolation.RECORDED_FIXTURE,
        ProviderSummaryState.DETERMINISTIC_ONLY.value: ProviderIsolation.LOCAL_DETERMINISTIC,
        ProviderSummaryState.NOT_REQUIRED.value: ProviderIsolation.LOCAL_DETERMINISTIC,
        ProviderSummaryState.FAILED.value: ProviderIsolation.FAILED,
    }.get(provider_state, ProviderIsolation.FAILED)


class PersistenceIntent(StrEnum):
    NONE = "none"
    IMPLICIT = "implicit"
    EXPLICIT = "explicit"
    UNKNOWN = "unknown"


class EventType(StrEnum):
    EVIDENCE_CAPTURED = "EvidenceCaptured"
    EVIDENCE_EVALUATION_COMPLETED = "EvidenceEvaluationCompleted"
    EVIDENCE_EVALUATION_FAILED = "EvidenceEvaluationFailed"
    MEMORY_CANDIDATE_CREATED = "MemoryCandidateCreated"
    DETECTOR_VERDICT_RECORDED = "DetectorVerdictRecorded"
    SEMANTIC_ASSESSMENT_RECORDED = "SemanticAssessmentRecorded"
    POLICY_DECISION_RECORDED = "PolicyDecisionRecorded"
    MEMORY_COMMITTED = "MemoryCommitted"
    MEMORY_REDACTED = "MemoryRedacted"
    MEMORY_QUARANTINED = "MemoryQuarantined"
    MEMORY_BLOCKED = "MemoryBlocked"
    MEMORY_APPROVED = "MemoryApproved"
    MEMORY_REVOKED = "MemoryRevoked"
    MEMORY_SUPERSEDED = "MemorySuperseded"
    MEMORY_EXPIRED = "MemoryExpired"
    POLICY_ACTIVATED = "PolicyActivated"
    POLICY_ACTIVATION_REJECTED = "PolicyActivationRejected"
    LEDGER_CHECKPOINT_CREATED = "LedgerCheckpointCreated"
    STREAM_STARTED = "StreamStarted"
    STREAM_ABORTED = "StreamAborted"
    STREAM_COMMITTED = "StreamCommitted"


class ActorType(StrEnum):
    SYSTEM = "system"
    OPERATOR = "operator"
    CODEX = "codex"
    TOOL = "tool"
    AGENT = "agent"
    POLICY = "policy"
    DETECTOR = "detector"


class Actor(StrictModel):
    type: ActorType
    id: Identifier


class EvidenceReference(StrictModel):
    evidence_id: Identifier
    digest: Sha256Hex


class CandidateEvidenceReference(StrictModel):
    evidence_id: Identifier
    evidence_digest: Sha256Hex


class EvidenceRecord(StrictModel):
    evidence_id: Identifier
    session_id: Identifier
    task_id: Identifier | None = None
    source_class: SourceClass
    source_name: str | None = Field(default=None, max_length=256)
    safe_excerpt: str = Field(max_length=2000)
    content_digest: Sha256Hex
    content_size: int = Field(ge=0)
    retention_state: Literal["digest_only", "protected_local", "expired"] = "digest_only"
    captured_at: str
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class MemoryCandidate(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    candidate_id: Identifier
    namespace: str = Field(
        pattern=r"^(facts|preferences|project|instructions|policies|tool_results|scratch|credentials)(\.[a-z0-9][a-z0-9_-]*)*$",
        max_length=160,
    )
    kind: MemoryKind
    statement: str = Field(min_length=1, max_length=8192)
    source_class: SourceClass
    source_refs: list[CandidateEvidenceReference] = Field(min_length=1, max_length=32)
    session_id: Identifier
    task_id: Identifier | None = None
    confidence: float = Field(ge=0, le=1)
    durability_rationale: str = Field(min_length=1, max_length=1000)
    sensitivity: Sensitivity
    requested_ttl_seconds: int | None = Field(default=None, ge=60, le=31_536_000)
    persistence_requested: bool
    authority_signal: Signal
    secrecy_signal: Signal
    contains_redactions: bool
    extractor_provider: Literal[
        "live_openai",
        "live_codex_subscription",
        "recorded_fixture",
        "deterministic",
    ]
    extractor_version: str = Field(min_length=1, max_length=128)
    content_digest: Sha256Hex
    created_at: str


class EvidenceOffset(StrictModel):
    source_ref: Identifier
    start: int = Field(ge=0)
    end: int = Field(ge=0)

    @field_validator("end")
    @classmethod
    def validate_end(cls, value: int, info: Any) -> int:
        start = info.data.get("start", 0)
        if value < start:
            raise ValueError("end must be greater than or equal to start")
        return value


class DetectorResult(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    result_id: Identifier
    candidate_id: Identifier
    detector_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,63}$")
    detector_version: str = Field(min_length=1, max_length=64)
    execution_order: int = Field(ge=0)
    status: DetectorStatus
    matched: bool | None
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    categories: list[str]
    message: str = Field(min_length=1, max_length=1000)
    evidence_offsets: list[EvidenceOffset] = Field(default_factory=list, max_length=64)
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    failure_class: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
    latency_ms: int = Field(ge=0, le=300_000)
    recorded_at: str

    @field_validator("matched")
    @classmethod
    def validate_match_status(cls, value: bool | None, info: Any) -> bool | None:
        status = info.data.get("status")
        if status == DetectorStatus.OK and value is None:
            raise ValueError("successful detector result requires matched")
        if status is not None and status != DetectorStatus.OK and value is not None:
            raise ValueError("failed detector result must not claim matched status")
        return value


class SemanticFailure(StrictModel):
    class_name: Literal[
        "timeout",
        "unavailable",
        "refusal",
        "incomplete",
        "invalid_schema",
        "invalid_response",
        "internal_error",
        "unsupported_auth",
        "executable_drift",
        "tool_activity",
        "output_limit",
        "process_exit",
        "cleanup_failure",
        "cancelled",
    ] = Field(alias="class")
    retryable: bool


class SemanticAssessment(StrictModel):
    schema_version: Literal["1.0.0", "1.0.1"] = "1.0.1"
    assessment_id: Identifier
    candidate_id: Identifier
    provider_state: ProviderState
    requested_provider: RequestedProvider | None = None
    requested_model: str | None = Field(default=None, min_length=1, max_length=128)
    returned_model: str | None = Field(default=None, min_length=1, max_length=128)
    prompt_version: str = Field(min_length=1, max_length=128)
    risk_score: float | None = Field(default=None, ge=0, le=1)
    categories: list[str]
    persistence_intent: PersistenceIntent
    authority_claim: Signal
    exfiltration_risk: float | None = Field(default=None, ge=0, le=1)
    tool_hijack_risk: float | None = Field(default=None, ge=0, le=1)
    cross_task_risk: float | None = Field(default=None, ge=0, le=1)
    secret_risk: float | None = Field(default=None, ge=0, le=1)
    rationale: str | None = Field(default=None, max_length=2000)
    recommended_disposition: Action | None = None
    sanitized_content_digest: Sha256Hex
    cache_hit: bool = False
    latency_ms: int = Field(ge=0, le=300_000)
    failure: SemanticFailure | None = None
    assessed_at: str

    @model_validator(mode="after")
    def validate_provider_outcome(self) -> SemanticAssessment:
        successful_provider = {
            ProviderState.RECORDED_FIXTURE: RequestedProvider.FIXTURE,
            ProviderState.LIVE_OPENAI: RequestedProvider.OPENAI,
            ProviderState.LIVE_CODEX_SUBSCRIPTION: RequestedProvider.CODEX_SUBSCRIPTION,
        }
        if self.requested_provider is None and self.schema_version != "1.0.0":
            raise ValueError("current semantic assessment requires provider provenance")
        if (
            self.requested_provider is not None
            and self.provider_state is not ProviderState.FAILED
            and self.requested_provider is not successful_provider[self.provider_state]
        ):
            raise ValueError("successful semantic provider identity is inconsistent")
        if self.provider_state is ProviderState.LIVE_OPENAI and (
            self.requested_model is None or self.returned_model is None
        ):
            raise ValueError(
                "live OpenAI semantic assessment requires requested and returned models"
            )
        if self.provider_state is ProviderState.LIVE_CODEX_SUBSCRIPTION:
            if self.requested_model is None:
                raise ValueError("subscription semantic assessment requires a requested model")
            if self.returned_model is not None:
                raise ValueError(
                    "subscription semantic assessment must not assert a returned model"
                )
        score_fields = (
            self.risk_score,
            self.exfiltration_risk,
            self.tool_hijack_risk,
            self.cross_task_risk,
            self.secret_risk,
        )
        if self.provider_state == ProviderState.FAILED:
            if self.failure is None:
                raise ValueError("failed semantic assessment requires failure metadata")
            if (
                self.schema_version == "1.0.1"
                and self.requested_provider
                in {RequestedProvider.OPENAI, RequestedProvider.CODEX_SUBSCRIPTION}
                and self.requested_model is None
            ):
                raise ValueError("current failed live-provider assessment requires requested model")
            if self.schema_version == "1.0.1" and self.returned_model is not None:
                raise ValueError(
                    "current failed semantic assessment must not assert a returned model"
                )
            if any(value is not None for value in score_fields):
                raise ValueError("failed semantic assessment must not contain risk scores")
            if self.categories:
                raise ValueError("failed semantic assessment must not contain risk categories")
            if (
                self.persistence_intent is not PersistenceIntent.UNKNOWN
                or self.authority_claim is not Signal.UNKNOWN
            ):
                raise ValueError("failed semantic assessment requires neutral intent signals")
            if self.recommended_disposition is not None or self.rationale is not None:
                raise ValueError("failed semantic assessment must not claim a disposition")
        elif self.failure is not None or self.risk_score is None:
            raise ValueError("successful semantic assessment requires a score and no failure")
        return self


class PolicyDecision(StrictModel):
    decision_id: Identifier
    candidate_id: Identifier
    policy_id: PolicyIdentifier
    policy_version: str = Field(min_length=1, max_length=64)
    policy_digest: Sha256Hex
    matched_rule_id: str | None = Field(default=None, max_length=64)
    mode: Mode
    actual_action: Action
    would_have_action: Action
    shadow_mode: bool
    reason_codes: list[str]
    detector_result_ids: list[Identifier]
    semantic_assessment_id: Identifier | None = None
    decided_at: str


class EventInput(StrictModel):
    stream_id: Identifier
    event_type: EventType
    actor: Actor
    session_id: Identifier | None = None
    task_id: Identifier | None = None
    source_class: EventSourceClass | None = None
    memory_id: Identifier | None = None
    evidence_references: list[EvidenceReference] = Field(default_factory=list)
    policy_id: PolicyIdentifier | None = None
    policy_version: str | None = Field(default=None, max_length=64)
    detector_bundle_version: str | None = Field(default=None, max_length=128)
    semantic_model_identifier: str | None = Field(default=None, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)
    occurred_at: str | None = None
    event_id: Identifier | None = None


class EventEnvelope(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    event_id: Identifier
    stream_id: Identifier
    sequence_number: int = Field(ge=1)
    event_type: EventType
    occurred_at: str
    actor: Actor
    session_id: Identifier | None
    task_id: Identifier | None
    source_class: EventSourceClass | None
    memory_id: Identifier | None
    evidence_references: list[EvidenceReference]
    policy_id: PolicyIdentifier | None
    policy_version: str | None
    detector_bundle_version: str | None
    semantic_model_identifier: str | None
    payload: dict[str, Any]
    payload_digest: Sha256Hex
    previous_event_hash: Sha256Hex
    canonicalization_algorithm: Literal["VC-CJ-1"] = "VC-CJ-1"
    digest_algorithm: Literal["SHA-256"] = "SHA-256"
    event_hash: Sha256Hex
    signature_algorithm: Literal["Ed25519"] = "Ed25519"
    signing_key_id: str = Field(pattern=r"^vc-ed25519-[0-9a-f]{64}$")
    signature: str = Field(pattern=r"^[A-Za-z0-9+/]{86}==$")


class MemoryStatus(StrEnum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    BLOCKED = "blocked"
    REDACTED = "redacted"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"


class MemoryRecord(StrictModel):
    memory_id: Identifier
    commit_event_id: Identifier
    candidate_id: Identifier
    session_id: Identifier
    safe_statement: str = Field(min_length=1, max_length=8192)
    namespace: str = Field(max_length=160)
    kind: MemoryKind
    source_class: SourceClass
    status: Literal["active", "redacted", "revoked", "superseded", "expired"]
    trust_decision: Literal["allowed", "redacted", "manually_approved", "shadow_admitted"]
    policy_id: PolicyIdentifier
    policy_version: str
    actual_action: Action
    would_have_action: Action
    committed_at: str
    expires_at: str | None
    shadow_admitted: bool
    manual_approval_event_id: Identifier | None
    risk_categories: list[str]
    semantic_provider: ProviderSummaryState
    last_event_id: Identifier
    last_event_sequence: int = Field(ge=1)


class LedgerVerification(StrictModel):
    verified: bool
    completeness_state: Literal["anchored_complete", "tail_unproven", "invalid"]
    expected_head_source: Literal["local_sidecar", "supplied_checkpoint", "none"]
    expected_head_sequence: int | None
    observed_head_sequence: int | None
    total_events: int = Field(ge=0)
    first_invalid_event_id: Identifier | None
    failure_class: str | None
    signing_key_id: str
    public_key_fingerprint: Sha256Hex
    materialized_view_consistent: bool
    verified_at: str


def new_id() -> str:
    """Generate a UUIDv7 without requiring Python 3.14's uuid.uuid7()."""

    timestamp_ms = int(time.time_ns() // 1_000_000) & ((1 << 48) - 1)
    random_a = secrets.randbits(12)
    random_b = secrets.randbits(62)
    value = timestamp_ms << 80
    value |= 0x7 << 76
    value |= random_a << 64
    value |= 0b10 << 62
    value |= random_b
    return str(uuid.UUID(int=value))


def utc_now() -> datetime:
    return datetime.now(UTC)


def format_utc(value: datetime | None = None) -> str:
    """Normalize a timestamp for signed VC-CJ-1 event envelopes."""

    current = (value or utc_now()).astimezone(UTC)
    base = current.strftime("%Y-%m-%dT%H:%M:%S")
    if current.microsecond:
        fraction = f"{current.microsecond:06d}".rstrip("0")
        return f"{base}.{fraction}Z"
    return f"{base}Z"
