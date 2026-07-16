"""Evidence-to-decision memory firewall pipeline."""

from __future__ import annotations

import asyncio
import hmac
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import urlsplit

import aiosqlite
from pydantic import Field, ValidationError

from verity_cordon.core.errors import LedgerError, ResourceLimitError
from verity_cordon.core.models import (
    Action,
    Actor,
    ActorType,
    DetectorResult,
    DetectorStatus,
    EventEnvelope,
    EventInput,
    EventSourceClass,
    EventType,
    EvidenceRecord,
    EvidenceReference,
    MemoryCandidate,
    MemoryKind,
    MemoryRecord,
    PolicyDecision,
    ProviderState,
    ProviderSummaryState,
    SemanticAssessment,
    Severity,
    SourceClass,
    StrictModel,
    format_utc,
    new_id,
    utc_now,
)
from verity_cordon.core.protocols import CandidateExtractor, SemanticAdjudicator
from verity_cordon.crypto.canonical import canonical_json, sha256_hex
from verity_cordon.detectors.builtin import SecretSanitizer
from verity_cordon.detectors.runner import DetectorRunner
from verity_cordon.ledger.store import SQLiteEventStore
from verity_cordon.memory.injection import render_approved_memory
from verity_cordon.memory.materializer import QuarantineRecord, SQLiteMemoryView
from verity_cordon.memory.safe_display import display_safe_statement
from verity_cordon.policies.engine import PolicyEngine, PolicyEvaluation
from verity_cordon.semantic.base import run_semantic_assessment
from verity_cordon.telemetry.instrumentation import Statistics, span

ProjectionWriter = Callable[
    [aiosqlite.Connection, list[EventEnvelope]],
    Awaitable[None],
]


class EvidenceSubmission(StrictModel):
    session_id: str = Field(min_length=8, max_length=128)
    task_id: str | None = Field(default=None, min_length=8, max_length=128)
    source_class: SourceClass
    source_name: str | None = Field(default=None, max_length=256)
    content: str = Field(min_length=1, max_length=10_485_760)
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class CandidateOutcome(StrictModel):
    candidate: MemoryCandidate
    detector_results: list[DetectorResult]
    semantic_assessment: SemanticAssessment | None
    decision: PolicyDecision
    memory_id: str | None
    status: Literal["active", "redacted", "quarantined", "blocked"]


class EvidenceEvaluation(StrictModel):
    evidence: EvidenceRecord
    outcomes: list[CandidateOutcome]


class _QueueIntegrityError(LedgerError):
    def __init__(self, message: str, *, health_error: str) -> None:
        super().__init__(message)
        self.health_error = health_error


TerminalCommitFactory = Callable[
    [list[CandidateOutcome], bool],
    tuple[EventInput, ProjectionWriter],
]


@dataclass(slots=True)
class _OutcomeCommit:
    inputs: list[EventInput]
    projector: ProjectionWriter
    outcome: CandidateOutcome


def _source_actor(submission: EvidenceSubmission, *, safe_source_name: str | None) -> Actor:
    mapping = {
        SourceClass.USER_INPUT: ActorType.CODEX,
        SourceClass.TOOL_OUTPUT: ActorType.TOOL,
        SourceClass.AGENT_OUTPUT: ActorType.AGENT,
    }
    actor_type = mapping.get(submission.source_class, ActorType.SYSTEM)
    raw_id = safe_source_name or f"source.{submission.source_class.value}"
    safe_id = "".join(
        character if character.isalnum() or character in "._:-" else "-" for character in raw_id
    )
    if len(safe_id) < 8:
        safe_id = f"source.{safe_id}"
    return Actor(type=actor_type, id=safe_id[:128])


def _provider_summary(semantic: SemanticAssessment | None) -> ProviderSummaryState:
    if semantic is None:
        return ProviderSummaryState.DETERMINISTIC_ONLY
    if semantic.provider_state == ProviderState.FAILED:
        return ProviderSummaryState.FAILED
    if semantic.provider_state == ProviderState.LIVE_OPENAI:
        return ProviderSummaryState.LIVE_OPENAI
    if semantic.provider_state == ProviderState.LIVE_CODEX_SUBSCRIPTION:
        return ProviderSummaryState.LIVE_CODEX_SUBSCRIPTION
    return ProviderSummaryState.RECORDED_FIXTURE


def semantic_model_identifier_for_event(
    semantic: SemanticAssessment | None,
) -> str | None:
    """Select signed model provenance without treating a request as attestation."""

    if semantic is None:
        return None
    return semantic.returned_model or semantic.requested_model


def _parse_queue_timestamp(value: object, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise _QueueIntegrityError(
            f"Queued evidence has an invalid {field} timestamp.",
            health_error="queued_evidence_timestamp_invalid",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _QueueIntegrityError(
            f"Queued evidence {field} timestamp lacks a UTC offset.",
            health_error="queued_evidence_timestamp_invalid",
        )
    normalized = parsed.astimezone(UTC)
    if str(value) != format_utc(normalized):
        raise _QueueIntegrityError(
            f"Queued evidence {field} timestamp is not canonical UTC.",
            health_error="queued_evidence_timestamp_invalid",
        )
    return normalized


def _require_aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must include a UTC offset.")
    return value.astimezone(UTC)


class MemoryService:
    def __init__(
        self,
        *,
        event_store: SQLiteEventStore,
        memory_view: SQLiteMemoryView,
        extractor: CandidateExtractor,
        detector_runner: DetectorRunner,
        semantic_adjudicator: SemanticAdjudicator,
        policy_engine: PolicyEngine,
        statistics: Statistics | None = None,
        pending_evidence_max_items: int = 256,
        pending_evidence_max_bytes: int = 16_777_216,
        pending_evidence_max_attempts: int = 3,
        pending_evidence_max_age_seconds: int = 3600,
    ) -> None:
        if (
            min(
                pending_evidence_max_items,
                pending_evidence_max_bytes,
                pending_evidence_max_attempts,
                pending_evidence_max_age_seconds,
            )
            <= 0
        ):
            raise ValueError("Pending-evidence limits must be positive.")
        self.event_store = event_store
        self.memory_view = memory_view
        self.extractor = extractor
        self.detector_runner = detector_runner
        self.semantic_adjudicator = semantic_adjudicator
        self.policy_engine = policy_engine
        self.sanitizer = SecretSanitizer()
        self.semantic_timeout_ms = policy_engine.policy.limits.semantic_timeout_ms
        self.statistics = statistics or Statistics()
        self.pending_evidence_max_items = pending_evidence_max_items
        self.pending_evidence_max_bytes = pending_evidence_max_bytes
        self.pending_evidence_max_attempts = pending_evidence_max_attempts
        self.pending_evidence_max_age_seconds = pending_evidence_max_age_seconds
        self._pending_evidence_lock = asyncio.Lock()

    def _safe_source_name(self, source_name: str | None) -> str | None:
        if source_name is None:
            return None
        raw = source_name.strip()
        if not raw:
            return None
        try:
            parsed = urlsplit(raw)
        except ValueError:
            parsed = None
        if parsed is not None and parsed.scheme and parsed.hostname:
            raw = f"url.{parsed.hostname}"
        else:
            raw = raw.split("?", 1)[0].split("#", 1)[0]
        sanitized = self.sanitizer.sanitize(raw).text
        safe = "".join(
            character if character.isalnum() or character in "._:-" else "-"
            for character in sanitized
        ).strip("-")
        return (safe or "source.redacted")[:256]

    def _validate_evidence_size(self, submission: EvidenceSubmission) -> bytes:
        content_bytes = submission.content.encode("utf-8")
        if len(content_bytes) > self.policy_engine.policy.limits.max_evidence_bytes:
            raise ResourceLimitError("Evidence exceeds the active policy size boundary.")
        return content_bytes

    def _requires_semantic(
        self,
        candidate: MemoryCandidate,
        detector_results: list[DetectorResult],
    ) -> bool:
        positive_high = any(
            result.status == DetectorStatus.OK
            and result.matched is True
            and result.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
            for result in detector_results
        )
        return bool(
            positive_high
            or candidate.source_class in {SourceClass.TOOL_OUTPUT, SourceClass.AGENT_OUTPUT}
            or candidate.kind
            in {
                MemoryKind.OPERATIONAL_INSTRUCTION,
                MemoryKind.POLICY_STATEMENT,
                MemoryKind.UNKNOWN,
            }
        )

    async def _capture_evidence(
        self,
        submission: EvidenceSubmission,
        *,
        sanitized_text: str,
        queued_content: str | None = None,
    ) -> EvidenceRecord:
        evidence_id = new_id()
        event_id = new_id()
        captured_at = format_utc()
        safe_excerpt = sanitized_text[:2000]
        sanitized_digest = sha256_hex(sanitized_text.encode("utf-8"))
        sanitization = self.sanitizer.sanitize(submission.content)
        safe_source_name = self._safe_source_name(submission.source_name)
        if not hmac.compare_digest(sanitization.text, sanitized_text):
            raise LedgerError("Sanitized evidence changed before capture.")
        record = EvidenceRecord(
            evidence_id=evidence_id,
            session_id=submission.session_id,
            task_id=submission.task_id,
            source_class=submission.source_class,
            source_name=safe_source_name,
            safe_excerpt=safe_excerpt,
            content_digest=sha256_hex(submission.content.encode("utf-8")),
            content_size=len(submission.content.encode("utf-8")),
            retention_state="digest_only",
            captured_at=captured_at,
            metadata={
                "sanitized_content_digest": sanitized_digest,
                "sanitizer_version": self.sanitizer.sanitizer_version,
                "redaction_count": sanitization.redaction_count,
                "redaction_types": ",".join(sanitization.redaction_types),
            },
        )
        event = EventInput(
            event_id=event_id,
            stream_id=evidence_id,
            event_type=EventType.EVIDENCE_CAPTURED,
            actor=_source_actor(submission, safe_source_name=safe_source_name),
            session_id=submission.session_id,
            task_id=submission.task_id,
            source_class=EventSourceClass(submission.source_class.value),
            evidence_references=[
                EvidenceReference(evidence_id=evidence_id, digest=record.content_digest)
            ],
            payload=record.model_dump(mode="json"),
            occurred_at=captured_at,
        )

        async def project(connection: aiosqlite.Connection, _: list[EventEnvelope]) -> None:
            await connection.execute(
                """
                INSERT INTO evidence(
                    evidence_id, session_id, task_id, source_class, source_name,
                    safe_excerpt, content_digest, protected_content, retention_state,
                    captured_at, metadata_json, capture_event_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)
                """,
                (
                    record.evidence_id,
                    record.session_id,
                    record.task_id,
                    record.source_class.value,
                    record.source_name,
                    record.safe_excerpt,
                    record.content_digest,
                    record.retention_state,
                    record.captured_at,
                    canonical_json(record.metadata),
                    event_id,
                ),
            )
            if queued_content is not None:
                queue_state = await (
                    await connection.execute(
                        """
                        SELECT COUNT(*) AS item_count,
                               COALESCE(SUM(LENGTH(CAST(sanitized_content AS BLOB))), 0)
                                   AS byte_count
                        FROM pending_evidence
                        WHERE state = 'pending'
                        """
                    )
                ).fetchone()
                item_count = int(queue_state["item_count"]) if queue_state is not None else 0
                byte_count = int(queue_state["byte_count"]) if queue_state is not None else 0
                queued_size = len(queued_content.encode("utf-8"))
                if (
                    item_count >= self.pending_evidence_max_items
                    or byte_count + queued_size > self.pending_evidence_max_bytes
                ):
                    raise ResourceLimitError("The durable evidence queue is at capacity.")
                await connection.execute(
                    """
                    INSERT INTO pending_evidence(
                        evidence_id, state, sanitized_content, sanitized_content_digest,
                        enqueued_at, attempts, next_attempt_at, last_error_code,
                        failed_at, terminal_event_id
                    ) VALUES (?, 'pending', ?, ?, ?, 0, ?, NULL, NULL, NULL)
                    """,
                    (
                        record.evidence_id,
                        queued_content,
                        sanitized_digest,
                        captured_at,
                        captured_at,
                    ),
                )

        await self.event_store.append_with_projection([event], project)
        return record

    def _normalize_extracted_candidate(
        self,
        candidate: MemoryCandidate,
        evidence: EvidenceRecord,
    ) -> MemoryCandidate:
        sanitized = self.sanitizer.sanitize(candidate.statement)
        update: dict[str, Any] = {
            "statement": sanitized.text,
            "content_digest": sha256_hex(sanitized.text.encode("utf-8")),
            "contains_redactions": candidate.contains_redactions or sanitized.contains_secrets,
        }
        if sanitized.contains_secrets:
            update.update(
                {
                    "kind": MemoryKind.CREDENTIAL_MATERIAL,
                    "sensitivity": "credential",
                    "namespace": "credentials.redacted",
                }
            )
        normalized = candidate.model_copy(update=update)
        if normalized.session_id != evidence.session_id:
            raise LedgerError("Candidate extraction returned a mismatched session identity.")
        if normalized.task_id != evidence.task_id:
            raise LedgerError("Candidate extraction returned a mismatched task identity.")
        if normalized.source_class != evidence.source_class:
            raise LedgerError("Candidate extraction returned a mismatched source class.")
        if not normalized.source_refs:
            raise LedgerError("Candidate extraction returned mismatched provenance.")
        if any(
            reference.evidence_id != evidence.evidence_id
            or not hmac.compare_digest(reference.evidence_digest, evidence.content_digest)
            for reference in normalized.source_refs
        ):
            raise LedgerError("Candidate extraction returned mismatched evidence provenance.")
        return MemoryCandidate.model_validate(normalized.model_dump(mode="json"))

    def _risk_categories(
        self,
        detector_results: list[DetectorResult],
        semantic: SemanticAssessment | None,
    ) -> list[str]:
        categories = {
            category
            for result in detector_results
            if result.status == DetectorStatus.OK and result.matched is True
            for category in result.categories
        }
        if semantic is not None:
            categories.update(semantic.categories)
        return sorted(categories)

    def _safe_statement(self, candidate: MemoryCandidate, action: Action) -> str:
        return display_safe_statement(candidate, action=action)

    def _build_outcome_commit(
        self,
        candidate: MemoryCandidate,
        detector_results: list[DetectorResult],
        semantic: SemanticAssessment | None,
        evaluation: PolicyEvaluation,
    ) -> _OutcomeCommit:
        decision = evaluation.decision
        memory_id = new_id() if decision.actual_action in {Action.ALLOW, Action.REDACT} else None
        occurred_at = format_utc()
        expires_at = (
            format_utc(utc_now() + timedelta(seconds=evaluation.ttl_seconds))
            if evaluation.ttl_seconds is not None
            else None
        )
        candidate_event_id = new_id()
        detector_event_ids = [new_id() for _ in detector_results]
        semantic_event_id = new_id() if semantic is not None else None
        decision_event_id = new_id()
        outcome_event_id = new_id()
        references = [
            EvidenceReference(evidence_id=ref.evidence_id, digest=ref.evidence_digest)
            for ref in candidate.source_refs
        ]
        common: dict[str, Any] = {
            "stream_id": candidate.candidate_id,
            "actor": Actor(type=ActorType.POLICY, id="verity.policy-engine"),
            "session_id": candidate.session_id,
            "task_id": candidate.task_id,
            "source_class": EventSourceClass(candidate.source_class.value),
            "memory_id": memory_id,
            "evidence_references": references,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "detector_bundle_version": self.detector_runner.bundle_version,
            "semantic_model_identifier": semantic_model_identifier_for_event(semantic),
            "occurred_at": occurred_at,
        }
        inputs = [
            EventInput(
                event_id=candidate_event_id,
                event_type=EventType.MEMORY_CANDIDATE_CREATED,
                payload=candidate.model_dump(mode="json"),
                **common,
            )
        ]
        inputs.extend(
            EventInput(
                event_id=event_id,
                event_type=EventType.DETECTOR_VERDICT_RECORDED,
                payload=result.model_dump(mode="json"),
                **common,
            )
            for event_id, result in zip(detector_event_ids, detector_results, strict=True)
        )
        if semantic is not None and semantic_event_id is not None:
            inputs.append(
                EventInput(
                    event_id=semantic_event_id,
                    event_type=EventType.SEMANTIC_ASSESSMENT_RECORDED,
                    payload=semantic.model_dump(mode="json", by_alias=True),
                    **common,
                )
            )
        inputs.append(
            EventInput(
                event_id=decision_event_id,
                event_type=EventType.POLICY_DECISION_RECORDED,
                payload=decision.model_dump(mode="json"),
                **common,
            )
        )
        outcome_type = {
            Action.ALLOW: EventType.MEMORY_COMMITTED,
            Action.REDACT: EventType.MEMORY_REDACTED,
            Action.QUARANTINE: EventType.MEMORY_QUARANTINED,
            Action.BLOCK: EventType.MEMORY_BLOCKED,
        }[decision.actual_action]
        safe_statement = self._safe_statement(candidate, decision.actual_action)
        risk_categories = self._risk_categories(detector_results, semantic)
        outcome_payload = {
            "candidate_id": candidate.candidate_id,
            "decision_id": decision.decision_id,
            "memory_id": memory_id,
            "safe_statement": safe_statement,
            "namespace": candidate.namespace,
            "kind": candidate.kind.value,
            "source_class": candidate.source_class.value,
            "actual_action": decision.actual_action.value,
            "would_have_action": decision.would_have_action.value,
            "shadow_mode": decision.shadow_mode,
            "expires_at": expires_at,
            "risk_categories": risk_categories,
            "semantic_provider": _provider_summary(semantic).value,
        }
        inputs.append(
            EventInput(
                event_id=outcome_event_id,
                event_type=outcome_type,
                payload=outcome_payload,
                **common,
            )
        )

        async def project(
            connection: aiosqlite.Connection,
            envelopes: list[EventEnvelope],
        ) -> None:
            by_event_id = {envelope.event_id: envelope for envelope in envelopes}
            await connection.execute(
                """
                INSERT INTO memory_candidates(
                    candidate_id, session_id, namespace, kind, source_class,
                    record_json, creation_event_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate.candidate_id,
                    candidate.session_id,
                    candidate.namespace,
                    candidate.kind.value,
                    candidate.source_class.value,
                    canonical_json(candidate.model_dump(mode="json")),
                    candidate_event_id,
                ),
            )
            for event_id, result in zip(detector_event_ids, detector_results, strict=True):
                await connection.execute(
                    "INSERT INTO detector_results(result_id, candidate_id, record_json, event_id) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        result.result_id,
                        candidate.candidate_id,
                        canonical_json(result.model_dump(mode="json")),
                        event_id,
                    ),
                )
            if semantic is not None and semantic_event_id is not None:
                await connection.execute(
                    """
                    INSERT INTO semantic_assessments(
                        assessment_id, candidate_id, record_json, event_id
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        semantic.assessment_id,
                        candidate.candidate_id,
                        canonical_json(semantic.model_dump(mode="json", by_alias=True)),
                        semantic_event_id,
                    ),
                )
            await connection.execute(
                "INSERT INTO policy_decisions(decision_id, candidate_id, record_json, event_id) "
                "VALUES (?, ?, ?, ?)",
                (
                    decision.decision_id,
                    candidate.candidate_id,
                    canonical_json(decision.model_dump(mode="json")),
                    decision_event_id,
                ),
            )
            outcome_envelope = by_event_id[outcome_event_id]
            if memory_id is not None:
                status = "redacted" if decision.actual_action == Action.REDACT else "active"
                trust_decision = (
                    "shadow_admitted"
                    if decision.shadow_mode
                    else "redacted"
                    if decision.actual_action == Action.REDACT
                    else "allowed"
                )
                record = MemoryRecord(
                    memory_id=memory_id,
                    commit_event_id=outcome_event_id,
                    candidate_id=candidate.candidate_id,
                    session_id=candidate.session_id,
                    safe_statement=safe_statement,
                    namespace=candidate.namespace,
                    kind=candidate.kind,
                    source_class=candidate.source_class,
                    status=status,
                    trust_decision=trust_decision,
                    policy_id=decision.policy_id,
                    policy_version=decision.policy_version,
                    actual_action=decision.actual_action,
                    would_have_action=decision.would_have_action,
                    committed_at=occurred_at,
                    expires_at=expires_at,
                    shadow_admitted=decision.shadow_mode,
                    manual_approval_event_id=None,
                    risk_categories=risk_categories,
                    semantic_provider=_provider_summary(semantic),
                    last_event_id=outcome_event_id,
                    last_event_sequence=outcome_envelope.sequence_number,
                )
                serialized = canonical_json(record.model_dump(mode="json"))
                parameters = (
                    record.memory_id,
                    record.candidate_id,
                    record.namespace,
                    record.kind.value,
                    record.source_class.value,
                    record.status,
                    serialized,
                    record.last_event_sequence,
                )
                await connection.execute(
                    """
                    INSERT INTO active_memories(
                        memory_id, candidate_id, namespace, kind, source_class,
                        status, record_json, last_event_sequence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    parameters,
                )
                await connection.execute(
                    """
                    INSERT INTO memory_inventory(
                        memory_id, candidate_id, namespace, kind, source_class,
                        status, record_json, last_event_sequence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    parameters,
                )
            elif decision.actual_action == Action.QUARANTINE:
                quarantine = QuarantineRecord(
                    candidate_id=candidate.candidate_id,
                    decision_id=decision.decision_id,
                    safe_statement=safe_statement,
                    namespace=candidate.namespace,
                    kind=candidate.kind,
                    source_class=candidate.source_class,
                    risk_categories=risk_categories,
                    policy_id=decision.policy_id,
                    policy_version=decision.policy_version,
                    quarantine_event_id=outcome_event_id,
                    created_at=occurred_at,
                    actual_action=Action.QUARANTINE,
                    would_have_action=decision.would_have_action,
                    semantic_provider=_provider_summary(semantic),
                )
                await connection.execute(
                    """
                    INSERT INTO quarantined_memories(
                        candidate_id, decision_id, namespace, kind, source_class,
                        record_json, quarantine_event_id, resolution_event_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        quarantine.candidate_id,
                        quarantine.decision_id,
                        quarantine.namespace,
                        quarantine.kind.value,
                        quarantine.source_class.value,
                        canonical_json(quarantine.model_dump(mode="json")),
                        quarantine.quarantine_event_id,
                    ),
                )

        status = {
            Action.ALLOW: "active",
            Action.REDACT: "redacted",
            Action.QUARANTINE: "quarantined",
            Action.BLOCK: "blocked",
        }[decision.actual_action]
        return _OutcomeCommit(
            inputs=inputs,
            projector=project,
            outcome=CandidateOutcome(
                candidate=candidate,
                detector_results=detector_results,
                semantic_assessment=semantic,
                decision=decision,
                memory_id=memory_id,
                status=status,
            ),
        )

    async def _commit_outcomes(
        self,
        plans: Sequence[_OutcomeCommit],
        *,
        terminal: tuple[EventInput, ProjectionWriter] | None = None,
        finalizer: ProjectionWriter | None = None,
    ) -> list[CandidateOutcome]:
        inputs = [event for plan in plans for event in plan.inputs]
        if terminal is not None:
            inputs.append(terminal[0])
        if not inputs:
            if finalizer is not None:
                connection = await self.event_store._connect()
                try:
                    await connection.execute("BEGIN IMMEDIATE")
                    await finalizer(connection, [])
                    await connection.commit()
                except BaseException:
                    await connection.rollback()
                    raise
                finally:
                    await connection.close()
            return []

        async def project(
            connection: aiosqlite.Connection,
            envelopes: list[EventEnvelope],
        ) -> None:
            for plan in plans:
                await plan.projector(connection, envelopes)
            if terminal is not None:
                await terminal[1](connection, envelopes)
            if finalizer is not None:
                await finalizer(connection, envelopes)

        primary = plans[0].outcome if len(plans) == 1 else None
        async with span(
            "verity.memory.materialize",
            candidate_id=primary.candidate.candidate_id if primary is not None else None,
            action=(primary.decision.actual_action.value if primary is not None else "batch"),
            content_length=len(plans),
        ):
            await self.event_store.append_with_projection(inputs, project)
        return [plan.outcome for plan in plans]

    async def evaluate_evidence(self, submission: EvidenceSubmission) -> EvidenceEvaluation:
        content_bytes = submission.content.encode("utf-8")
        async with span(
            "verity.memory.evaluate",
            source_class=submission.source_class.value,
            content_length=len(content_bytes),
            content_digest_prefix=sha256_hex(content_bytes)[:12],
        ) as timing:
            result, _ = await self._evaluate_evidence(submission)
        await self.statistics.observe_evaluation(timing["latency_ms"])
        return result

    async def enqueue_evidence(self, submission: EvidenceSubmission) -> EvidenceRecord:
        """Durably capture sanitized hook evidence without waiting for adjudication."""

        if not self.event_store.healthy:
            raise LedgerError("The ledger is unhealthy; evidence capture is disabled.")
        content_bytes = self._validate_evidence_size(submission)
        sanitized = self.sanitizer.sanitize(submission.content)
        async with span(
            "verity.evidence.capture",
            source_class=submission.source_class.value,
            content_length=len(content_bytes),
            content_digest_prefix=sha256_hex(content_bytes)[:12],
        ) as _:
            return await self._capture_evidence(
                submission,
                sanitized_text=sanitized.text,
                queued_content=sanitized.text,
            )

    async def pending_evidence_count(self) -> int:
        return (await self.evidence_queue_counts())["pending_evidence"]

    async def evidence_queue_counts(self) -> dict[str, int]:
        connection = await self.event_store._connect()
        try:
            row = await (
                await connection.execute(
                    """
                    SELECT
                        SUM(CASE WHEN state = 'pending' THEN 1 ELSE 0 END) AS pending_count,
                        SUM(CASE WHEN state = 'failed' THEN 1 ELSE 0 END) AS failed_count
                    FROM pending_evidence
                    """
                )
            ).fetchone()
            return {
                "pending_evidence": int(row["pending_count"] or 0) if row else 0,
                "failed_evidence": int(row["failed_count"] or 0) if row else 0,
            }
        finally:
            await connection.close()

    @staticmethod
    def _load_signed_queue_evidence(
        event: EventEnvelope | None,
        *,
        evidence_id: str,
    ) -> EvidenceRecord:
        if event is None:
            raise _QueueIntegrityError(
                "Queued evidence lacks a signed capture event.",
                health_error="queued_evidence_capture_missing",
            )
        try:
            evidence = EvidenceRecord.model_validate(event.payload)
        except ValidationError as exc:
            raise _QueueIntegrityError(
                "Queued evidence has an invalid signed capture record.",
                health_error="queued_evidence_capture_invalid",
            ) from exc
        expected_source = EventSourceClass(evidence.source_class.value)
        if (
            evidence.evidence_id != evidence_id
            or event.stream_id != evidence_id
            or event.session_id != evidence.session_id
            or event.task_id != evidence.task_id
            or event.source_class != expected_source
            or not any(
                reference.evidence_id == evidence_id
                and hmac.compare_digest(reference.digest, evidence.content_digest)
                for reference in event.evidence_references
            )
        ):
            raise _QueueIntegrityError(
                "Queued evidence identity does not match its signed event.",
                health_error="queued_evidence_identity_mismatch",
            )
        return evidence

    @staticmethod
    def _validate_pending_queue_row(
        row: aiosqlite.Row,
        evidence: EvidenceRecord,
    ) -> tuple[str, str, datetime]:
        enqueued_at = _parse_queue_timestamp(row["enqueued_at"], field="enqueue")
        captured_at = _parse_queue_timestamp(evidence.captured_at, field="capture")
        _parse_queue_timestamp(row["next_attempt_at"], field="next attempt")
        if enqueued_at != captured_at:
            raise _QueueIntegrityError(
                "Queued evidence enqueue time does not match its signed capture event.",
                health_error="queued_evidence_timestamp_mismatch",
            )
        sanitized_value = row["sanitized_content"]
        if not isinstance(sanitized_value, str):
            raise _QueueIntegrityError(
                "Queued sanitized evidence content is missing.",
                health_error="queued_evidence_digest_mismatch",
            )
        sanitized_digest = sha256_hex(sanitized_value.encode("utf-8"))
        signed_digest = evidence.metadata.get("sanitized_content_digest")
        if (
            not isinstance(signed_digest, str)
            or not hmac.compare_digest(str(row["sanitized_content_digest"]), sanitized_digest)
            or not hmac.compare_digest(signed_digest, sanitized_digest)
        ):
            raise _QueueIntegrityError(
                "Queued sanitized evidence failed its signed digest check.",
                health_error="queued_evidence_digest_mismatch",
            )
        return sanitized_value, sanitized_digest, enqueued_at

    async def verify_pending_evidence_integrity(self) -> bool:
        """Boundedly validate every pending spool row before evaluation or injection."""

        if not self.event_store.healthy:
            return False
        verification = await self.event_store.verify()
        if not verification.verified or not self.event_store.healthy:
            return False
        connection = await self.event_store._connect()
        try:
            queue_state = await (
                await connection.execute(
                    """
                    SELECT COUNT(*) AS item_count,
                           COALESCE(SUM(LENGTH(CAST(sanitized_content AS BLOB))), 0)
                               AS byte_count,
                           SUM(
                               CASE WHEN state = 'failed'
                                   AND last_error_code = 'queue_integrity_error'
                               THEN 1 ELSE 0 END
                           ) AS persistent_integrity_failures
                    FROM pending_evidence
                    WHERE state = 'pending'
                       OR (state = 'failed' AND last_error_code = 'queue_integrity_error')
                    """
                )
            ).fetchone()
            item_count = int(queue_state["item_count"]) if queue_state else 0
            byte_count = int(queue_state["byte_count"]) if queue_state else 0
            persistent_failures = (
                int(queue_state["persistent_integrity_failures"] or 0) if queue_state else 0
            )
            if persistent_failures:
                self.event_store._mark_unhealthy("queued_evidence_integrity_failure_persisted")
                return False
            if (
                item_count > self.pending_evidence_max_items
                or byte_count > self.pending_evidence_max_bytes
            ):
                self.event_store._mark_unhealthy("queued_evidence_capacity_exceeded")
                return False
            rows = await (
                await connection.execute(
                    """
                    SELECT evidence_id, sanitized_content, sanitized_content_digest,
                           enqueued_at, next_attempt_at
                    FROM pending_evidence
                    WHERE state = 'pending'
                    ORDER BY enqueued_at, evidence_id
                    """
                )
            ).fetchall()
        finally:
            await connection.close()
        if not rows:
            return True
        capture_events = {
            event.stream_id: event
            for event in await self.event_store.list_events()
            if event.event_type == EventType.EVIDENCE_CAPTURED
        }
        for row in rows:
            evidence: EvidenceRecord | None = None
            try:
                evidence_id = str(row["evidence_id"])
                evidence = self._load_signed_queue_evidence(
                    capture_events.get(evidence_id),
                    evidence_id=evidence_id,
                )
                self._validate_pending_queue_row(row, evidence)
            except _QueueIntegrityError as error:
                if evidence is None:
                    self.event_store._mark_unhealthy(error.health_error)
                else:
                    try:
                        await self._record_pending_failure(
                            evidence,
                            error_code="queue_integrity_error",
                            now=utc_now(),
                            force_terminal=True,
                        )
                    finally:
                        self.event_store._mark_unhealthy(error.health_error)
                return False
        return True

    async def process_pending_evidence(
        self,
        *,
        limit: int = 25,
        now: datetime | None = None,
    ) -> int:
        """Evaluate due durable queue entries and remove each only with its outcome commit."""

        if not 1 <= limit <= 100:
            raise ValueError("Pending-evidence limit must be between 1 and 100.")
        async with self._pending_evidence_lock:
            return await self._process_pending_evidence(limit=limit, now=now)

    async def _process_pending_evidence(
        self,
        *,
        limit: int,
        now: datetime | None,
    ) -> int:
        if not await self.verify_pending_evidence_integrity():
            return 0
        current = utc_now() if now is None else _require_aware_utc(now, field="Queue time")
        connection = await self.event_store._connect()
        try:
            rows = await (
                await connection.execute(
                    """
                    SELECT evidence_id, sanitized_content, sanitized_content_digest,
                           enqueued_at, next_attempt_at
                    FROM pending_evidence
                    WHERE state = 'pending' AND next_attempt_at <= ?
                    ORDER BY enqueued_at, evidence_id
                    LIMIT ?
                    """,
                    (format_utc(current), limit),
                )
            ).fetchall()
        finally:
            await connection.close()
        if not rows:
            return 0

        capture_events = {
            event.stream_id: event
            for event in await self.event_store.list_events()
            if event.event_type == EventType.EVIDENCE_CAPTURED
        }
        processed = 0
        for row in rows:
            evidence_id = str(row["evidence_id"])
            evidence: EvidenceRecord | None = None
            try:
                evidence = self._load_signed_queue_evidence(
                    capture_events.get(evidence_id),
                    evidence_id=evidence_id,
                )
                sanitized_text, sanitized_digest, enqueued_at = self._validate_pending_queue_row(
                    row, evidence
                )
                if current - enqueued_at >= timedelta(
                    seconds=self.pending_evidence_max_age_seconds
                ):
                    await self._record_pending_failure(
                        evidence,
                        error_code="queue_expired",
                        now=current,
                        force_terminal=True,
                    )
                    continue
                submission = EvidenceSubmission(
                    session_id=evidence.session_id,
                    task_id=evidence.task_id,
                    source_class=evidence.source_class,
                    source_name=evidence.source_name,
                    content=sanitized_text,
                    metadata={},
                )
                content_bytes = sanitized_text.encode("utf-8")
                async with span(
                    "verity.memory.evaluate",
                    source_class=submission.source_class.value,
                    content_length=len(content_bytes),
                    content_digest_prefix=sanitized_digest[:12],
                ) as timing:
                    await self._evaluate_captured_evidence(
                        submission,
                        evidence,
                        sanitized_text=sanitized_text,
                        pending_evidence_id=evidence_id,
                    )
                await self.statistics.observe_evaluation(timing["latency_ms"])
                processed += 1
            except Exception as error:
                if evidence is None:
                    health_error = (
                        error.health_error
                        if isinstance(error, _QueueIntegrityError)
                        else "queued_evidence_capture_invalid"
                    )
                    self.event_store._mark_unhealthy(health_error)
                    break
                if isinstance(error, _QueueIntegrityError):
                    try:
                        await self._record_pending_failure(
                            evidence,
                            error_code="queue_integrity_error",
                            now=current,
                            force_terminal=True,
                        )
                    finally:
                        self.event_store._mark_unhealthy(error.health_error)
                    break
                else:
                    await self._record_pending_failure(
                        evidence,
                        error_code="evaluation_error",
                        now=current,
                    )
        return processed

    async def _record_pending_failure(
        self,
        evidence: EvidenceRecord,
        *,
        error_code: str,
        now: datetime,
        force_terminal: bool = False,
    ) -> bool:
        evidence_id = evidence.evidence_id
        connection = await self.event_store._connect()
        try:
            row = await (
                await connection.execute(
                    """
                    SELECT attempts, enqueued_at
                    FROM pending_evidence
                    WHERE evidence_id = ? AND state = 'pending'
                    """,
                    (evidence_id,),
                )
            ).fetchone()
        finally:
            await connection.close()
        if row is None:
            return False

        attempts = int(row["attempts"]) + 1
        terminal = force_terminal or attempts >= self.pending_evidence_max_attempts
        if not terminal:
            enqueued_at = _parse_queue_timestamp(row["enqueued_at"], field="enqueue")
            terminal = now - enqueued_at >= timedelta(seconds=self.pending_evidence_max_age_seconds)
        if terminal:
            event_id = new_id()
            failed_at = format_utc(now)
            event = EventInput(
                event_id=event_id,
                stream_id=evidence_id,
                event_type=EventType.EVIDENCE_EVALUATION_FAILED,
                actor=Actor(type=ActorType.SYSTEM, id="verity.evidence-worker"),
                session_id=evidence.session_id,
                task_id=evidence.task_id,
                source_class=EventSourceClass(evidence.source_class.value),
                evidence_references=[
                    EvidenceReference(
                        evidence_id=evidence.evidence_id,
                        digest=evidence.content_digest,
                    )
                ],
                payload={
                    "evidence_id": evidence_id,
                    "error_code": error_code,
                    "attempts": attempts,
                    "content_purged": True,
                },
                occurred_at=failed_at,
            )

            async def project_failure(
                connection: aiosqlite.Connection,
                _: list[EventEnvelope],
            ) -> None:
                cursor = await connection.execute(
                    """
                    UPDATE pending_evidence
                    SET state = 'failed', sanitized_content = NULL, attempts = ?,
                        next_attempt_at = ?, last_error_code = ?, failed_at = ?,
                        terminal_event_id = ?
                    WHERE evidence_id = ? AND state = 'pending'
                    """,
                    (
                        attempts,
                        failed_at,
                        error_code,
                        failed_at,
                        event_id,
                        evidence_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise LedgerError("Queued evidence changed before terminal failure commit.")

            await self.event_store.append_with_projection([event], project_failure)
            return True

        delay_seconds = min(300, 2 ** min(attempts, 8))
        connection = await self.event_store._connect()
        try:
            await connection.execute("BEGIN IMMEDIATE")
            cursor = await connection.execute(
                """
                UPDATE pending_evidence
                SET attempts = ?, next_attempt_at = ?, last_error_code = ?
                WHERE evidence_id = ? AND state = 'pending'
                """,
                (
                    attempts,
                    format_utc(now + timedelta(seconds=delay_seconds)),
                    error_code,
                    evidence_id,
                ),
            )
            if cursor.rowcount != 1:
                raise LedgerError("Queued evidence changed before retry scheduling.")
            await connection.commit()
        except BaseException:
            await connection.rollback()
            raise
        finally:
            await connection.close()
        return False

    async def _complete_pending_without_candidates(
        self,
        evidence: EvidenceRecord,
        *,
        pending_evidence_id: str,
    ) -> None:
        event_id = new_id()
        occurred_at = format_utc()
        event = EventInput(
            event_id=event_id,
            stream_id=evidence.evidence_id,
            event_type=EventType.EVIDENCE_EVALUATION_COMPLETED,
            actor=Actor(type=ActorType.SYSTEM, id="verity.evidence-worker"),
            session_id=evidence.session_id,
            task_id=evidence.task_id,
            source_class=EventSourceClass(evidence.source_class.value),
            evidence_references=[
                EvidenceReference(
                    evidence_id=evidence.evidence_id,
                    digest=evidence.content_digest,
                )
            ],
            payload={
                "evidence_id": evidence.evidence_id,
                "candidate_count": 0,
                "outcome": "no_candidate",
            },
            occurred_at=occurred_at,
        )

        async def project_completion(
            connection: aiosqlite.Connection,
            _: list[EventEnvelope],
        ) -> None:
            cursor = await connection.execute(
                "DELETE FROM pending_evidence WHERE evidence_id = ? AND state = 'pending'",
                (pending_evidence_id,),
            )
            if cursor.rowcount != 1:
                raise LedgerError("Queued evidence changed before completion commit.")

        await self.event_store.append_with_projection([event], project_completion)

    async def evaluate_transactional_stream(
        self,
        submission: EvidenceSubmission,
        *,
        terminal_factory: TerminalCommitFactory,
    ) -> tuple[EvidenceEvaluation, bool]:
        """Evaluate a complete stream and commit its decisions with one terminal event."""

        content_bytes = submission.content.encode("utf-8")
        async with span(
            "verity.memory.evaluate",
            source_class=submission.source_class.value,
            content_length=len(content_bytes),
            content_digest_prefix=sha256_hex(content_bytes)[:12],
        ) as timing:
            result, accepted = await self._evaluate_evidence(
                submission,
                atomic_stream=True,
                terminal_factory=terminal_factory,
            )
        await self.statistics.observe_evaluation(timing["latency_ms"])
        return result, accepted

    async def _evaluate_evidence(
        self,
        submission: EvidenceSubmission,
        *,
        atomic_stream: bool = False,
        terminal_factory: TerminalCommitFactory | None = None,
    ) -> tuple[EvidenceEvaluation, bool]:
        if not self.event_store.healthy:
            raise LedgerError("The ledger is unhealthy; memory evaluation is disabled.")
        self._validate_evidence_size(submission)
        sanitized = self.sanitizer.sanitize(submission.content)
        evidence = await self._capture_evidence(
            submission,
            sanitized_text=sanitized.text,
        )
        return await self._evaluate_captured_evidence(
            submission,
            evidence,
            sanitized_text=sanitized.text,
            atomic_stream=atomic_stream,
            terminal_factory=terminal_factory,
        )

    async def _evaluate_captured_evidence(
        self,
        submission: EvidenceSubmission,
        evidence: EvidenceRecord,
        *,
        sanitized_text: str,
        atomic_stream: bool = False,
        terminal_factory: TerminalCommitFactory | None = None,
        pending_evidence_id: str | None = None,
    ) -> tuple[EvidenceEvaluation, bool]:
        async with span(
            "verity.memory.extract",
            source_class=submission.source_class.value,
            content_length=len(sanitized_text.encode("utf-8")),
            content_digest_prefix=evidence.content_digest[:12],
        ):
            extracted = await self.extractor.extract(
                sanitized_evidence=sanitized_text,
                evidence_id=evidence.evidence_id,
                evidence_digest=evidence.content_digest,
                source_class=submission.source_class.value,
                session_id=submission.session_id,
                task_id=submission.task_id,
            )
        if pending_evidence_id is not None and not extracted:
            await self._complete_pending_without_candidates(
                evidence,
                pending_evidence_id=pending_evidence_id,
            )
            return EvidenceEvaluation(evidence=evidence, outcomes=[]), True
        evaluated: list[
            tuple[
                MemoryCandidate,
                list[DetectorResult],
                SemanticAssessment | None,
                PolicyEvaluation,
            ]
        ] = []
        for raw_candidate in extracted:
            candidate = self._normalize_extracted_candidate(raw_candidate, evidence)
            detector_results = await self.detector_runner.run(
                candidate,
                timeout_ms=self.policy_engine.policy.limits.detector_timeout_ms,
            )
            semantic = None
            if self._requires_semantic(candidate, detector_results):
                semantic = await run_semantic_assessment(
                    self.semantic_adjudicator,
                    candidate,
                    timeout_ms=self.semantic_timeout_ms,
                )
            async with span(
                "verity.policy.decide",
                candidate_id=candidate.candidate_id,
                policy_version=self.policy_engine.policy.version,
                source_class=candidate.source_class.value,
            ):
                policy_evaluation = self.policy_engine.evaluate(
                    candidate,
                    detector_results,
                    semantic,
                )
            evaluated.append((candidate, detector_results, semantic, policy_evaluation))
        accepted = all(
            evaluation.decision.actual_action in {Action.ALLOW, Action.REDACT}
            for _, _, _, evaluation in evaluated
        )
        if atomic_stream and not accepted:
            adjusted: list[
                tuple[
                    MemoryCandidate,
                    list[DetectorResult],
                    SemanticAssessment | None,
                    PolicyEvaluation,
                ]
            ] = []
            for candidate, detector_results, semantic, evaluation in evaluated:
                if evaluation.decision.actual_action in {Action.ALLOW, Action.REDACT}:
                    evaluation = PolicyEvaluation(
                        decision=evaluation.decision.model_copy(
                            update={
                                "actual_action": Action.BLOCK,
                                "reason_codes": [
                                    *evaluation.decision.reason_codes,
                                    "stream.atomic_abort",
                                ],
                            }
                        ),
                        ttl_seconds=None,
                        manual_review_required=evaluation.manual_review_required,
                    )
                adjusted.append((candidate, detector_results, semantic, evaluation))
            evaluated = adjusted

        plans = [
            self._build_outcome_commit(candidate, detector_results, semantic, evaluation)
            for candidate, detector_results, semantic, evaluation in evaluated
        ]
        preview = [plan.outcome for plan in plans]
        terminal = terminal_factory(preview, accepted) if terminal_factory is not None else None
        finalizer: ProjectionWriter | None = None
        if pending_evidence_id is not None:

            async def finalize_pending(
                connection: aiosqlite.Connection,
                _: list[EventEnvelope],
            ) -> None:
                cursor = await connection.execute(
                    "DELETE FROM pending_evidence WHERE evidence_id = ?",
                    (pending_evidence_id,),
                )
                if cursor.rowcount != 1:
                    raise LedgerError("Queued evidence changed before outcome commit.")

            finalizer = finalize_pending
        outcomes = await self._commit_outcomes(
            plans,
            terminal=terminal,
            finalizer=finalizer,
        )
        return EvidenceEvaluation(evidence=evidence, outcomes=outcomes), accepted

    async def session_start_context(self, *, session_id: str, token_budget: int) -> str:
        if not self.event_store.healthy:
            return ""
        if not await self.verify_pending_evidence_integrity():
            return ""
        verification = await self.event_store.verify()
        if not verification.verified:
            return ""
        await self.expire_due_memories()
        if not self.event_store.healthy:
            return ""
        async with span("verity.memory.inject", content_length=0) as _:
            return render_approved_memory(
                await self.memory_view.list_active(),
                token_budget=token_budget,
            )

    async def expire_due_memories(self, *, now: datetime | None = None) -> list[str]:
        """Append explicit expiration events and atomically remove due active memory."""

        if not self.event_store.healthy:
            raise LedgerError("The ledger is unhealthy; expiration is disabled.")
        current = (now or utc_now()).astimezone(UTC)
        due: list[MemoryRecord] = []
        for record in await self.memory_view.list_active():
            if record.expires_at is None:
                continue
            try:
                expires_at = datetime.fromisoformat(record.expires_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise LedgerError("An active memory expiration is invalid.") from exc
            if expires_at.tzinfo is None:
                raise LedgerError("An active memory expiration lacks a UTC offset.")
            if expires_at.astimezone(UTC) <= current:
                due.append(record)
        if not due:
            return []

        occurred_at = format_utc(current)
        events = [
            EventInput(
                event_id=new_id(),
                stream_id=record.candidate_id,
                event_type=EventType.MEMORY_EXPIRED,
                actor=Actor(type=ActorType.SYSTEM, id="verity.expiration-sweep"),
                session_id=record.session_id,
                source_class=EventSourceClass.SYSTEM,
                memory_id=record.memory_id,
                policy_id=record.policy_id,
                policy_version=record.policy_version,
                payload={
                    "memory_id": record.memory_id,
                    "commit_event_id": record.commit_event_id,
                    "expires_at": record.expires_at,
                    "reason": "ttl_elapsed",
                },
                occurred_at=occurred_at,
            )
            for record in due
        ]

        async def project(
            connection: aiosqlite.Connection,
            envelopes: list[EventEnvelope],
        ) -> None:
            for record, envelope in zip(due, envelopes, strict=True):
                expired = record.model_copy(
                    update={
                        "status": "expired",
                        "last_event_id": envelope.event_id,
                        "last_event_sequence": envelope.sequence_number,
                    }
                )
                await connection.execute(
                    "DELETE FROM active_memories WHERE memory_id = ?",
                    (record.memory_id,),
                )
                await connection.execute(
                    """
                    UPDATE memory_inventory
                    SET status = 'expired', record_json = ?, last_event_sequence = ?
                    WHERE memory_id = ?
                    """,
                    (
                        canonical_json(expired.model_dump(mode="json")),
                        envelope.sequence_number,
                        record.memory_id,
                    ),
                )

        await self.event_store.append_with_projection(events, project)
        return [record.memory_id for record in due]
