"""Evidence-to-decision memory firewall pipeline."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import aiosqlite
from pydantic import Field

from verity_cordon.core.errors import LedgerError
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
from verity_cordon.policies.engine import PolicyEngine, PolicyEvaluation
from verity_cordon.semantic.base import run_semantic_assessment


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


def _source_actor(submission: EvidenceSubmission) -> Actor:
    mapping = {
        SourceClass.USER_INPUT: ActorType.CODEX,
        SourceClass.TOOL_OUTPUT: ActorType.TOOL,
        SourceClass.AGENT_OUTPUT: ActorType.AGENT,
    }
    actor_type = mapping.get(submission.source_class, ActorType.SYSTEM)
    raw_id = submission.source_name or f"source.{submission.source_class.value}"
    safe_id = "".join(
        character if character.isalnum() or character in "._:-" else "-"
        for character in raw_id
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
    return ProviderSummaryState.RECORDED_FIXTURE


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
    ) -> None:
        self.event_store = event_store
        self.memory_view = memory_view
        self.extractor = extractor
        self.detector_runner = detector_runner
        self.semantic_adjudicator = semantic_adjudicator
        self.policy_engine = policy_engine
        self.sanitizer = SecretSanitizer()
        self.semantic_timeout_ms = policy_engine.policy.limits.semantic_timeout_ms

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
    ) -> EvidenceRecord:
        evidence_id = new_id()
        event_id = new_id()
        captured_at = format_utc()
        safe_excerpt = sanitized_text[:2000]
        record = EvidenceRecord(
            evidence_id=evidence_id,
            session_id=submission.session_id,
            task_id=submission.task_id,
            source_class=submission.source_class,
            source_name=submission.source_name,
            safe_excerpt=safe_excerpt,
            content_digest=sha256_hex(submission.content.encode("utf-8")),
            content_size=len(submission.content.encode("utf-8")),
            retention_state="digest_only",
            captured_at=captured_at,
            metadata={},
        )
        event = EventInput(
            event_id=event_id,
            stream_id=evidence_id,
            event_type=EventType.EVIDENCE_CAPTURED,
            actor=_source_actor(submission),
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
        if not any(
            reference.evidence_id == evidence.evidence_id
            for reference in normalized.source_refs
        ):
            raise LedgerError("Candidate extraction returned mismatched provenance.")
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
        if action != Action.REDACT or candidate.contains_redactions:
            return candidate.statement
        return f"[REDACTED BY POLICY: {candidate.namespace}]"

    async def _commit_outcome(
        self,
        candidate: MemoryCandidate,
        detector_results: list[DetectorResult],
        semantic: SemanticAssessment | None,
        evaluation: PolicyEvaluation,
    ) -> CandidateOutcome:
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
            "semantic_model_identifier": (
                semantic.returned_model if semantic is not None else None
            ),
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

        await self.event_store.append_with_projection(inputs, project)
        status = {
            Action.ALLOW: "active",
            Action.REDACT: "redacted",
            Action.QUARANTINE: "quarantined",
            Action.BLOCK: "blocked",
        }[decision.actual_action]
        return CandidateOutcome(
            candidate=candidate,
            detector_results=detector_results,
            semantic_assessment=semantic,
            decision=decision,
            memory_id=memory_id,
            status=status,
        )

    async def evaluate_evidence(self, submission: EvidenceSubmission) -> EvidenceEvaluation:
        if not self.event_store.healthy:
            raise LedgerError("The ledger is unhealthy; memory evaluation is disabled.")
        sanitized = self.sanitizer.sanitize(submission.content)
        evidence = await self._capture_evidence(
            submission,
            sanitized_text=sanitized.text,
        )
        extracted = await self.extractor.extract(
            sanitized_evidence=sanitized.text,
            evidence_id=evidence.evidence_id,
            evidence_digest=evidence.content_digest,
            source_class=submission.source_class.value,
            session_id=submission.session_id,
            task_id=submission.task_id,
        )
        outcomes: list[CandidateOutcome] = []
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
            policy_evaluation = self.policy_engine.evaluate(
                candidate,
                detector_results,
                semantic,
            )
            outcomes.append(
                await self._commit_outcome(
                    candidate,
                    detector_results,
                    semantic,
                    policy_evaluation,
                )
            )
        return EvidenceEvaluation(evidence=evidence, outcomes=outcomes)

    async def session_start_context(self, *, session_id: str, token_budget: int) -> str:
        del session_id
        if not self.event_store.healthy:
            return ""
        verification = await self.event_store.verify()
        if not verification.verified:
            return ""
        await self.expire_due_memories()
        if not self.event_store.healthy:
            return ""
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
                expires_at = datetime.fromisoformat(
                    record.expires_at.replace("Z", "+00:00")
                )
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
