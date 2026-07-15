"""Retroactive evaluation of active memory against the current trust policy."""

from __future__ import annotations

import hmac
from typing import Any, ClassVar

import aiosqlite
from pydantic import ValidationError

from verity_cordon.core.errors import (
    ConflictError,
    LedgerIntegrityError,
    NotFoundError,
)
from verity_cordon.core.models import (
    Action,
    Actor,
    ActorType,
    EventEnvelope,
    EventInput,
    EventSourceClass,
    EventType,
    EvidenceReference,
    Identifier,
    MemoryCandidate,
    MemoryKind,
    MemoryRecord,
    PolicyDecision,
    PolicyIdentifier,
    ProviderSummaryState,
    SemanticAssessment,
    Sensitivity,
    StrictModel,
    format_utc,
    new_id,
)
from verity_cordon.crypto.canonical import canonical_json, sha256_hex
from verity_cordon.ledger.verify import LedgerVerifier
from verity_cordon.memory.service import MemoryService
from verity_cordon.policies.models import PolicyDocument
from verity_cordon.semantic.base import run_semantic_assessment
from verity_cordon.telemetry.instrumentation import span


class RescanResult(StrictModel):
    """Content-safe result suitable for the CLI and local API surfaces."""

    memory_id: Identifier
    candidate_id: Identifier
    original_candidate_id: Identifier
    original_candidate_event_id: Identifier
    rescan_candidate_event_id: Identifier
    decision_id: Identifier
    detector_result_ids: list[Identifier]
    semantic_assessment_id: Identifier | None
    actual_action: Action
    would_have_action: Action
    policy_id: PolicyIdentifier
    policy_version: str
    detector_bundle_version: str
    semantic_provider: ProviderSummaryState
    revoked: bool
    revocation_event_id: Identifier | None
    active_memory_count_after: int
    unrelated_active_memories_preserved: int
    ledger_verified: bool
    view_consistent: bool


def _operator_actor(actor_id: str) -> Actor:
    safe = "".join(
        character if character.isalnum() or character in "._:-" else "-" for character in actor_id
    )
    if len(safe) < 8:
        safe = f"operator.{safe}"
    return Actor(type=ActorType.OPERATOR, id=safe[:128])


def _provider_summary(semantic: SemanticAssessment | None) -> ProviderSummaryState:
    if semantic is None:
        return ProviderSummaryState.DETERMINISTIC_ONLY
    mapping = {
        "failed": ProviderSummaryState.FAILED,
        "live_openai": ProviderSummaryState.LIVE_OPENAI,
        "recorded_fixture": ProviderSummaryState.RECORDED_FIXTURE,
    }
    return mapping[semantic.provider_state.value]


class RetroactiveRescanService:
    """Re-evaluate a signed candidate and revoke unsafe active memory atomically."""

    _REVOCATION_ACTIONS: ClassVar[frozenset[Action]] = frozenset(
        {Action.REDACT, Action.QUARANTINE, Action.BLOCK}
    )

    def __init__(self, memory_service: MemoryService) -> None:
        self.memory_service = memory_service
        self.store = memory_service.event_store
        self.view = memory_service.memory_view

    def _safe_reason(self, reason: str) -> str:
        sanitized = self.memory_service.sanitizer.sanitize(reason.strip()).text
        if not sanitized:
            raise ConflictError("A non-empty rescan reason is required.")
        return sanitized[:500]

    @staticmethod
    def _validate_candidate_event(
        event: EventEnvelope,
        candidate: MemoryCandidate,
    ) -> None:
        expected_references = [
            (reference.evidence_id, reference.evidence_digest)
            for reference in candidate.source_refs
        ]
        observed_references = [
            (reference.evidence_id, reference.digest) for reference in event.evidence_references
        ]
        expected_source = EventSourceClass(candidate.source_class.value)
        if (
            event.event_type is not EventType.MEMORY_CANDIDATE_CREATED
            or event.stream_id != candidate.candidate_id
            or event.session_id != candidate.session_id
            or event.task_id != candidate.task_id
            or event.source_class is not expected_source
            or expected_references != observed_references
            or not hmac.compare_digest(
                candidate.content_digest,
                sha256_hex(candidate.statement.encode("utf-8")),
            )
        ):
            raise LedgerIntegrityError("The signed candidate provenance is inconsistent.")

    async def _load_verified_target(
        self,
        memory_id: str,
    ) -> tuple[MemoryRecord, MemoryCandidate, EventEnvelope]:
        if not self.store.healthy:
            raise LedgerIntegrityError("Rescan requires a healthy signed ledger.")
        verification = await self.store.verify()
        if not verification.verified or not verification.materialized_view_consistent:
            raise LedgerIntegrityError("Rescan requires a verified ledger and memory view.")
        events = await self.store.list_events()
        activation_events = [
            event for event in events if event.event_type is EventType.POLICY_ACTIVATED
        ]
        if not activation_events:
            raise LedgerIntegrityError("Rescan requires one signed active policy.")
        active_policy_event = max(activation_events, key=lambda event: event.sequence_number)
        try:
            signed_policy = PolicyDocument.model_validate(active_policy_event.payload.get("policy"))
        except ValidationError as exc:
            raise LedgerIntegrityError("The signed active policy is invalid.") from exc
        runtime_policy = self.memory_service.policy_engine.policy
        if (
            signed_policy.policy_id != runtime_policy.policy_id
            or signed_policy.version != runtime_policy.version
            or not hmac.compare_digest(signed_policy.content_digest, runtime_policy.content_digest)
        ):
            raise ConflictError("The runtime policy does not match the signed active policy.")
        active, _, _ = LedgerVerifier.replay_memory_state(events)
        raw_target = active.get(memory_id)
        if raw_target is None:
            raise NotFoundError("The active memory was not found.")
        try:
            target = MemoryRecord.model_validate(raw_target)
        except ValidationError as exc:
            raise LedgerIntegrityError("The signed active-memory state is invalid.") from exc

        candidate_events = [
            event
            for event in events
            if event.event_type is EventType.MEMORY_CANDIDATE_CREATED
            and event.stream_id == target.candidate_id
        ]
        if len(candidate_events) != 1:
            raise LedgerIntegrityError("The active memory lacks one signed candidate event.")
        candidate_event = candidate_events[0]
        try:
            candidate = MemoryCandidate.model_validate(candidate_event.payload)
        except ValidationError as exc:
            raise LedgerIntegrityError("The signed candidate payload is invalid.") from exc
        self._validate_candidate_event(candidate_event, candidate)

        commit_events = [event for event in events if event.event_id == target.commit_event_id]
        if len(commit_events) != 1:
            raise LedgerIntegrityError("The active memory lacks one signed commit event.")
        commit_event = commit_events[0]
        if (
            commit_event.event_type
            not in {
                EventType.MEMORY_COMMITTED,
                EventType.MEMORY_REDACTED,
                EventType.MEMORY_APPROVED,
            }
            or commit_event.stream_id != target.candidate_id
            or commit_event.memory_id != target.memory_id
            or commit_event.session_id != candidate.session_id
            or commit_event.payload.get("candidate_id") != target.candidate_id
            or commit_event.payload.get("memory_id") != target.memory_id
            or commit_event.payload.get("namespace") != candidate.namespace
            or commit_event.payload.get("kind") != candidate.kind.value
            or commit_event.payload.get("source_class") != candidate.source_class.value
            or candidate_event.sequence_number >= commit_event.sequence_number
            or target.last_event_id != target.commit_event_id
            or target.last_event_sequence != commit_event.sequence_number
        ):
            raise LedgerIntegrityError("The active memory commit does not match its candidate.")
        return target, candidate, candidate_event

    def _prepare_candidate(
        self,
        candidate: MemoryCandidate,
        *,
        candidate_event_id: str,
        safe_reason: str,
    ) -> MemoryCandidate:
        """Create a sanitized, independently signed rescan candidate."""

        sanitized = self.memory_service.sanitizer.sanitize(candidate.statement)
        updates: dict[str, object] = {
            "candidate_id": new_id(),
            "statement": sanitized.text,
            "content_digest": sha256_hex(sanitized.text.encode("utf-8")),
            "contains_redactions": candidate.contains_redactions or sanitized.contains_secrets,
            "durability_rationale": (
                f"Retroactive rescan of signed candidate event {candidate_event_id}. "
                f"Operator reason: {safe_reason}"
            )[:1000],
            "extractor_provider": "deterministic",
            "extractor_version": (
                f"verity-rescan-sanitizer-{self.memory_service.sanitizer.sanitizer_version}"
            )[:128],
            "created_at": format_utc(),
        }
        if sanitized.contains_secrets:
            updates.update(
                {
                    "kind": MemoryKind.CREDENTIAL_MATERIAL,
                    "sensitivity": Sensitivity.CREDENTIAL,
                    "namespace": "credentials.redacted",
                }
            )
        return MemoryCandidate.model_validate(
            candidate.model_copy(update=updates).model_dump(mode="json")
        )

    @staticmethod
    def _event_common(
        *,
        candidate: MemoryCandidate,
        target: MemoryRecord,
        decision: PolicyDecision,
        detector_bundle_version: str,
        semantic_model_identifier: str | None,
        occurred_at: str,
    ) -> dict[str, Any]:
        return {
            "stream_id": candidate.candidate_id,
            "session_id": candidate.session_id,
            "task_id": candidate.task_id,
            "source_class": EventSourceClass(candidate.source_class.value),
            "memory_id": target.memory_id,
            "evidence_references": [
                EvidenceReference(
                    evidence_id=reference.evidence_id,
                    digest=reference.evidence_digest,
                )
                for reference in candidate.source_refs
            ],
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "detector_bundle_version": detector_bundle_version,
            "semantic_model_identifier": semantic_model_identifier,
            "occurred_at": occurred_at,
        }

    async def rescan(
        self,
        memory_id: str,
        *,
        actor_id: str,
        reason: str,
        confirmed: bool,
    ) -> RescanResult:
        if not confirmed:
            raise ConflictError("Retroactive rescan requires explicit confirmation.")
        safe_reason = self._safe_reason(reason)
        target, original_candidate, candidate_event = await self._load_verified_target(memory_id)
        candidate = self._prepare_candidate(
            original_candidate,
            candidate_event_id=candidate_event.event_id,
            safe_reason=safe_reason,
        )

        policy_engine = self.memory_service.policy_engine
        detector_runner = self.memory_service.detector_runner
        semantic_adjudicator = self.memory_service.semantic_adjudicator
        semantic_timeout_ms = self.memory_service.semantic_timeout_ms
        policy_digest = policy_engine.policy.content_digest
        detector_bundle_version = detector_runner.bundle_version

        detector_results = await detector_runner.run(
            candidate,
            timeout_ms=policy_engine.policy.limits.detector_timeout_ms,
        )
        semantic: SemanticAssessment | None = None
        if self.memory_service._requires_semantic(candidate, detector_results):
            semantic = await run_semantic_assessment(
                semantic_adjudicator,
                candidate,
                timeout_ms=semantic_timeout_ms,
            )
        async with span(
            "verity.policy.decide",
            candidate_id=candidate.candidate_id,
            policy_version=policy_engine.policy.version,
            source_class=candidate.source_class.value,
        ):
            evaluation = policy_engine.evaluate(candidate, detector_results, semantic)
        decision = evaluation.decision

        if (
            self.memory_service.policy_engine is not policy_engine
            or self.memory_service.detector_runner is not detector_runner
            or self.memory_service.semantic_adjudicator is not semantic_adjudicator
            or self.memory_service.policy_engine.policy.content_digest != policy_digest
            or self.memory_service.detector_runner.bundle_version != detector_bundle_version
        ):
            raise ConflictError("The active evaluation configuration changed during rescan.")

        occurred_at = format_utc()
        semantic_model_identifier = (
            (semantic.returned_model or semantic.requested_model) if semantic is not None else None
        )
        common = self._event_common(
            candidate=candidate,
            target=target,
            decision=decision,
            detector_bundle_version=detector_bundle_version,
            semantic_model_identifier=semantic_model_identifier,
            occurred_at=occurred_at,
        )
        rescan_candidate_event_id = new_id()
        detector_event_ids = [new_id() for _ in detector_results]
        semantic_event_id = new_id() if semantic is not None else None
        decision_event_id = new_id()
        revoke = decision.actual_action in self._REVOCATION_ACTIONS
        revocation_event_id = new_id() if revoke else None

        inputs: list[EventInput] = [
            EventInput(
                event_id=rescan_candidate_event_id,
                event_type=EventType.MEMORY_CANDIDATE_CREATED,
                actor=_operator_actor(actor_id),
                payload=candidate.model_dump(mode="json"),
                **common,
            )
        ]
        inputs.extend(
            EventInput(
                event_id=event_id,
                event_type=EventType.DETECTOR_VERDICT_RECORDED,
                actor=Actor(type=ActorType.DETECTOR, id="verity.detector-runner"),
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
                    actor=Actor(type=ActorType.AGENT, id="verity.semantic-adjudicator"),
                    payload=semantic.model_dump(mode="json", by_alias=True),
                    **common,
                )
            )
        inputs.append(
            EventInput(
                event_id=decision_event_id,
                event_type=EventType.POLICY_DECISION_RECORDED,
                actor=Actor(type=ActorType.POLICY, id="verity.policy-engine"),
                payload=decision.model_dump(mode="json"),
                **common,
            )
        )
        if revoke and revocation_event_id is not None:
            revocation_common = {
                **common,
                "source_class": EventSourceClass.OPERATOR_ACTION,
            }
            inputs.append(
                EventInput(
                    event_id=revocation_event_id,
                    event_type=EventType.MEMORY_REVOKED,
                    actor=_operator_actor(actor_id),
                    payload={
                        "memory_id": target.memory_id,
                        "commit_event_id": target.commit_event_id,
                        "candidate_id": target.candidate_id,
                        "original_candidate_event_id": candidate_event.event_id,
                        "rescan_candidate_id": candidate.candidate_id,
                        "rescan_candidate_event_id": rescan_candidate_event_id,
                        "rescan_decision_id": decision.decision_id,
                        "reason": safe_reason,
                        "previous_status": target.status,
                        "actual_action": decision.actual_action.value,
                        "would_have_action": decision.would_have_action.value,
                        "evaluated_content_digest": candidate.content_digest,
                    },
                    **revocation_common,
                )
            )

        async def project(
            connection: aiosqlite.Connection,
            envelopes: list[EventEnvelope],
        ) -> None:
            active_policy_row = await (
                await connection.execute(
                    """
                    SELECT policy_id, version, content_digest
                    FROM policies
                    WHERE active = 1
                    """
                )
            ).fetchone()
            if (
                active_policy_row is None
                or str(active_policy_row["policy_id"]) != decision.policy_id
                or str(active_policy_row["version"]) != decision.policy_version
                or not hmac.compare_digest(
                    str(active_policy_row["content_digest"]),
                    decision.policy_digest,
                )
            ):
                raise ConflictError("The signed active policy changed during rescan.")
            row = await (
                await connection.execute(
                    """
                    SELECT candidate_id, record_json, last_event_sequence
                    FROM active_memories
                    WHERE memory_id = ?
                    """,
                    (target.memory_id,),
                )
            ).fetchone()
            if (
                row is None
                or str(row["candidate_id"]) != target.candidate_id
                or int(row["last_event_sequence"]) != target.last_event_sequence
                or str(row["record_json"]) != canonical_json(target.model_dump(mode="json"))
            ):
                raise ConflictError("The active memory changed during rescan.")

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
                    rescan_candidate_event_id,
                ),
            )
            for event_id, result in zip(detector_event_ids, detector_results, strict=True):
                await connection.execute(
                    """
                    INSERT INTO detector_results(result_id, candidate_id, record_json, event_id)
                    VALUES (?, ?, ?, ?)
                    """,
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
                """
                INSERT INTO policy_decisions(decision_id, candidate_id, record_json, event_id)
                VALUES (?, ?, ?, ?)
                """,
                (
                    decision.decision_id,
                    candidate.candidate_id,
                    canonical_json(decision.model_dump(mode="json")),
                    decision_event_id,
                ),
            )
            if revoke and revocation_event_id is not None:
                revocation_envelope = next(
                    envelope for envelope in envelopes if envelope.event_id == revocation_event_id
                )
                revoked = target.model_copy(
                    update={
                        "status": "revoked",
                        "last_event_id": revocation_event_id,
                        "last_event_sequence": revocation_envelope.sequence_number,
                    }
                )
                cursor = await connection.execute(
                    """
                    DELETE FROM active_memories
                    WHERE memory_id = ? AND candidate_id = ? AND last_event_sequence = ?
                    """,
                    (target.memory_id, target.candidate_id, target.last_event_sequence),
                )
                if cursor.rowcount != 1:
                    raise ConflictError("The active memory changed during rescan.")
                cursor = await connection.execute(
                    """
                    UPDATE memory_inventory
                    SET status = 'revoked', record_json = ?, last_event_sequence = ?
                    WHERE memory_id = ? AND candidate_id = ? AND last_event_sequence = ?
                    """,
                    (
                        canonical_json(revoked.model_dump(mode="json")),
                        revocation_envelope.sequence_number,
                        target.memory_id,
                        target.candidate_id,
                        target.last_event_sequence,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ConflictError("The memory inventory changed during rescan.")

        if revoke:
            async with span(
                "verity.memory.revoke",
                memory_id=target.memory_id,
                candidate_id=candidate.candidate_id,
                action=decision.actual_action.value,
            ):
                await self.store.append_with_projection(inputs, project)
        else:
            await self.store.append_with_projection(inputs, project)
        verification = await self.store.verify()
        if not verification.verified or not verification.materialized_view_consistent:
            raise LedgerIntegrityError("Rescan committed but ledger verification failed.")
        active_count = len(await self.view.list_active())
        return RescanResult(
            memory_id=target.memory_id,
            candidate_id=candidate.candidate_id,
            original_candidate_id=original_candidate.candidate_id,
            original_candidate_event_id=candidate_event.event_id,
            rescan_candidate_event_id=rescan_candidate_event_id,
            decision_id=decision.decision_id,
            detector_result_ids=[result.result_id for result in detector_results],
            semantic_assessment_id=(semantic.assessment_id if semantic is not None else None),
            actual_action=decision.actual_action,
            would_have_action=decision.would_have_action,
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            detector_bundle_version=detector_bundle_version,
            semantic_provider=_provider_summary(semantic),
            revoked=revoke,
            revocation_event_id=revocation_event_id,
            active_memory_count_after=active_count,
            unrelated_active_memories_preserved=max(0, active_count - (0 if revoke else 1)),
            ledger_verified=verification.verified,
            view_consistent=verification.materialized_view_consistent,
        )
