"""Content-safe read projections for CLI and Control Room."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from pydantic import ValidationError

from verity_cordon.core.errors import LedgerError, NotFoundError
from verity_cordon.core.models import (
    ActorType,
    DetectorResult,
    DetectorStatus,
    EventEnvelope,
    EventType,
    EvidenceRecord,
    LedgerVerification,
    MemoryCandidate,
    MemoryRecord,
    PolicyDecision,
    SemanticAssessment,
    SourceClass,
)
from verity_cordon.crypto.canonical import parse_json_strict
from verity_cordon.ledger.store import SQLiteEventStore
from verity_cordon.memory.safe_display import display_safe_candidate
from verity_cordon.telemetry.instrumentation import Statistics

_SAFE_RISK_CATEGORIES = frozenset(
    {
        "ambiguous",
        "anomalous_size",
        "benign_fact",
        "benign_preference",
        "concealed_instruction",
        "credential_material",
        "cross_task_contamination",
        "data_exfiltration",
        "persistent_instruction",
        "privilege_escalation",
        "protected_namespace",
        "secret_material",
        "self_reinforcement",
        "tool_hijack",
        "untrusted_authority",
    }
)
_SAFE_COMPONENT_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PROJECTION_ONLY_FAILURES = frozenset(
    {
        "auxiliary_projection_drift",
        "materialized_view_drift",
    }
)


def _safe_categories(values: Iterable[str]) -> list[str]:
    """Allow-list display taxonomy; plugin/model free text is never reflected."""

    supplied = tuple(values)
    categories = {value for value in supplied if value in _SAFE_RISK_CATEGORIES}
    if any(value not in _SAFE_RISK_CATEGORIES for value in supplied):
        categories.add("unclassified_signal")
    return sorted(categories)


def _safe_component_label(value: str | None) -> str | None:
    if value is None:
        return None
    return value if _SAFE_COMPONENT_LABEL.fullmatch(value) else "untrusted-label-hidden"


def _safe_detector_result(result: DetectorResult) -> dict[str, Any]:
    projected = result.model_dump(mode="json")
    projected["categories"] = _safe_categories(result.categories)
    projected["metadata"] = {}
    projected["failure_class"] = "detector_failure" if result.failure_class is not None else None
    projected["detector_version"] = _safe_component_label(result.detector_version)
    if result.status is not DetectorStatus.OK:
        projected["message"] = "Detector evaluation did not return a usable verdict."
    elif result.matched:
        projected["message"] = "Detector reported a policy-relevant match."
    else:
        projected["message"] = "Detector reported no policy-relevant match."
    return projected


def _safe_semantic_assessment(assessment: SemanticAssessment) -> dict[str, Any]:
    projected = assessment.model_dump(mode="json", by_alias=True)
    projected["categories"] = _safe_categories(assessment.categories)
    projected["requested_model"] = _safe_component_label(assessment.requested_model)
    projected["returned_model"] = _safe_component_label(assessment.returned_model)
    projected["prompt_version"] = _safe_component_label(assessment.prompt_version)
    projected["rationale"] = (
        "Semantic rationale is hidden from routine views; structured risk fields are shown."
        if assessment.rationale is not None
        else None
    )
    return projected


def _status_from_events(events: Iterable[EventEnvelope]) -> str:
    status = "unknown"
    for event in events:
        if event.event_type is EventType.MEMORY_COMMITTED:
            status = "active"
        elif event.event_type is EventType.MEMORY_REDACTED:
            status = "redacted"
        elif event.event_type is EventType.MEMORY_QUARANTINED:
            status = "quarantined"
        elif event.event_type is EventType.MEMORY_BLOCKED:
            status = "blocked"
        elif event.event_type is EventType.MEMORY_APPROVED:
            status = "redacted" if event.payload.get("actual_action") == "redact" else "active"
        elif event.event_type is EventType.MEMORY_REVOKED:
            status = "revoked"
        elif event.event_type is EventType.MEMORY_SUPERSEDED:
            status = "superseded"
        elif event.event_type is EventType.MEMORY_EXPIRED:
            status = "expired"
    return status


def _candidate_lifecycle_events(
    events: list[EventEnvelope],
    candidate_events: list[EventEnvelope],
) -> list[EventEnvelope]:
    """Include later events that reference a memory created by this candidate.

    A retroactive rescan has its own candidate stream, but its revocation event
    references the original memory ID. Candidate status must therefore follow
    the memory lifecycle across streams without mixing the rescan's detector or
    semantic records into the original candidate evaluation.
    """

    memory_ids = {event.memory_id for event in candidate_events if event.memory_id is not None}
    if not memory_ids:
        return candidate_events
    direct_event_ids = {event.event_id for event in candidate_events}
    linked = [
        event
        for event in events
        if event.event_id in direct_event_ids or event.memory_id in memory_ids
    ]
    return sorted(linked, key=lambda event: event.sequence_number)


class LedgerQueries:
    def __init__(self, store: SQLiteEventStore, statistics: Statistics | None = None) -> None:
        self.store = store
        self.runtime_statistics = statistics or Statistics()

    async def list_memories(self) -> list[MemoryRecord]:
        verification = await self.store.verify()
        if not verification.verified or not verification.materialized_view_consistent:
            raise LedgerError(
                "Materialized memory records are unavailable while verification fails."
            )
        connection = await self.store._connect()
        try:
            rows = await (
                await connection.execute(
                    "SELECT record_json FROM memory_inventory ORDER BY last_event_sequence DESC"
                )
            ).fetchall()
        finally:
            await connection.close()
        return [
            MemoryRecord.model_validate(parse_json_strict(str(row["record_json"]))) for row in rows
        ]

    async def get_memory(self, memory_id: str) -> MemoryRecord:
        items = await self.list_memories()
        match = next((item for item in items if item.memory_id == memory_id), None)
        if match is None:
            raise NotFoundError("The memory record was not found.")
        return match

    async def get_evidence_status(self, evidence_id: str) -> dict[str, Any]:
        """Return a content-safe signed checkpoint for one captured evidence item.

        Queue rows are intentionally not treated as proof of completion. A terminal
        state requires either a signed failure/completion event or a complete signed
        candidate-policy-outcome set committed atomically with removal from the queue.
        """

        events, verification = await self._signed_projection_events()
        captures = [
            event
            for event in events
            if event.event_type is EventType.EVIDENCE_CAPTURED and event.stream_id == evidence_id
        ]
        if len(captures) != 1:
            if not captures:
                raise NotFoundError("The evidence record was not found.")
            raise LedgerError("The signed evidence history has duplicate captures.")
        capture_event = captures[0]
        try:
            evidence = EvidenceRecord.model_validate(capture_event.payload)
        except ValidationError as exc:
            raise LedgerError("The signed evidence capture payload is invalid.") from exc
        if evidence.evidence_id != evidence_id:
            raise LedgerError("The signed evidence capture has mismatched identity.")

        related = [
            event
            for event in events
            if event.event_id != capture_event.event_id
            and any(reference.evidence_id == evidence_id for reference in event.evidence_references)
        ]
        candidate_events = [
            event for event in related if event.event_type is EventType.MEMORY_CANDIDATE_CREATED
        ]
        decision_events = [
            event for event in related if event.event_type is EventType.POLICY_DECISION_RECORDED
        ]
        outcome_types = {
            EventType.MEMORY_COMMITTED,
            EventType.MEMORY_REDACTED,
            EventType.MEMORY_QUARANTINED,
            EventType.MEMORY_BLOCKED,
        }
        outcome_events = [event for event in related if event.event_type in outcome_types]
        failure_events = [
            event for event in related if event.event_type is EventType.EVIDENCE_EVALUATION_FAILED
        ]
        completion_events = [
            event
            for event in related
            if event.event_type is EventType.EVIDENCE_EVALUATION_COMPLETED
        ]
        rescan_revocation_events = [
            event
            for event in related
            if event.event_type is EventType.MEMORY_REVOKED
            and isinstance(event.payload.get("rescan_candidate_id"), str)
        ]
        if len(failure_events) > 1 or len(completion_events) > 1:
            raise LedgerError("The signed evidence history has conflicting terminal events.")
        if failure_events and (completion_events or outcome_events):
            raise LedgerError("The signed evidence history has conflicting outcomes.")

        try:
            candidates = [
                MemoryCandidate.model_validate(event.payload) for event in candidate_events
            ]
            decisions = [PolicyDecision.model_validate(event.payload) for event in decision_events]
        except ValidationError as exc:
            raise LedgerError("The signed evidence decision history is invalid.") from exc
        candidate_ids = [candidate.candidate_id for candidate in candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise LedgerError("The signed evidence history has duplicate candidates.")
        for event, candidate in zip(candidate_events, candidates, strict=True):
            if (
                event.stream_id != candidate.candidate_id
                or event.session_id != evidence.session_id
                or event.task_id != evidence.task_id
                or event.source_class is None
                or event.source_class.value != evidence.source_class.value
                or candidate.session_id != evidence.session_id
                or candidate.task_id != evidence.task_id
                or candidate.source_class != evidence.source_class
                or not any(
                    reference.evidence_id == evidence_id
                    and reference.evidence_digest == evidence.content_digest
                    for reference in candidate.source_refs
                )
            ):
                raise LedgerError("A signed evidence candidate has mismatched provenance.")
        original_candidates = [
            (event, candidate)
            for event, candidate in zip(candidate_events, candidates, strict=True)
            if event.actor.type is not ActorType.OPERATOR
        ]
        rescan_candidates = [
            (event, candidate)
            for event, candidate in zip(candidate_events, candidates, strict=True)
            if event.actor.type is ActorType.OPERATOR
        ]
        for event, candidate in rescan_candidates:
            if (
                event.memory_id is None
                or candidate.extractor_provider != "deterministic"
                or not candidate.extractor_version.startswith("verity-rescan-sanitizer-")
            ):
                raise LedgerError("A signed operator candidate is not a valid rescan record.")
        original_candidate_ids = [candidate.candidate_id for _, candidate in original_candidates]
        rescan_candidate_ids = [candidate.candidate_id for _, candidate in rescan_candidates]
        decision_by_candidate = {decision.candidate_id: decision for decision in decisions}
        if len(decision_by_candidate) != len(decisions):
            raise LedgerError("The signed evidence history has duplicate decisions.")
        if set(decision_by_candidate) - set(candidate_ids):
            raise LedgerError("A signed evidence decision lacks its candidate.")
        if any(
            event.stream_id != decision.candidate_id
            for event, decision in zip(decision_events, decisions, strict=True)
        ):
            raise LedgerError("A signed evidence decision has mismatched identity.")
        decision_event_by_candidate = {
            decision.candidate_id: event
            for event, decision in zip(decision_events, decisions, strict=True)
        }
        outcome_candidate_ids: list[str] = []
        action_event_types = {
            "allow": EventType.MEMORY_COMMITTED,
            "redact": EventType.MEMORY_REDACTED,
            "quarantine": EventType.MEMORY_QUARANTINED,
            "block": EventType.MEMORY_BLOCKED,
        }
        for event in outcome_events:
            candidate_id = event.payload.get("candidate_id")
            action = event.payload.get("actual_action")
            decision = decision_by_candidate.get(str(candidate_id))
            if (
                not isinstance(candidate_id, str)
                or not isinstance(action, str)
                or action_event_types.get(action) is not event.event_type
                or event.stream_id != candidate_id
                or candidate_id not in original_candidate_ids
                or decision is None
                or decision.actual_action.value != action
                or event.policy_id != decision.policy_id
                or event.policy_version != decision.policy_version
            ):
                raise LedgerError("A signed evidence outcome payload is invalid.")
            outcome_candidate_ids.append(candidate_id)
        if completion_events:
            completion = completion_events[0]
            if (
                completion.stream_id != evidence_id
                or completion.session_id != evidence.session_id
                or completion.task_id != evidence.task_id
                or completion.payload
                != {
                    "evidence_id": evidence_id,
                    "candidate_count": 0,
                    "outcome": "no_candidate",
                }
            ):
                raise LedgerError("The signed empty evidence completion is invalid.")

        connection = await self.store._connect()
        try:
            queue_row = await (
                await connection.execute(
                    "SELECT state FROM pending_evidence WHERE evidence_id = ?",
                    (evidence_id,),
                )
            ).fetchone()
        finally:
            await connection.close()
        queue_state = str(queue_row["state"]) if queue_row is not None else None

        complete_candidate_set = bool(
            original_candidate_ids
            and queue_state is None
            and set(original_candidate_ids)
            == set(outcome_candidate_ids)
            == {
                candidate_id
                for candidate_id in decision_by_candidate
                if candidate_id in set(original_candidate_ids)
            }
            and len(outcome_candidate_ids) == len(original_candidate_ids)
        )
        signed_failure = bool(failure_events and queue_state == "failed")
        signed_empty_completion = bool(
            completion_events and not candidate_ids and queue_state is None
        )
        signed_terminal = signed_failure or signed_empty_completion or complete_candidate_set
        terminal_outcome = "failed" if signed_failure else "completed" if signed_terminal else None
        terminal_events = (
            failure_events
            if signed_failure
            else completion_events
            if signed_empty_completion
            else outcome_events
            if complete_candidate_set
            else []
        )
        actions = (
            [str(event.payload["actual_action"]) for event in outcome_events]
            if complete_candidate_set
            else []
        )
        policy_versions = sorted(
            {
                decision.policy_version
                for decision in decisions
                if decision.candidate_id in set(original_candidate_ids)
            }
        )
        rescan_summaries: list[tuple[int, dict[str, Any]]] = []
        revoking_actions = {"redact", "quarantine", "block"}
        for candidate_event, candidate in rescan_candidates:
            decision = decision_by_candidate.get(candidate.candidate_id)
            decision_event = decision_event_by_candidate.get(candidate.candidate_id)
            if decision is None or decision_event is None:
                raise LedgerError("A signed rescan candidate lacks its decision.")
            matching_revocations = [
                event
                for event in rescan_revocation_events
                if event.payload.get("rescan_candidate_id") == candidate.candidate_id
            ]
            should_revoke = decision.actual_action.value in revoking_actions
            if len(matching_revocations) != (1 if should_revoke else 0):
                raise LedgerError("A signed rescan has an inconsistent revocation outcome.")
            revocation = matching_revocations[0] if matching_revocations else None
            if revocation is not None and (
                revocation.memory_id != candidate_event.memory_id
                or revocation.payload.get("memory_id") != candidate_event.memory_id
                or revocation.payload.get("rescan_candidate_event_id") != candidate_event.event_id
                or revocation.payload.get("rescan_decision_id") != decision.decision_id
                or revocation.payload.get("actual_action") != decision.actual_action.value
                or revocation.payload.get("would_have_action") != decision.would_have_action.value
            ):
                raise LedgerError("A signed rescan revocation has mismatched identity.")
            rescan_summaries.append(
                (
                    decision_event.sequence_number,
                    {
                        "candidate_id": candidate.candidate_id,
                        "candidate_event_id": candidate_event.event_id,
                        "decision_id": decision.decision_id,
                        "actual_action": decision.actual_action.value,
                        "would_have_action": decision.would_have_action.value,
                        "policy_id": decision.policy_id,
                        "policy_version": decision.policy_version,
                        "memory_id": candidate_event.memory_id,
                        "revoked": revocation is not None,
                        "revocation_event_id": (
                            revocation.event_id if revocation is not None else None
                        ),
                    },
                )
            )
        latest_rescan = (
            max(rescan_summaries, key=lambda item: item[0])[1] if rescan_summaries else None
        )
        ready = bool(
            terminal_outcome == "completed"
            and verification.verified
            and verification.materialized_view_consistent
        )
        warning_code = (
            "view_inconsistent"
            if verification.failure_class == "materialized_view_drift"
            else "ledger_unverified"
            if not verification.verified
            else "evaluation_failed"
            if terminal_outcome == "failed"
            else "evaluation_pending"
            if not signed_terminal
            else None
        )
        return {
            "schema_version": "1.0.0",
            "evidence_id": evidence.evidence_id,
            "evaluation_state": "signed_terminal" if signed_terminal else "pending",
            "terminal_outcome": terminal_outcome,
            "terminal_event_ids": [event.event_id for event in terminal_events],
            "candidate_ids": original_candidate_ids if complete_candidate_set else [],
            "actual_actions": actions,
            "policy_versions": policy_versions if complete_candidate_set else [],
            "rescan_count": len(rescan_candidate_ids),
            "latest_rescan": latest_rescan,
            "session_id": evidence.session_id,
            "task_id": evidence.task_id,
            "source_class": evidence.source_class.value,
            "source_name": evidence.source_name,
            "captured_at": evidence.captured_at,
            "content_digest": evidence.content_digest,
            "ledger_verified": verification.verified,
            "view_consistent": verification.materialized_view_consistent,
            "fresh_session_ready": ready,
            "warning_code": warning_code,
        }

    async def _signed_projection_events(
        self,
    ) -> tuple[list[EventEnvelope], LedgerVerification]:
        """Return events only when their cryptographic chain remains trustworthy.

        Projection drift is allowed through so callers can present the signed source of
        truth while clearly reporting that ledger/projection verification failed.
        """

        verification = await self.store.verify()
        if (
            not verification.verified
            and verification.failure_class not in _PROJECTION_ONLY_FAILURES
        ):
            raise LedgerError(
                "Signed candidate history is unavailable while the ledger is invalid."
            )
        return await self.store.list_events(), verification

    async def list_candidate_summaries(self) -> list[dict[str, Any]]:
        events, _ = await self._signed_projection_events()
        by_stream: dict[str, list[EventEnvelope]] = {}
        for event in events:
            by_stream.setdefault(event.stream_id, []).append(event)

        results: list[dict[str, Any]] = []
        candidate_events = [
            event for event in events if event.event_type is EventType.MEMORY_CANDIDATE_CREATED
        ]
        for candidate_event in reversed(candidate_events):
            try:
                model = MemoryCandidate.model_validate(candidate_event.payload)
            except ValidationError as exc:
                raise LedgerError("A signed candidate payload is invalid.") from exc
            if model.candidate_id != candidate_event.stream_id:
                raise LedgerError("A signed candidate payload has mismatched identity.")
            candidate = display_safe_candidate(model)
            stream_events = by_stream[candidate_event.stream_id]
            lifecycle_events = _candidate_lifecycle_events(events, stream_events)
            detector_models = [
                DetectorResult.model_validate(event.payload)
                for event in stream_events
                if event.event_type is EventType.DETECTOR_VERDICT_RECORDED
            ]
            semantic_models = [
                SemanticAssessment.model_validate(event.payload)
                for event in stream_events
                if event.event_type is EventType.SEMANTIC_ASSESSMENT_RECORDED
            ]
            decision_models = [
                PolicyDecision.model_validate(event.payload)
                for event in stream_events
                if event.event_type is EventType.POLICY_DECISION_RECORDED
            ]
            if any(item.candidate_id != model.candidate_id for item in detector_models):
                raise LedgerError("A signed detector payload has mismatched identity.")
            if any(item.candidate_id != model.candidate_id for item in semantic_models):
                raise LedgerError("A signed semantic payload has mismatched identity.")
            if any(item.candidate_id != model.candidate_id for item in decision_models):
                raise LedgerError("A signed policy-decision payload has mismatched identity.")
            decision = decision_models[-1] if decision_models else None
            semantic = semantic_models[-1] if semantic_models else None
            detector_categories = {
                category
                for detector in detector_models
                if detector.status is DetectorStatus.OK and detector.matched is True
                for category in detector.categories
            }
            semantic_categories = semantic.categories if semantic is not None else []
            results.append(
                {
                    "candidate_id": candidate["candidate_id"],
                    "safe_statement": candidate["statement"],
                    "namespace": candidate["namespace"],
                    "kind": candidate["kind"],
                    "source_class": candidate["source_class"],
                    "session_id": candidate["session_id"],
                    "created_at": candidate["created_at"],
                    "status": _status_from_events(lifecycle_events),
                    "policy_id": decision.policy_id if decision else None,
                    "policy_version": decision.policy_version if decision else None,
                    "actual_action": decision.actual_action.value if decision else None,
                    "would_have_action": (decision.would_have_action.value if decision else None),
                    "shadow_mode": decision.shadow_mode if decision else False,
                    "risk_categories": _safe_categories(
                        detector_categories.union(semantic_categories)
                    ),
                    "semantic_provider": (
                        semantic.provider_state.value if semantic else "deterministic_only"
                    ),
                }
            )
        return results

    async def get_candidate_detail(self, candidate_id: str) -> dict[str, Any]:
        events, verification = await self._signed_projection_events()
        related_events = [event for event in events if event.stream_id == candidate_id]
        candidate_events = [
            event
            for event in related_events
            if event.event_type is EventType.MEMORY_CANDIDATE_CREATED
        ]
        if not candidate_events:
            raise NotFoundError("The candidate record was not found.")
        try:
            candidate_model = MemoryCandidate.model_validate(candidate_events[-1].payload)
            detector_models = [
                DetectorResult.model_validate(event.payload)
                for event in related_events
                if event.event_type is EventType.DETECTOR_VERDICT_RECORDED
            ]
            semantic_models = [
                SemanticAssessment.model_validate(event.payload)
                for event in related_events
                if event.event_type is EventType.SEMANTIC_ASSESSMENT_RECORDED
            ]
            decision_models = [
                PolicyDecision.model_validate(event.payload)
                for event in related_events
                if event.event_type is EventType.POLICY_DECISION_RECORDED
            ]
        except ValidationError as exc:
            raise LedgerError("A signed candidate-detail payload is invalid.") from exc
        if candidate_model.candidate_id != candidate_id:
            raise LedgerError("A signed candidate payload has mismatched identity.")
        if (
            any(item.candidate_id != candidate_id for item in detector_models)
            or any(item.candidate_id != candidate_id for item in semantic_models)
            or any(item.candidate_id != candidate_id for item in decision_models)
        ):
            raise LedgerError("A signed candidate-detail payload has mismatched identity.")
        if not decision_models:
            raise NotFoundError("The candidate decision was not found.")
        decision = decision_models[-1]
        semantic = semantic_models[-1] if semantic_models else None
        candidate = display_safe_candidate(candidate_model)
        lifecycle_events = _candidate_lifecycle_events(events, related_events)
        return {
            "candidate": candidate,
            "status": _status_from_events(lifecycle_events),
            "detector_results": [_safe_detector_result(item) for item in detector_models],
            "semantic_assessment": _safe_semantic_assessment(semantic) if semantic else None,
            "policy_decision": {
                "policy_id": decision.policy_id,
                "policy_version": decision.policy_version,
                "matched_rule_id": decision.matched_rule_id,
                "mode": decision.mode.value,
                "actual_action": decision.actual_action.value,
                "would_have_action": decision.would_have_action.value,
                "shadow_mode": decision.shadow_mode,
                "reason": ", ".join(
                    code if _SAFE_COMPONENT_LABEL.fullmatch(code) else "policy-reason-hidden"
                    for code in decision.reason_codes
                ),
            },
            "event_ids": [event.event_id for event in lifecycle_events],
            "ledger_verified": verification.verified,
        }

    def _event_summary(self, event: EventEnvelope, *, chain_status: str) -> dict[str, Any]:
        action = event.payload.get("actual_action")
        source_class = event.source_class.value if event.source_class else None
        if source_class not in {item.value for item in SourceClass}:
            source_class = None
        return {
            "event_id": event.event_id,
            "sequence_number": event.sequence_number,
            "event_type": event.event_type.value,
            "occurred_at": event.occurred_at,
            "memory_id": event.memory_id,
            "source_class": source_class,
            "action": action if isinstance(action, str) else None,
            "policy_version": event.policy_version,
            "event_hash": event.event_hash,
            "chain_status": chain_status,
        }

    async def list_event_summaries(self) -> list[dict[str, Any]]:
        events, verification = await self._signed_projection_events()
        chain_status = "verified" if verification.verified else "projection_drift"
        return [self._event_summary(event, chain_status=chain_status) for event in reversed(events)]

    async def statistics(self) -> dict[str, Any]:
        verification = await self.store.verify()
        runtime = await self.runtime_statistics.snapshot()
        counts = {
            "total_candidates": 0,
            "allowed": 0,
            "redacted": 0,
            "quarantined": 0,
            "blocked": 0,
            "revoked": 0,
        }
        if (
            not verification.verified
            and verification.failure_class not in _PROJECTION_ONLY_FAILURES
        ):
            return {
                "schema_version": "1.0.0",
                "counts": counts,
                "semantic_timeouts": 0,
                "detector_failures": 0,
                "average_evaluation_latency_ms": runtime["average_evaluation_latency_ms"],
                "ledger_state": "invalid",
                "statistics_available": False,
            }

        events = await self.store.list_events()
        try:
            decisions = [
                PolicyDecision.model_validate(event.payload)
                for event in events
                if event.event_type is EventType.POLICY_DECISION_RECORDED
            ]
            detector_results = [
                DetectorResult.model_validate(event.payload)
                for event in events
                if event.event_type is EventType.DETECTOR_VERDICT_RECORDED
            ]
            semantic_assessments = [
                SemanticAssessment.model_validate(event.payload)
                for event in events
                if event.event_type is EventType.SEMANTIC_ASSESSMENT_RECORDED
            ]
        except ValidationError as exc:
            raise LedgerError("Signed statistics history is invalid.") from exc
        revoked = {
            event.memory_id
            for event in events
            if event.event_type is EventType.MEMORY_REVOKED and event.memory_id is not None
        }
        counts = {
            "total_candidates": len(decisions),
            "allowed": sum(item.actual_action.value == "allow" for item in decisions),
            "redacted": sum(item.actual_action.value == "redact" for item in decisions),
            "quarantined": sum(item.actual_action.value == "quarantine" for item in decisions),
            "blocked": sum(item.actual_action.value == "block" for item in decisions),
            "revoked": len(revoked),
        }
        return {
            "schema_version": "1.0.0",
            "counts": counts,
            "semantic_timeouts": sum(
                assessment.failure is not None and assessment.failure.class_name == "timeout"
                for assessment in semantic_assessments
            ),
            "detector_failures": sum(
                result.status is not DetectorStatus.OK for result in detector_results
            ),
            "average_evaluation_latency_ms": runtime["average_evaluation_latency_ms"],
            "ledger_state": "verified" if verification.verified else "invalid",
            "statistics_available": True,
        }
