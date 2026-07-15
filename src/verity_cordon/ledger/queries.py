"""Content-safe read projections for CLI and Control Room."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from pydantic import ValidationError

from verity_cordon.core.errors import LedgerError, NotFoundError
from verity_cordon.core.models import (
    DetectorResult,
    DetectorStatus,
    EventEnvelope,
    EventType,
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
