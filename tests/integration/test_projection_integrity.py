"""Signed source-of-truth and content-safe candidate-detail projection tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from verity_cordon.core.errors import LedgerError, LedgerIntegrityError
from verity_cordon.core.models import (
    Action,
    Actor,
    ActorType,
    DetectorResult,
    DetectorStatus,
    EventInput,
    EventType,
    MemoryCandidate,
    Mode,
    PersistenceIntent,
    PolicyDecision,
    ProviderState,
    RequestedProvider,
    SemanticAssessment,
    Severity,
    Signal,
    SourceClass,
    format_utc,
    new_id,
)
from verity_cordon.crypto.canonical import canonical_json, parse_json_strict
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.detectors.builtin import builtin_detectors
from verity_cordon.detectors.runner import DetectorRunner
from verity_cordon.ledger.queries import LedgerQueries
from verity_cordon.ledger.store import SQLiteEventStore
from verity_cordon.memory.materializer import SQLiteMemoryView
from verity_cordon.memory.service import EvidenceSubmission, MemoryService
from verity_cordon.policies.engine import PolicyEngine
from verity_cordon.policies.load import load_builtin_policy
from verity_cordon.policies.repository import SQLitePolicyRepository
from verity_cordon.semantic.fixture import FixtureCandidateExtractor, FixtureSemanticAdjudicator

UNTRUSTED_ECHO = "UNTRUSTED candidate echo: synthetic-demo-artifact-sink"


async def _build_service(
    tmp_path: Path,
    *,
    detectors=None,
    adjudicator=None,
) -> tuple[MemoryService, SQLiteEventStore, LedgerQueries]:
    key = FileKeyProvider.generate(tmp_path / "signing-key.pem")
    store = SQLiteEventStore(tmp_path / "verity.sqlite3", key, tmp_path / "ledger-head.json")
    await store.initialize()
    policy = load_builtin_policy(Mode.ENFORCE)
    await SQLitePolicyRepository(store).ensure_initial(policy)
    view = SQLiteMemoryView(store)
    service = MemoryService(
        event_store=store,
        memory_view=view,
        extractor=FixtureCandidateExtractor(),
        detector_runner=DetectorRunner(detectors or builtin_detectors()),
        semantic_adjudicator=adjudicator or FixtureSemanticAdjudicator(),
        policy_engine=PolicyEngine(policy),
    )
    return service, store, LedgerQueries(store)


async def _evaluate_tool_fact(service: MemoryService) -> str:
    evaluation = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            source_name="synthetic-docs-tool",
            content="The release manifest is generated from release.yaml.",
        )
    )
    assert len(evaluation.outcomes) == 1
    return evaluation.outcomes[0].candidate.candidate_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("table", "candidate_column", "field"),
    [
        ("memory_candidates", "candidate_id", "statement"),
        ("detector_results", "candidate_id", "message"),
        ("semantic_assessments", "candidate_id", "rationale"),
        ("policy_decisions", "candidate_id", "reason_codes"),
    ],
)
async def test_candidate_detail_uses_signed_events_and_flags_auxiliary_tampering(
    tmp_path: Path,
    table: str,
    candidate_column: str,
    field: str,
) -> None:
    service, store, queries = await _build_service(tmp_path)
    candidate_id = await _evaluate_tool_fact(service)
    before = await queries.get_candidate_detail(candidate_id)
    assert before["ledger_verified"] is True

    connection = await store._connect()
    try:
        row = await (
            await connection.execute(
                f"SELECT record_json FROM {table} WHERE {candidate_column} = ? LIMIT 1",  # noqa: S608
                (candidate_id,),
            )
        ).fetchone()
        assert row is not None
        record = parse_json_strict(str(row["record_json"]))
        assert isinstance(record, dict)
        record[field] = [UNTRUSTED_ECHO] if field == "reason_codes" else UNTRUSTED_ECHO
        await connection.execute(
            f"UPDATE {table} SET record_json = ? WHERE {candidate_column} = ?",  # noqa: S608
            (canonical_json(record), candidate_id),
        )
        await connection.commit()
    finally:
        await connection.close()

    detail = await queries.get_candidate_detail(candidate_id)
    verification = await store.verify()

    assert detail["candidate"]["statement"] == (
        "The release manifest is generated from release.yaml."
    )
    assert UNTRUSTED_ECHO not in canonical_json(detail)
    assert detail["ledger_verified"] is False
    assert verification.verified is False
    assert verification.failure_class == "auxiliary_projection_drift"


class _EchoDetector:
    detector_id = "echo-detector"
    detector_version = "1.0.0"

    async def inspect(self, candidate: MemoryCandidate) -> DetectorResult:
        return DetectorResult(
            result_id=new_id(),
            candidate_id=candidate.candidate_id,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            execution_order=0,
            status=DetectorStatus.OK,
            matched=False,
            severity=Severity.INFO,
            confidence=0.5,
            categories=[UNTRUSTED_ECHO],
            message=UNTRUSTED_ECHO,
            metadata={"untrusted": UNTRUSTED_ECHO},
            failure_class=None,
            latency_ms=0,
            recorded_at=format_utc(),
        )


class _EchoAdjudicator:
    provider_label = "recorded_fixture"

    async def assess(self, candidate: MemoryCandidate) -> SemanticAssessment:
        return SemanticAssessment(
            assessment_id=new_id(),
            candidate_id=candidate.candidate_id,
            provider_state=ProviderState.RECORDED_FIXTURE,
            requested_provider=RequestedProvider.FIXTURE,
            requested_model=None,
            returned_model="verity-fixture-v1",
            prompt_version="semantic-risk-v1",
            risk_score=0.05,
            categories=["benign_fact", UNTRUSTED_ECHO],
            persistence_intent=PersistenceIntent.NONE,
            authority_claim=Signal.NONE,
            exfiltration_risk=0.0,
            tool_hijack_risk=0.0,
            cross_task_risk=0.0,
            secret_risk=0.0,
            rationale=UNTRUSTED_ECHO,
            recommended_disposition=Action.ALLOW,
            sanitized_content_digest=candidate.content_digest,
            cache_hit=False,
            latency_ms=0,
            failure=None,
            assessed_at=format_utc(),
        )


@pytest.mark.asyncio
async def test_candidate_detail_never_reflects_plugin_or_semantic_free_text(tmp_path: Path) -> None:
    service, store, queries = await _build_service(
        tmp_path,
        detectors=[_EchoDetector()],
        adjudicator=_EchoAdjudicator(),
    )
    candidate_id = await _evaluate_tool_fact(service)

    detail = await queries.get_candidate_detail(candidate_id)
    encoded = canonical_json(detail)

    assert detail["ledger_verified"] is True
    assert (await store.verify()).verified is True
    assert UNTRUSTED_ECHO not in encoded
    assert detail["detector_results"][0]["metadata"] == {}
    assert detail["detector_results"][0]["message"] == (
        "Detector reported no policy-relevant match."
    )
    assert detail["detector_results"][0]["categories"] == ["unclassified_signal"]
    assert detail["semantic_assessment"]["categories"] == [
        "benign_fact",
        "unclassified_signal",
    ]
    assert detail["semantic_assessment"]["rationale"].startswith("Semantic rationale is hidden")


@pytest.mark.asyncio
async def test_tampered_memory_projection_is_never_returned(tmp_path: Path) -> None:
    service, store, queries = await _build_service(tmp_path)
    await _evaluate_tool_fact(service)
    memory = (await queries.list_memories())[0]
    connection = await store._connect()
    try:
        tampered = memory.model_copy(update={"safe_statement": UNTRUSTED_ECHO})
        await connection.execute(
            "UPDATE memory_inventory SET record_json = ? WHERE memory_id = ?",
            (canonical_json(tampered.model_dump(mode="json")), memory.memory_id),
        )
        await connection.commit()
    finally:
        await connection.close()

    with pytest.raises(LedgerError, match="verification fails"):
        await queries.list_memories()


@pytest.mark.asyncio
async def test_event_timeline_refuses_cryptographically_invalid_history(tmp_path: Path) -> None:
    service, store, queries = await _build_service(tmp_path)
    await _evaluate_tool_fact(service)
    connection = await store._connect()
    try:
        row = await (
            await connection.execute(
                "SELECT sequence_number, envelope_json FROM events ORDER BY sequence_number LIMIT 1"
            )
        ).fetchone()
        assert row is not None
        envelope = parse_json_strict(str(row["envelope_json"]))
        assert isinstance(envelope, dict)
        envelope["actor"]["id"] = "tampered.actor"
        await connection.execute("DROP TRIGGER events_no_update")
        await connection.execute(
            "UPDATE events SET envelope_json = ? WHERE sequence_number = ?",
            (canonical_json(envelope), int(row["sequence_number"])),
        )
        await connection.commit()
    finally:
        await connection.close()

    with pytest.raises(LedgerError, match="history is unavailable"):
        await queries.list_event_summaries()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("safe_excerpt", "tampered provenance"),
        ("source_class", "agent_output"),
        ("metadata_json", '{"tampered":true}'),
        ("retention_state", "expired"),
    ],
)
async def test_evidence_projection_is_bound_to_signed_capture(
    tmp_path: Path,
    column: str,
    value: str,
) -> None:
    service, store, _ = await _build_service(tmp_path)
    await _evaluate_tool_fact(service)
    connection = await store._connect()
    try:
        await connection.execute(
            f"UPDATE evidence SET {column} = ?",  # noqa: S608
            (value,),
        )
        await connection.commit()
    finally:
        await connection.close()

    verification = await store.verify()

    assert verification.verified is False
    assert verification.failure_class == "evidence_projection_drift"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE policies SET validated_json = '{}' WHERE active = 1",
        "UPDATE policies SET active = 0 WHERE active = 1",
        "UPDATE policies SET content_digest = '" + ("0" * 64) + "' WHERE active = 1",
    ],
)
async def test_active_policy_projection_tampering_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    _, store, _ = await _build_service(tmp_path)
    connection = await store._connect()
    try:
        await connection.execute(mutation)
        await connection.commit()
    finally:
        await connection.close()

    verification = await store.verify()

    assert verification.verified is False
    assert verification.failure_class == "policy_projection_drift"
    with pytest.raises(LedgerIntegrityError, match="verification failed"):
        await SQLitePolicyRepository(store).get_active()


@pytest.mark.asyncio
async def test_policy_decision_requires_a_preceding_signed_activation(tmp_path: Path) -> None:
    key = FileKeyProvider.generate(tmp_path / "signing-key.pem")
    store = SQLiteEventStore(tmp_path / "verity.sqlite3", key, tmp_path / "ledger-head.json")
    await store.initialize()
    policy = load_builtin_policy(Mode.ENFORCE)
    candidate_id = new_id()
    decision = PolicyDecision(
        decision_id=new_id(),
        candidate_id=candidate_id,
        policy_id=policy.policy_id,
        policy_version=policy.version,
        policy_digest=policy.content_digest,
        matched_rule_id=None,
        mode=policy.mode,
        actual_action=Action.QUARANTINE,
        would_have_action=Action.QUARANTINE,
        shadow_mode=False,
        reason_codes=["synthetic_missing_activation"],
        detector_result_ids=[],
        semantic_assessment_id=None,
        decided_at=format_utc(),
    )
    await store.append(
        [
            EventInput(
                stream_id=candidate_id,
                event_type=EventType.POLICY_DECISION_RECORDED,
                actor=Actor(type=ActorType.POLICY, id="verity.policy-engine"),
                policy_id=policy.policy_id,
                policy_version=policy.version,
                payload=decision.model_dump(mode="json"),
            )
        ]
    )

    verification = await store.verify()

    assert verification.verified is False
    assert verification.failure_class == "policy_decision_activation_mismatch"
