"""Retroactive rescan acceptance tests over signed candidate history."""

from __future__ import annotations

import asyncio

import pytest
from typer.testing import CliRunner

from tests.integration.test_memory_pipeline import POISONED_DOCS, build_service
from verity_cordon.cli.main import app
from verity_cordon.core.config import Settings
from verity_cordon.core.errors import ConflictError, NotFoundError
from verity_cordon.core.models import Action, EventType, Mode, SourceClass, new_id
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.daemon.runtime import build_runtime
from verity_cordon.detectors.builtin import builtin_detectors
from verity_cordon.detectors.runner import DetectorRunner
from verity_cordon.ledger.queries import LedgerQueries
from verity_cordon.memory.rescan import RetroactiveRescanService
from verity_cordon.memory.service import EvidenceSubmission
from verity_cordon.memory.trust_actions import TrustActions
from verity_cordon.policies.engine import PolicyEngine
from verity_cordon.policies.load import load_builtin_policy
from verity_cordon.policies.repository import SQLitePolicyRepository


@pytest.mark.asyncio
async def test_enforcement_rescan_revokes_only_shadow_admitted_poison(tmp_path) -> None:
    service, store, view = await build_service(tmp_path, mode=Mode.SHADOW)
    evaluation = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            task_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            source_name="poisoned-docs-mcp",
            content=POISONED_DOCS,
        )
    )
    malicious_outcome = next(
        outcome
        for outcome in evaluation.outcomes
        if "demo_artifact_sink" in outcome.candidate.statement
    )
    assert malicious_outcome.memory_id is not None
    active_before = await view.list_active()
    malicious = next(
        item for item in active_before if item.memory_id == malicious_outcome.memory_id
    )
    legitimate = next(item for item in active_before if item.memory_id != malicious.memory_id)
    original_events = await store.list_events()
    original_candidate = next(
        event
        for event in original_events
        if event.event_type is EventType.MEMORY_CANDIDATE_CREATED
        and event.stream_id == malicious.candidate_id
    )

    enforce_policy = load_builtin_policy(Mode.ENFORCE)
    await SQLitePolicyRepository(store).activate(
        enforce_policy,
        actor_id="operator.demo",
        reason="Test enforcement activation.",
    )
    service.policy_engine = PolicyEngine(enforce_policy)
    original_events = await store.list_events()
    result = await RetroactiveRescanService(service).rescan(
        malicious.memory_id,
        actor_id="operator.demo",
        reason="Current enforcement policy rejects persistent tool authority.",
        confirmed=True,
    )

    active_after = await view.list_active()
    new_events = (await store.list_events())[len(original_events) :]
    assert result.actual_action is Action.QUARANTINE
    assert result.revoked is True
    assert result.revocation_event_id is not None
    assert result.original_candidate_id == malicious.candidate_id
    assert result.candidate_id != malicious.candidate_id
    assert result.original_candidate_event_id == original_candidate.event_id
    assert [item.memory_id for item in active_after] == [legitimate.memory_id]
    rescan_candidate = next(
        event for event in new_events if event.event_type is EventType.MEMORY_CANDIDATE_CREATED
    )
    assert rescan_candidate.event_id == result.rescan_candidate_event_id
    assert rescan_candidate.stream_id == result.candidate_id
    assert original_candidate.event_id in rescan_candidate.payload["durability_rationale"]
    assert "Current enforcement policy" in rescan_candidate.payload["durability_rationale"]
    assert any(
        event.event_type is EventType.POLICY_DECISION_RECORDED
        and event.payload["decision_id"] == result.decision_id
        for event in new_events
    )
    assert any(
        event.event_type is EventType.MEMORY_REVOKED
        and event.memory_id == malicious.memory_id
        and event.payload["rescan_decision_id"] == result.decision_id
        for event in new_events
    )
    assert all(
        event.policy_id == result.policy_id
        and event.policy_version == result.policy_version
        and event.detector_bundle_version == result.detector_bundle_version
        for event in new_events
    )
    assert any(
        event.event_type is EventType.MEMORY_COMMITTED and event.memory_id == malicious.memory_id
        for event in await store.list_events()
    )
    verification = await store.verify()
    assert verification.verified is True
    assert verification.materialized_view_consistent is True
    queries = LedgerQueries(store)
    original_detail = await queries.get_candidate_detail(malicious.candidate_id)
    original_summary = next(
        item
        for item in await queries.list_candidate_summaries()
        if item["candidate_id"] == malicious.candidate_id
    )
    assert original_detail["status"] == "revoked"
    assert result.revocation_event_id in original_detail["event_ids"]
    assert original_summary["status"] == "revoked"


@pytest.mark.asyncio
async def test_benign_rescan_records_current_decision_without_revocation(tmp_path) -> None:
    service, store, view = await build_service(tmp_path, mode=Mode.ENFORCE)
    await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.USER_INPUT,
            content="The project uses Python 3.12.",
        )
    )
    target = (await view.list_active())[0]
    event_count = len(await store.list_events())

    result = await RetroactiveRescanService(service).rescan(
        target.memory_id,
        actor_id="operator.demo",
        reason="Routine current-policy validation.",
        confirmed=True,
    )

    new_events = (await store.list_events())[event_count:]
    assert result.actual_action is Action.ALLOW
    assert result.revoked is False
    assert result.revocation_event_id is None
    assert [item.memory_id for item in await view.list_active()] == [target.memory_id]
    rescan_candidate = next(
        event for event in new_events if event.event_type is EventType.MEMORY_CANDIDATE_CREATED
    )
    assert rescan_candidate.event_id == result.rescan_candidate_event_id
    assert rescan_candidate.payload["content_digest"]
    assert "Routine current-policy validation" in rescan_candidate.payload["durability_rationale"]
    assert any(event.event_type is EventType.POLICY_DECISION_RECORDED for event in new_events)
    assert all(event.event_type is not EventType.MEMORY_REVOKED for event in new_events)
    assert (await store.verify()).verified is True


@pytest.mark.asyncio
async def test_evidence_status_remains_terminal_after_safe_signed_rescan(tmp_path) -> None:
    service, store, view = await build_service(tmp_path, mode=Mode.ENFORCE)
    evaluation = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            task_id=new_id(),
            source_class=SourceClass.USER_INPUT,
            content="The project uses Python 3.12.",
        )
    )
    target = (await view.list_active())[0]
    queries = LedgerQueries(store)
    before = await queries.get_evidence_status(evaluation.evidence.evidence_id)

    result = await RetroactiveRescanService(service).rescan(
        target.memory_id,
        actor_id="operator.demo",
        reason="Routine signed evidence checkpoint regression.",
        confirmed=True,
    )
    after = await queries.get_evidence_status(evaluation.evidence.evidence_id)

    assert before["evaluation_state"] == "signed_terminal"
    assert after["evaluation_state"] == "signed_terminal"
    assert after["terminal_outcome"] == "completed"
    assert after["terminal_event_ids"] == before["terminal_event_ids"]
    assert after["candidate_ids"] == before["candidate_ids"]
    assert after["actual_actions"] == before["actual_actions"] == ["allow"]
    assert after["policy_versions"] == before["policy_versions"]
    assert after["rescan_count"] == 1
    assert after["latest_rescan"] == {
        "candidate_id": result.candidate_id,
        "candidate_event_id": result.rescan_candidate_event_id,
        "decision_id": result.decision_id,
        "actual_action": "allow",
        "would_have_action": "allow",
        "policy_id": result.policy_id,
        "policy_version": result.policy_version,
        "memory_id": result.memory_id,
        "revoked": False,
        "revocation_event_id": None,
    }
    assert after["fresh_session_ready"] is True
    assert after["warning_code"] is None


@pytest.mark.asyncio
async def test_evidence_status_preserves_terminal_checkpoint_after_revoking_rescan(
    tmp_path,
) -> None:
    service, store, view = await build_service(tmp_path, mode=Mode.SHADOW)
    evaluation = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            task_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            source_name="poisoned-docs-mcp",
            content=POISONED_DOCS,
        )
    )
    poisoned = next(
        outcome
        for outcome in evaluation.outcomes
        if "demo_artifact_sink" in outcome.candidate.statement
    )
    assert poisoned.memory_id is not None
    queries = LedgerQueries(store)
    before = await queries.get_evidence_status(evaluation.evidence.evidence_id)

    enforce_policy = load_builtin_policy(Mode.ENFORCE)
    await SQLitePolicyRepository(store).activate(
        enforce_policy,
        actor_id="operator.demo",
        reason="Activate enforcement for evidence-status rescan regression.",
    )
    service.policy_engine = PolicyEngine(enforce_policy)
    result = await RetroactiveRescanService(service).rescan(
        poisoned.memory_id,
        actor_id="operator.demo",
        reason="Revoke the synthetic delayed instruction.",
        confirmed=True,
    )
    after = await queries.get_evidence_status(evaluation.evidence.evidence_id)

    assert result.revoked is True
    assert result.revocation_event_id is not None
    assert after["evaluation_state"] == "signed_terminal"
    assert after["terminal_outcome"] == "completed"
    assert after["terminal_event_ids"] == before["terminal_event_ids"]
    assert after["candidate_ids"] == before["candidate_ids"]
    assert after["actual_actions"] == before["actual_actions"]
    assert after["rescan_count"] == 1
    assert after["latest_rescan"] == {
        "candidate_id": result.candidate_id,
        "candidate_event_id": result.rescan_candidate_event_id,
        "decision_id": result.decision_id,
        "actual_action": "quarantine",
        "would_have_action": "quarantine",
        "policy_id": result.policy_id,
        "policy_version": result.policy_version,
        "memory_id": result.memory_id,
        "revoked": True,
        "revocation_event_id": result.revocation_event_id,
    }
    assert all(item.memory_id != poisoned.memory_id for item in await view.list_active())
    assert after["fresh_session_ready"] is True
    assert after["warning_code"] is None


@pytest.mark.asyncio
async def test_rescan_requires_confirmation_and_active_state(tmp_path) -> None:
    service, store, view = await build_service(tmp_path, mode=Mode.ENFORCE)
    await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.USER_INPUT,
            content="The project uses Python 3.12.",
        )
    )
    target = (await view.list_active())[0]
    event_count = len(await store.list_events())
    rescans = RetroactiveRescanService(service)

    with pytest.raises(ConflictError, match="confirmation"):
        await rescans.rescan(
            target.memory_id,
            actor_id="operator.demo",
            reason="Cancelled rescan.",
            confirmed=False,
        )
    assert len(await store.list_events()) == event_count

    service.policy_engine = PolicyEngine(load_builtin_policy(Mode.SHADOW))
    with pytest.raises(ConflictError, match="runtime policy"):
        await rescans.rescan(
            target.memory_id,
            actor_id="operator.demo",
            reason="Unsigned policy drift must fail closed.",
            confirmed=True,
        )
    assert len(await store.list_events()) == event_count
    service.policy_engine = PolicyEngine(load_builtin_policy(Mode.ENFORCE))

    await TrustActions(store, view).revoke(
        target.memory_id,
        actor_id="operator.demo",
        reason="Make the target non-active.",
        confirmed=True,
    )
    with pytest.raises(NotFoundError, match="active memory"):
        await rescans.rescan(
            target.memory_id,
            actor_id="operator.demo",
            reason="Must reject a non-active target.",
            confirmed=True,
        )


class _GateDetector:
    detector_id = "rescan-gate"
    detector_version = "1.0.0"

    def __init__(self, started: asyncio.Event, release: asyncio.Event) -> None:
        self.started = started
        self.release = release

    async def inspect(self, candidate):
        self.started.set()
        await self.release.wait()
        return (await builtin_detectors()[0].inspect(candidate)).model_copy(
            update={
                "result_id": new_id(),
                "detector_id": self.detector_id,
                "detector_version": self.detector_version,
            }
        )


@pytest.mark.asyncio
async def test_concurrent_revocation_rolls_back_rescan_batch(tmp_path) -> None:
    service, store, view = await build_service(tmp_path, mode=Mode.SHADOW)
    evaluation = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            content=POISONED_DOCS,
        )
    )
    target_id = next(
        outcome.memory_id
        for outcome in evaluation.outcomes
        if "demo_artifact_sink" in outcome.candidate.statement
    )
    assert target_id is not None
    enforce_policy = load_builtin_policy(Mode.ENFORCE)
    await SQLitePolicyRepository(store).activate(
        enforce_policy,
        actor_id="operator.demo",
        reason="Test enforcement activation.",
    )
    service.policy_engine = PolicyEngine(enforce_policy)
    started = asyncio.Event()
    release = asyncio.Event()
    service.detector_runner = DetectorRunner([_GateDetector(started, release)])
    event_count = len(await store.list_events())

    task = asyncio.create_task(
        RetroactiveRescanService(service).rescan(
            target_id,
            actor_id="operator.demo",
            reason="Concurrent rescan test.",
            confirmed=True,
        )
    )
    await started.wait()
    await TrustActions(store, view).revoke(
        target_id,
        actor_id="operator.demo",
        reason="Concurrent operator revocation wins.",
        confirmed=True,
    )
    release.set()

    with pytest.raises(ConflictError, match="changed during rescan"):
        await task
    new_events = (await store.list_events())[event_count:]
    assert [event.event_type for event in new_events] == [EventType.MEMORY_REVOKED]
    assert (await store.verify()).verified is True


def test_memory_rescan_cli_executes_real_signed_path(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("VERITY_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VERITY_SEMANTIC_PROVIDER", "fixture")

    async def seed() -> str:
        settings = Settings.from_env()
        settings.prepare()
        FileKeyProvider.generate(settings.key_path)
        runtime = await build_runtime(settings)
        shadow_policy = load_builtin_policy(Mode.SHADOW)
        await runtime.policy_repository.activate(
            shadow_policy,
            actor_id="operator.demo",
            reason="CLI rescan shadow seed.",
        )
        runtime.replace_policy(shadow_policy)
        evaluation = await runtime.memory_service.evaluate_evidence(
            EvidenceSubmission(
                session_id=new_id(),
                source_class=SourceClass.TOOL_OUTPUT,
                content=POISONED_DOCS,
            )
        )
        target = next(
            outcome.memory_id
            for outcome in evaluation.outcomes
            if "demo_artifact_sink" in outcome.candidate.statement
        )
        assert target is not None
        enforce_policy = load_builtin_policy(Mode.ENFORCE)
        await runtime.policy_repository.activate(
            enforce_policy,
            actor_id="operator.demo",
            reason="CLI rescan enforcement activation.",
        )
        runtime.replace_policy(enforce_policy)
        return target

    memory_id = asyncio.run(seed())
    result = CliRunner().invoke(
        app,
        [
            "memory",
            "rescan",
            memory_id,
            "--reason",
            "CLI retroactive review.",
            "--yes",
        ],
    )

    assert result.exit_code == 0, result.output
    assert '"actual_action": "quarantine"' in result.output
    assert '"revoked": true' in result.output

    async def verify() -> None:
        runtime = await build_runtime(Settings.from_env())
        assert all(item.memory_id != memory_id for item in await runtime.memory_view.list_active())
        assert (await runtime.event_store.verify()).verified is True

    asyncio.run(verify())
