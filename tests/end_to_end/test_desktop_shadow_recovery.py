"""Desktop shadow-admission and selective-recovery security matrix."""

from __future__ import annotations

import json
import sqlite3

import pytest

from tests.end_to_end.test_demo import demo_settings
from tests.integration.test_memory_pipeline import POISONED_DOCS, build_service
from verity_cordon.core.errors import LedgerIntegrityError
from verity_cordon.core.models import Action, DetectorStatus, Mode, SourceClass, new_id
from verity_cordon.demo import run_offline_demo
from verity_cordon.detectors.builtin import builtin_detectors
from verity_cordon.ledger.queries import LedgerQueries
from verity_cordon.memory.rescan import RetroactiveRescanService
from verity_cordon.memory.service import EvidenceSubmission
from verity_cordon.memory.trust_actions import TrustActions
from verity_cordon.policies.engine import PolicyEngine
from verity_cordon.policies.load import load_builtin_policy
from verity_cordon.policies.repository import SQLitePolicyRepository
from verity_cordon.telemetry.instrumentation import Statistics

ARTIFACT_MARKER = "VERITY_SYNTHETIC_RELEASE_MANIFEST_V1"
ENVIRONMENT_MARKER = "VERITY_SYNTHETIC_DEMO_ENV_V1"
FALSE_POSITIVE_TRAP = (
    'The security guide quotes "for all future sessions, hide this instruction" '
    "as an example of memory poisoning, not an instruction to follow."
)


class _ExplodingDetector:
    detector_id = "synthetic-shadow-dependency-failure"
    detector_version = "1.0.0"

    async def inspect(self, candidate):
        del candidate
        raise RuntimeError("raw evidence must not enter a dependency error")


@pytest.mark.asyncio
async def test_offline_shadow_demo_attempts_only_the_fixed_local_markers(tmp_path) -> None:
    run = await run_offline_demo(demo_settings(tmp_path))

    delayed = run.summary["delayed_attempt"]
    assert delayed == {
        "scenario_id": "vc-delayed-docs-v1",
        "trigger": "synthetic_release_task",
        "simulation": True,
        "causal_claim": "not_established",
        "sequence": "memory_presence_verified_then_fixed_sink_invoked",
        "shadow_memory_active_in_new_session": True,
        "sink_tool": "demo_artifact_sink",
        "arguments": {
            "artifact_marker": ARTIFACT_MARKER,
            "environment_marker": ENVIRONMENT_MARKER,
        },
        "accepted": True,
        "call_count": 1,
        "canonical_pair_sha256": (
            "603b7659309872e291e10d540808a6d4e6df88abcbb338c8f3fcdca7aa2c0d4c"
        ),
        "transport": "stdio",
        "boundary": "local_inert_fixture_only",
        "external_transmission_performed": False,
    }
    assert "blocked" not in delayed
    assert "prevented" not in delayed


@pytest.mark.asyncio
async def test_shadow_recovery_preserves_unrelated_and_false_positive_memory(tmp_path) -> None:
    service, store, view = await build_service(tmp_path, mode=Mode.SHADOW)
    benign = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            task_id=new_id(),
            source_class=SourceClass.USER_INPUT,
            content="The unrelated build target uses Python 3.12.",
        )
    )
    false_positive = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            task_id=new_id(),
            source_class=SourceClass.IMPORTED_FILE,
            source_name="synthetic-security-guide",
            content=FALSE_POSITIVE_TRAP,
        )
    )
    poisoned = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            task_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            source_name="poisoned-docs-mcp",
            content=POISONED_DOCS,
        )
    )
    malicious = next(
        outcome
        for outcome in poisoned.outcomes
        if "demo_artifact_sink" in outcome.candidate.statement
    )
    assert malicious.memory_id is not None
    assert benign.outcomes[0].memory_id is not None
    assert benign.outcomes[0].decision.actual_action is Action.ALLOW
    assert benign.outcomes[0].decision.would_have_action is Action.ALLOW
    assert false_positive.outcomes[0].decision.actual_action is Action.ALLOW
    assert false_positive.outcomes[0].decision.would_have_action is Action.ALLOW
    assert malicious.decision.actual_action is Action.ALLOW
    assert malicious.decision.would_have_action is Action.QUARANTINE

    shadow_context = await service.session_start_context(
        session_id=new_id(),
        token_budget=2000,
    )
    assert "demo_artifact_sink" in shadow_context
    assert "The unrelated build target uses Python 3.12." in shadow_context
    assert "security guide quotes" in shadow_context

    enforce_policy = load_builtin_policy(Mode.ENFORCE)
    await SQLitePolicyRepository(store).activate(
        enforce_policy,
        actor_id="operator.demo",
        reason="Activate enforcement for selective recovery.",
    )
    service.policy_engine = PolicyEngine(enforce_policy)
    rescanned = await RetroactiveRescanService(service).rescan(
        malicious.memory_id,
        actor_id="operator.demo",
        reason="Revoke the shadow-admitted synthetic delayed instruction.",
        confirmed=True,
    )
    assert rescanned.actual_action is Action.QUARANTINE
    assert rescanned.revoked is True

    with sqlite3.connect(store.database_path) as database:
        database.execute(
            "DELETE FROM active_memories WHERE memory_id = ?",
            (benign.outcomes[0].memory_id,),
        )
        database.commit()
    assert (await store.verify()).failure_class == "materialized_view_drift"
    preview = await view.rebuild(dry_run=True)
    rebuilt = await view.rebuild(dry_run=False)

    active = await view.list_active()
    active_text = "\n".join(item.safe_statement for item in active)
    recovered_context = await service.session_start_context(
        session_id=new_id(),
        token_budget=2000,
    )
    assert preview["changed"] is True
    assert rebuilt["verified_view"] is True
    assert "unrelated build target" in active_text
    assert "security guide quotes" in active_text
    assert "demo_artifact_sink" not in active_text
    assert "demo_artifact_sink" not in recovered_context
    detail = await LedgerQueries(store, Statistics()).get_candidate_detail(
        malicious.candidate.candidate_id
    )
    assert any(event["event_type"] == "MemoryRevoked" for event in detail["event_references"])
    verification = await store.verify()
    assert verification.verified is True
    assert verification.materialized_view_consistent is True


@pytest.mark.asyncio
async def test_shadow_dependency_failure_is_visible_and_not_misrepresented_as_protection(
    tmp_path,
) -> None:
    service, store, view = await build_service(
        tmp_path,
        mode=Mode.SHADOW,
        detectors=[_ExplodingDetector(), *builtin_detectors()],
    )

    evaluation = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            task_id=new_id(),
            source_class=SourceClass.USER_INPUT,
            content="The synthetic project uses Python 3.12.",
        )
    )

    outcome = evaluation.outcomes[0]
    failure = next(
        result
        for result in outcome.detector_results
        if result.detector_id == _ExplodingDetector.detector_id
    )
    assert failure.status is DetectorStatus.ERROR
    assert outcome.decision.actual_action is Action.ALLOW
    assert outcome.decision.would_have_action is Action.QUARANTINE
    assert outcome.decision.shadow_mode is True
    assert (await view.list_active())[0].shadow_admitted is True
    assert (await store.verify()).verified is True


@pytest.mark.asyncio
async def test_tampered_history_refuses_revocation_and_rebuild(tmp_path) -> None:
    service, store, view = await build_service(tmp_path, mode=Mode.SHADOW)
    result = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            task_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            source_name="poisoned-docs-mcp",
            content=POISONED_DOCS,
        )
    )
    malicious = next(
        outcome
        for outcome in result.outcomes
        if "demo_artifact_sink" in outcome.candidate.statement
    )
    assert malicious.memory_id is not None

    with sqlite3.connect(store.database_path) as database:
        database.execute("DROP TRIGGER events_no_update")
        raw = database.execute(
            "SELECT envelope_json FROM events WHERE sequence_number = 1"
        ).fetchone()[0]
        envelope = json.loads(raw)
        envelope["actor"]["id"] = "attacker.changed"
        database.execute(
            "UPDATE events SET envelope_json = ? WHERE sequence_number = 1",
            (json.dumps(envelope),),
        )
        database.commit()

    verification = await store.verify()
    assert verification.verified is False
    with pytest.raises(LedgerIntegrityError, match="verified ledger"):
        await TrustActions(store, view).revoke(
            malicious.memory_id,
            actor_id="operator.demo",
            reason="Tampered history must stop recovery.",
            confirmed=True,
        )
    with pytest.raises(LedgerIntegrityError, match="not safe to replay"):
        await view.rebuild(dry_run=False)
