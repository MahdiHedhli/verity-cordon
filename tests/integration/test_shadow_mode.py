"""Shadow evaluation records divergence without claiming active protection."""

from __future__ import annotations

import pytest

from tests.integration.test_memory_pipeline import POISONED_DOCS, build_service
from verity_cordon.core.models import Action, Mode, SourceClass, new_id
from verity_cordon.memory.service import EvidenceSubmission


@pytest.mark.asyncio
async def test_benign_shadow_decision_has_action_parity(tmp_path) -> None:
    service, _, view = await build_service(tmp_path, mode=Mode.SHADOW)

    result = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.USER_INPUT,
            content="The project uses Python 3.12.",
        )
    )

    decision = result.outcomes[0].decision
    assert decision.actual_action is Action.ALLOW
    assert decision.would_have_action is Action.ALLOW
    assert decision.shadow_mode is True
    assert (await view.list_active())[0].shadow_admitted is True


@pytest.mark.asyncio
async def test_malicious_shadow_decision_is_admitted_with_visible_divergence(tmp_path) -> None:
    service, store, view = await build_service(tmp_path, mode=Mode.SHADOW)

    result = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            content=POISONED_DOCS,
        )
    )
    malicious = next(
        outcome
        for outcome in result.outcomes
        if "demo_artifact_sink" in outcome.candidate.statement
    )
    active = next(
        item for item in await view.list_active() if item.memory_id == malicious.memory_id
    )
    decision_events = [
        event
        for event in await store.list_events()
        if event.event_type.value == "PolicyDecisionRecorded"
    ]

    assert malicious.decision.actual_action is Action.ALLOW
    assert malicious.decision.would_have_action is Action.QUARANTINE
    assert active.trust_decision == "shadow_admitted"
    assert active.actual_action is Action.ALLOW
    assert active.would_have_action is Action.QUARANTINE
    assert any(
        event.payload["actual_action"] == "allow"
        and event.payload["would_have_action"] == "quarantine"
        for event in decision_events
    )
    assert (await store.verify()).verified is True


@pytest.mark.asyncio
async def test_same_attack_is_quarantined_in_enforcement_mode(tmp_path) -> None:
    service, _, view = await build_service(tmp_path, mode=Mode.ENFORCE)

    result = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            content=POISONED_DOCS,
        )
    )
    malicious = next(
        outcome
        for outcome in result.outcomes
        if "demo_artifact_sink" in outcome.candidate.statement
    )

    assert malicious.decision.actual_action is Action.QUARANTINE
    assert malicious.decision.would_have_action is Action.QUARANTINE
    assert malicious.decision.shadow_mode is False
    assert all("demo_artifact_sink" not in item.safe_statement for item in await view.list_active())
