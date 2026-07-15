"""Selective revocation, manual review, and deterministic rebuild tests."""

from __future__ import annotations

import json
import sqlite3

import pytest

from tests.integration.test_memory_pipeline import POISONED_DOCS, build_service
from verity_cordon.core.errors import ConflictError, LedgerIntegrityError
from verity_cordon.core.models import Mode, SourceClass, new_id
from verity_cordon.memory.service import EvidenceSubmission
from verity_cordon.memory.trust_actions import TrustActions


@pytest.mark.asyncio
async def test_revoke_one_shadow_memory_preserves_legitimate_memory_and_history(tmp_path) -> None:
    service, store, view = await build_service(tmp_path, mode=Mode.SHADOW)
    await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            content=POISONED_DOCS,
        )
    )
    active_before = await view.list_active()
    malicious = next(item for item in active_before if "demo_artifact_sink" in item.safe_statement)
    safe = next(item for item in active_before if "release.yaml" in item.safe_statement)
    actions = TrustActions(store, view)

    preview = await actions.preview_revocation(malicious.memory_id)
    revoked = await actions.revoke(
        malicious.memory_id,
        actor_id="operator.demo",
        reason="Retroactive policy identifies persistent tool authority.",
        confirmed=True,
    )
    active_after = await view.list_active()
    events = await store.list_events()

    assert preview["active_after"] == 1
    assert revoked.status == "revoked"
    assert [item.memory_id for item in active_after] == [safe.memory_id]
    assert any(event.event_type.value == "MemoryRevoked" for event in events)
    assert any(
        event.event_type.value == "MemoryCommitted" and event.memory_id == malicious.memory_id
        for event in events
    )
    assert (await store.verify()).verified is True


@pytest.mark.asyncio
async def test_unconfirmed_revocation_is_a_noop(tmp_path) -> None:
    service, store, view = await build_service(tmp_path)
    await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.USER_INPUT,
            content="The project uses Python 3.12.",
        )
    )
    target = (await view.list_active())[0]
    event_count = len(await store.list_events())

    with pytest.raises(ConflictError, match="confirmation"):
        await TrustActions(store, view).revoke(
            target.memory_id,
            actor_id="operator.demo",
            reason="Cancelled test.",
            confirmed=False,
        )

    assert len(await store.list_events()) == event_count
    assert len(await view.list_active()) == 1


@pytest.mark.asyncio
async def test_tampered_history_refuses_revocation(tmp_path) -> None:
    service, store, view = await build_service(tmp_path)
    await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.USER_INPUT,
            content="The project uses Python 3.12.",
        )
    )
    target = (await view.list_active())[0]
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

    with pytest.raises(LedgerIntegrityError, match="verified ledger"):
        await TrustActions(store, view).revoke(
            target.memory_id,
            actor_id="operator.demo",
            reason="Must refuse under tampering.",
            confirmed=True,
        )


@pytest.mark.asyncio
async def test_rebuild_repairs_stale_view_without_changing_history(tmp_path) -> None:
    service, store, view = await build_service(tmp_path)
    await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.USER_INPUT,
            content="The project uses Python 3.12.",
        )
    )
    events_before = [event.event_hash for event in await store.list_events()]
    with sqlite3.connect(store.database_path) as database:
        database.execute("DELETE FROM active_memories")
        database.commit()
    assert (await store.verify()).failure_class == "materialized_view_drift"

    preview = await view.rebuild(dry_run=True)
    result = await view.rebuild(dry_run=False)

    assert preview["changed"] is True
    assert result["verified_view"] is True
    assert len(await view.list_active()) == 1
    assert [event.event_hash for event in await store.list_events()] == events_before


@pytest.mark.asyncio
async def test_quarantined_candidate_can_be_approved_with_auditable_reason(tmp_path) -> None:
    service, store, view = await build_service(tmp_path)
    await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            content=POISONED_DOCS,
        )
    )
    target = (await view.list_quarantined())[0]

    approved = await TrustActions(store, view).approve(
        target.candidate_id,
        actor_id="operator.demo",
        reason="Synthetic demo approval only.",
        confirmed=True,
    )

    assert approved.trust_decision == "manually_approved"
    assert approved.manual_approval_event_id is not None
    assert await view.list_quarantined() == []
    assert (await store.verify()).verified is True


@pytest.mark.asyncio
async def test_quarantined_candidate_can_be_blocked_without_active_memory(tmp_path) -> None:
    service, store, view = await build_service(tmp_path)
    await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            content=POISONED_DOCS,
        )
    )
    target = (await view.list_quarantined())[0]

    await TrustActions(store, view).block(
        target.candidate_id,
        actor_id="operator.demo",
        reason="Confirmed persistent instruction.",
        confirmed=True,
    )

    assert await view.list_quarantined() == []
    assert all("demo_artifact_sink" not in item.safe_statement for item in await view.list_active())
    assert (await store.verify()).verified is True
