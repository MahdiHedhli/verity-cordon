"""Approved-memory rendering boundaries."""

from __future__ import annotations

from verity_cordon.core.models import (
    Action,
    MemoryKind,
    MemoryRecord,
    ProviderSummaryState,
    SourceClass,
    new_id,
)
from verity_cordon.memory.injection import render_approved_memory


def _memory(statement: str, *, namespace: str = "project.release") -> MemoryRecord:
    event_id = new_id()
    return MemoryRecord(
        memory_id=new_id(),
        commit_event_id=event_id,
        candidate_id=new_id(),
        session_id=new_id(),
        safe_statement=statement,
        namespace=namespace,
        kind=MemoryKind.FACT,
        source_class=SourceClass.USER_INPUT,
        status="active",
        trust_decision="allowed",
        policy_id="verity-default",
        policy_version="1.0.0",
        actual_action=Action.ALLOW,
        would_have_action=Action.ALLOW,
        committed_at="2026-07-15T12:00:00.000Z",
        expires_at=None,
        shadow_admitted=False,
        manual_approval_event_id=None,
        risk_categories=["benign_fact"],
        semantic_provider=ProviderSummaryState.RECORDED_FIXTURE,
        last_event_id=event_id,
        last_event_sequence=1,
    )


def test_rendered_context_never_exceeds_conservative_token_budget() -> None:
    memories = [
        _memory("Release notes use release.yaml."),
        _memory("Unicode remains bounded: 短い🔐文本"),
    ]

    rendered = render_approved_memory(memories, token_budget=600)

    assert rendered
    assert len(rendered.encode("utf-8")) <= 600


def test_record_is_omitted_instead_of_truncated_when_budget_is_too_small() -> None:
    rendered = render_approved_memory(
        [_memory("🔐" * 300)],
        token_budget=500,
    )

    assert rendered == ""


def test_selection_order_is_deterministic_under_budget_pressure() -> None:
    first = _memory("First eligible record.", namespace="project.a")
    second = _memory("Second record must not displace the first.", namespace="project.z")
    first_only = render_approved_memory([first], token_budget=10_000)
    exact_first_budget = len(first_only.encode("utf-8"))
    constrained = render_approved_memory(
        [second, first],
        token_budget=exact_first_budget,
    )

    assert first_only
    assert constrained == first_only
