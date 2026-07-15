"""Privacy-safe telemetry attribute and latency tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from opentelemetry import trace as otel_trace

from tests.integration.test_memory_pipeline import build_service
from verity_cordon.core.models import SourceClass, new_id
from verity_cordon.memory.service import EvidenceSubmission
from verity_cordon.memory.trust_actions import TrustActions
from verity_cordon.telemetry.instrumentation import Statistics, safe_attributes, span


class _RecordingSpan:
    def __init__(self, name: str, attributes: dict[str, Any]) -> None:
        self.name = name
        self.attributes = dict(attributes)

    def __enter__(self) -> _RecordingSpan:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value


class _RecordingTracer:
    def __init__(self) -> None:
        self.spans: list[_RecordingSpan] = []

    def start_as_current_span(
        self,
        name: str,
        *,
        attributes: dict[str, Any],
    ) -> _RecordingSpan:
        recorded = _RecordingSpan(name, attributes)
        self.spans.append(recorded)
        return recorded


def test_safe_attributes_drop_raw_content_and_unknown_values() -> None:
    attributes = safe_attributes(
        {
            "candidate_id": "synthetic-candidate",
            "content_length": 42,
            "raw_prompt": "must never be exported",
            "api_key": "synthetic-secret",
        }
    )

    assert attributes == {
        "candidate_id": "synthetic-candidate",
        "content_length": 42,
    }


@pytest.mark.asyncio
async def test_evaluation_latency_is_observable_without_content() -> None:
    statistics = Statistics()
    async with span("verity.memory.evaluate", content_length=10) as timing:
        pass
    await statistics.observe_evaluation(timing["latency_ms"])

    snapshot = await statistics.snapshot()

    assert snapshot["average_evaluation_latency_ms"] >= 0


@pytest.mark.asyncio
async def test_security_pipeline_emits_promised_privacy_safe_spans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracer = _RecordingTracer()
    monkeypatch.setattr(otel_trace, "get_tracer", lambda _: tracer)
    service, store, view = await build_service(tmp_path)

    await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.USER_INPUT,
            content="The project uses Python 3.12.",
        )
    )
    target = (await view.list_active())[0]
    await TrustActions(store, view).revoke(
        target.memory_id,
        actor_id="operator.telemetry-test",
        reason="Synthetic telemetry coverage exercise.",
        confirmed=True,
    )
    await view.rebuild(dry_run=True)

    names = {record.name for record in tracer.spans}
    assert {
        "verity.memory.extract",
        "verity.policy.decide",
        "verity.ledger.append",
        "verity.memory.materialize",
        "verity.memory.revoke",
        "verity.ledger.verify",
    } <= names
    assert all("raw_prompt" not in record.attributes for record in tracer.spans)
    assert all("api_key" not in record.attributes for record in tracer.spans)
