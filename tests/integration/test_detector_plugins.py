"""Trusted detector entry-point discovery and isolation tests."""

from __future__ import annotations

import os
from importlib import metadata

import pytest

from tests.factories import make_candidate
from tests.integration.test_memory_pipeline import build_service
from verity_cordon.core.errors import ConfigurationError
from verity_cordon.core.models import (
    DetectorResult,
    DetectorStatus,
    Severity,
    SourceClass,
    format_utc,
    new_id,
)
from verity_cordon.crypto.canonical import canonical_json
from verity_cordon.detectors.plugins import ENTRY_POINT_GROUP, discover_detectors
from verity_cordon.detectors.runner import DetectorRunner
from verity_cordon.memory.service import EvidenceSubmission


class ReferenceDetector:
    detector_id = "reference-plugin"
    detector_version = "1.0.0"

    async def inspect(self, candidate) -> DetectorResult:
        return DetectorResult(
            result_id=new_id(),
            candidate_id=candidate.candidate_id,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            execution_order=0,
            status=DetectorStatus.OK,
            matched=False,
            severity=Severity.INFO,
            confidence=1,
            categories=[],
            message="Reference plugin found no demo marker.",
            latency_ms=0,
            recorded_at=format_utc(),
        )


class ExplodingDetector(ReferenceDetector):
    detector_id = "exploding-plugin"

    async def inspect(self, candidate) -> DetectorResult:
        del candidate
        raise RuntimeError("synthetic plugin failure")


class EnvironmentEchoDetector(ReferenceDetector):
    detector_id = "environment-echo-plugin"

    async def inspect(self, candidate) -> DetectorResult:
        synthetic_secret = os.environ["VERITY_TEST_PLUGIN_OUTPUT"]
        return DetectorResult(
            result_id=new_id(),
            candidate_id=candidate.candidate_id,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            execution_order=0,
            status=DetectorStatus.OK,
            matched=False,
            severity=Severity.INFO,
            confidence=1,
            categories=["synthetic_observation"],
            message=f"Plugin process output included {synthetic_secret}",
            metadata={f"source-{synthetic_secret}": f"value-{synthetic_secret}"},
            latency_ms=0,
            recorded_at=format_utc(),
        )


def point(name: str, value: str) -> metadata.EntryPoint:
    return metadata.EntryPoint(name=name, value=value, group=ENTRY_POINT_GROUP)


def test_discovery_loads_only_explicitly_enabled_entry_points(monkeypatch) -> None:
    monkeypatch.setattr(metadata.EntryPoint, "load", lambda self: ReferenceDetector)

    def available():
        return [point("reference", "synthetic:ReferenceDetector")]

    assert discover_detectors([], entry_points_provider=available) == []
    loaded = discover_detectors(["reference"], entry_points_provider=available)

    assert len(loaded) == 1
    assert loaded[0].detector_id == "reference-plugin"
    assert loaded[0].detector_version == "1.0.0"


def test_missing_malformed_and_duplicate_plugins_fail_closed(monkeypatch) -> None:
    def available():
        return [point("reference", "synthetic:ReferenceDetector")]

    with pytest.raises(ConfigurationError, match="not installed"):
        discover_detectors(["missing"], entry_points_provider=available)
    with pytest.raises(ConfigurationError, match="unique"):
        discover_detectors(["reference", "reference"], entry_points_provider=available)

    class Malformed:
        detector_id = "bad"
        detector_version = "1.0.0"

        def inspect(self, candidate):
            return candidate

    monkeypatch.setattr(metadata.EntryPoint, "load", lambda self: Malformed)
    with pytest.raises(ConfigurationError, match="async contract"):
        discover_detectors(["reference"], entry_points_provider=available)


@pytest.mark.asyncio
async def test_plugin_exception_is_isolated_as_a_safe_failure(monkeypatch) -> None:
    monkeypatch.setattr(metadata.EntryPoint, "load", lambda self: ExplodingDetector)
    detectors = discover_detectors(
        ["exploding"],
        entry_points_provider=lambda: [point("exploding", "synthetic:ExplodingDetector")],
    )

    results = await DetectorRunner(detectors).run(make_candidate(), timeout_ms=100)

    assert len(results) == 1
    assert results[0].status is DetectorStatus.ERROR
    assert results[0].failure_class == "DetectorException"
    assert "synthetic plugin failure" not in results[0].message


@pytest.mark.asyncio
async def test_plugin_process_output_is_sanitized_before_signed_event_persistence(
    tmp_path,
    monkeypatch,
) -> None:
    synthetic_secret = "sk-" + "svcacct-SYNTHETICONLY1234567890"
    monkeypatch.setenv("VERITY_TEST_PLUGIN_OUTPUT", synthetic_secret)
    service, store, _ = await build_service(tmp_path, detectors=[EnvironmentEchoDetector()])

    evaluation = await service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            source_class=SourceClass.USER_INPUT,
            content="The project uses Python 3.12.",
        )
    )
    persisted = canonical_json(
        [event.model_dump(mode="json", by_alias=True) for event in await store.list_events()]
    )

    assert evaluation.outcomes[0].detector_results[0].status is DetectorStatus.OK
    assert synthetic_secret not in persisted
    assert "<REDACTED:OPENAI_API_KEY_1>" in persisted
    assert (await store.verify()).verified is True
    for path in tmp_path.iterdir():
        if path.is_file():
            assert synthetic_secret.encode() not in path.read_bytes()
