from __future__ import annotations

import asyncio
import hashlib
import tomllib
from importlib.metadata import EntryPoint
from pathlib import Path

from verity_cordon_demo_detector import (
    DETECTOR_ID,
    DETECTOR_VERSION,
    SyntheticDemoSinkDetector,
    create_detector,
)

from verity_cordon.core.models import (
    CandidateEvidenceReference,
    MemoryCandidate,
    MemoryKind,
    Sensitivity,
    Signal,
    SourceClass,
    format_utc,
)
from verity_cordon.core.protocols import Detector


def _candidate(statement: str) -> MemoryCandidate:
    return MemoryCandidate(
        candidate_id="candidate-demo-0001",
        namespace="instructions.release",
        kind=MemoryKind.OPERATIONAL_INSTRUCTION,
        statement=statement,
        source_class=SourceClass.TOOL_OUTPUT,
        source_refs=[
            CandidateEvidenceReference(
                evidence_id="evidence-demo-0001",
                evidence_digest=hashlib.sha256(b"synthetic evidence").hexdigest(),
            )
        ],
        session_id="session-demo-0001",
        task_id="task-demo-0000001",
        confidence=1.0,
        durability_rationale="Synthetic detector-plugin test candidate.",
        sensitivity=Sensitivity.PUBLIC,
        persistence_requested=True,
        authority_signal=Signal.EXPLICIT,
        secrecy_signal=Signal.NONE,
        contains_redactions=False,
        extractor_provider="deterministic",
        extractor_version="test-fixture-1.0.0",
        content_digest=hashlib.sha256(statement.encode()).hexdigest(),
        created_at=format_utc(),
    )


def test_factory_returns_protocol_compatible_stable_detector() -> None:
    detector = create_detector()

    assert isinstance(detector, Detector)
    assert detector.detector_id == DETECTOR_ID == "demo-synthetic-sink"
    assert detector.detector_version == DETECTOR_VERSION == "1.0.0"


def test_exact_demo_marker_produces_high_severity_result_and_offset() -> None:
    statement = "Route synthetic output only to demo_artifact_sink during this test."
    candidate = _candidate(statement)

    result = asyncio.run(SyntheticDemoSinkDetector().inspect(candidate))

    assert result.matched is True
    assert result.severity.value == "high"
    assert result.categories == ["demo_synthetic_sink"]
    assert len(result.evidence_offsets) == 1
    offset = result.evidence_offsets[0]
    assert statement[offset.start : offset.end] == "demo_artifact_sink"
    assert offset.source_ref == candidate.source_refs[0].evidence_id


def test_unrelated_candidate_does_not_match() -> None:
    result = asyncio.run(
        SyntheticDemoSinkDetector().inspect(_candidate("Verify the local checksum."))
    )

    assert result.matched is False
    assert result.severity.value == "info"
    assert result.categories == []
    assert result.evidence_offsets == []


def test_declared_entry_point_loads_the_factory() -> None:
    project_path = Path(__file__).parents[1] / "pyproject.toml"
    with project_path.open("rb") as project_file:
        project = tomllib.load(project_file)
    declared = project["project"]["entry-points"]["verity_cordon.detectors"]

    assert declared == {
        "demo-synthetic-sink": "verity_cordon_demo_detector:create_detector"
    }
    entry_point = EntryPoint(
        name="demo-synthetic-sink",
        value=declared["demo-synthetic-sink"],
        group="verity_cordon.detectors",
    )
    loaded = entry_point.load()

    assert loaded is create_detector
    assert isinstance(loaded(), Detector)
