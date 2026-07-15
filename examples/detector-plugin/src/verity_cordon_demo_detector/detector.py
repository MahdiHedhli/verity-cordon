"""Side-effect-free detector for the synthetic poisoned-docs marker."""

from __future__ import annotations

from verity_cordon.core.models import (
    DetectorResult,
    DetectorStatus,
    EvidenceOffset,
    MemoryCandidate,
    Severity,
    format_utc,
    new_id,
)

DETECTOR_ID = "demo-synthetic-sink"
DETECTOR_VERSION = "1.0.0"
SYNTHETIC_MARKER = "demo_artifact_sink"


class SyntheticDemoSinkDetector:
    """Detect the exact inert sink marker used by the local security fixture."""

    detector_id = DETECTOR_ID
    detector_version = DETECTOR_VERSION

    async def inspect(self, candidate: MemoryCandidate) -> DetectorResult:
        start = candidate.statement.lower().find(SYNTHETIC_MARKER)
        matched = start >= 0
        offsets = (
            [
                EvidenceOffset(
                    source_ref=candidate.source_refs[0].evidence_id,
                    start=start,
                    end=start + len(SYNTHETIC_MARKER),
                )
            ]
            if matched
            else []
        )

        return DetectorResult(
            result_id=new_id(),
            candidate_id=candidate.candidate_id,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            execution_order=0,
            status=DetectorStatus.OK,
            matched=matched,
            severity=Severity.HIGH if matched else Severity.INFO,
            confidence=1.0,
            categories=["demo_synthetic_sink"] if matched else [],
            message=(
                "Synthetic demo sink marker detected."
                if matched
                else "Synthetic demo sink marker not detected."
            ),
            evidence_offsets=offsets,
            metadata={"fixture_only": True},
            latency_ms=0,
            recorded_at=format_utc(),
        )


def create_detector() -> SyntheticDemoSinkDetector:
    """Entry-point factory returning a new stateless detector instance."""

    return SyntheticDemoSinkDetector()
