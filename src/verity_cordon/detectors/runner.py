"""Concurrent detector fan-out with deterministic aggregation and isolation."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

from verity_cordon.core.models import (
    DetectorResult,
    DetectorStatus,
    MemoryCandidate,
    Severity,
    format_utc,
    new_id,
)
from verity_cordon.core.protocols import Detector
from verity_cordon.crypto.canonical import canonical_sha256_hex


class DetectorRunner:
    def __init__(self, detectors: Sequence[Detector]) -> None:
        identifiers = [detector.detector_id for detector in detectors]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Duplicate detector ID")
        self.detectors = tuple(detectors)

    @property
    def bundle_version(self) -> str:
        manifest = sorted(
            (detector.detector_id, detector.detector_version) for detector in self.detectors
        )
        return f"vc-detectors-{canonical_sha256_hex(manifest)[:16]}"

    def _failure(
        self,
        detector: Detector,
        candidate: MemoryCandidate,
        status: DetectorStatus,
        failure_class: str,
    ) -> DetectorResult:
        return DetectorResult(
            result_id=new_id(),
            candidate_id=candidate.candidate_id,
            detector_id=detector.detector_id,
            detector_version=detector.detector_version,
            execution_order=0,
            status=status,
            matched=None,
            severity=Severity.HIGH,
            confidence=0,
            categories=[],
            message="Detector did not return a usable verdict.",
            failure_class=failure_class,
            latency_ms=0,
            recorded_at=format_utc(),
        )

    async def _run_one(
        self,
        detector: Detector,
        candidate: MemoryCandidate,
        timeout_seconds: float,
    ) -> DetectorResult:
        try:
            async with asyncio.timeout(timeout_seconds):
                result = await detector.inspect(candidate)
            if not isinstance(result, DetectorResult):
                return self._failure(
                    detector,
                    candidate,
                    DetectorStatus.MALFORMED,
                    "MalformedResult",
                )
            if (
                result.candidate_id != candidate.candidate_id
                or result.detector_id != detector.detector_id
                or result.detector_version != detector.detector_version
            ):
                return self._failure(
                    detector,
                    candidate,
                    DetectorStatus.MALFORMED,
                    "IdentityMismatch",
                )
            return result
        except TimeoutError:
            return self._failure(detector, candidate, DetectorStatus.TIMEOUT, "Timeout")
        except asyncio.CancelledError:
            raise
        except Exception:
            return self._failure(detector, candidate, DetectorStatus.ERROR, "DetectorException")

    async def run(
        self,
        candidate: MemoryCandidate,
        *,
        timeout_ms: int,
    ) -> list[DetectorResult]:
        tasks: list[asyncio.Task[DetectorResult]] = []
        timeout_seconds = timeout_ms / 1000
        async with asyncio.TaskGroup() as group:
            for detector in self.detectors:
                tasks.append(group.create_task(self._run_one(detector, candidate, timeout_seconds)))
        ordered = sorted(
            (task.result() for task in tasks),
            key=lambda result: (result.detector_id, result.detector_version, result.result_id),
        )
        return [
            result.model_copy(update={"execution_order": index})
            for index, result in enumerate(ordered)
        ]
