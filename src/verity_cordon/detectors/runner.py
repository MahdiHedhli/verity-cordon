"""Concurrent detector fan-out with deterministic aggregation and isolation."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError

from verity_cordon.core.models import (
    DetectorResult,
    DetectorStatus,
    MemoryCandidate,
    Severity,
    format_utc,
    new_id,
)
from verity_cordon.core.protocols import Detector
from verity_cordon.crypto.canonical import canonical_json_bytes, canonical_sha256_hex
from verity_cordon.detectors.builtin import SecretSanitizer
from verity_cordon.telemetry.instrumentation import span

_MAX_CATEGORIES = 16
_MAX_CATEGORY_CHARACTERS = 64
_MAX_CATEGORY_BYTES = 256
_MAX_MESSAGE_CHARACTERS = 1_000
_MAX_MESSAGE_BYTES = 4_096
_MAX_METADATA_ITEMS = 32
_MAX_METADATA_KEY_CHARACTERS = 64
_MAX_METADATA_KEY_BYTES = 256
_MAX_METADATA_VALUE_CHARACTERS = 512
_MAX_METADATA_VALUE_BYTES = 2_048
_MAX_METADATA_SERIALIZED_BYTES = 8_192
_MAX_EVIDENCE_OFFSETS = 32
_MAX_OFFSET_VALUE = 16_777_216
_MAX_RESULT_SERIALIZED_BYTES = 16_384


class _DetectorOutputLimitError(ValueError):
    """A detector output crossed a fixed local resource boundary."""


class _MalformedDetectorOutputError(ValueError):
    """A detector output could not be represented safely."""


def _utf8_size(value: str) -> int:
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise _MalformedDetectorOutputError from exc


def _bounded_text(
    value: Any,
    *,
    max_characters: int,
    max_bytes: int,
    allow_empty: bool,
) -> str:
    if not isinstance(value, str):
        raise _MalformedDetectorOutputError
    if (not allow_empty and not value) or len(value) > max_characters:
        if len(value) > max_characters:
            raise _DetectorOutputLimitError
        raise _MalformedDetectorOutputError
    if _utf8_size(value) > max_bytes:
        raise _DetectorOutputLimitError
    return value


def _raw_offset_fields(offset: Any) -> tuple[Any, Any, Any]:
    if isinstance(offset, dict):
        return offset.get("source_ref"), offset.get("start"), offset.get("end")
    return (
        getattr(offset, "source_ref", None),
        getattr(offset, "start", None),
        getattr(offset, "end", None),
    )


def _validate_raw_shape(result: DetectorResult, candidate: MemoryCandidate) -> None:
    """Reject oversized model-construct bypasses before deep validation."""

    for name, max_characters in (
        ("result_id", 128),
        ("candidate_id", 128),
        ("detector_id", 64),
        ("detector_version", 64),
        ("failure_class", 128),
        ("recorded_at", 64),
    ):
        value = getattr(result, name, None)
        if value is None and name == "failure_class":
            continue
        _bounded_text(
            value,
            max_characters=max_characters,
            max_bytes=max_characters * 4,
            allow_empty=False,
        )

    _bounded_text(
        getattr(result, "message", None),
        max_characters=_MAX_MESSAGE_CHARACTERS,
        max_bytes=_MAX_MESSAGE_BYTES,
        allow_empty=False,
    )

    categories = getattr(result, "categories", None)
    if not isinstance(categories, list):
        raise _MalformedDetectorOutputError
    if len(categories) > _MAX_CATEGORIES:
        raise _DetectorOutputLimitError
    for category in categories:
        _bounded_text(
            category,
            max_characters=_MAX_CATEGORY_CHARACTERS,
            max_bytes=_MAX_CATEGORY_BYTES,
            allow_empty=False,
        )
    if len(categories) != len(set(categories)):
        raise _MalformedDetectorOutputError

    offsets = getattr(result, "evidence_offsets", None)
    if not isinstance(offsets, list):
        raise _MalformedDetectorOutputError
    if len(offsets) > _MAX_EVIDENCE_OFFSETS:
        raise _DetectorOutputLimitError
    allowed_source_refs = {reference.evidence_id for reference in candidate.source_refs}
    for offset in offsets:
        source_ref, start, end = _raw_offset_fields(offset)
        _bounded_text(source_ref, max_characters=128, max_bytes=512, allow_empty=False)
        if source_ref not in allowed_source_refs:
            raise _MalformedDetectorOutputError
        if type(start) is not int or type(end) is not int:  # bool is not an offset
            raise _MalformedDetectorOutputError
        if start < 0 or end < start:
            raise _MalformedDetectorOutputError
        if start > _MAX_OFFSET_VALUE or end > _MAX_OFFSET_VALUE:
            raise _DetectorOutputLimitError

    metadata = getattr(result, "metadata", None)
    if not isinstance(metadata, dict):
        raise _MalformedDetectorOutputError
    if len(metadata) > _MAX_METADATA_ITEMS:
        raise _DetectorOutputLimitError
    for key, value in metadata.items():
        _bounded_text(
            key,
            max_characters=_MAX_METADATA_KEY_CHARACTERS,
            max_bytes=_MAX_METADATA_KEY_BYTES,
            allow_empty=False,
        )
        if isinstance(value, str):
            _bounded_text(
                value,
                max_characters=_MAX_METADATA_VALUE_CHARACTERS,
                max_bytes=_MAX_METADATA_VALUE_BYTES,
                allow_empty=True,
            )
        elif value is None or isinstance(value, (bool, int)):
            if isinstance(value, int) and not isinstance(value, bool) and value.bit_length() > 256:
                raise _DetectorOutputLimitError
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise _MalformedDetectorOutputError
        else:
            raise _MalformedDetectorOutputError


def _hygienic_result(
    result: DetectorResult,
    candidate: MemoryCandidate,
    sanitizer: SecretSanitizer,
) -> DetectorResult:
    _validate_raw_shape(result, candidate)
    try:
        validated = DetectorResult.model_validate(result.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError, ValidationError) as exc:
        raise _MalformedDetectorOutputError from exc

    categories = [
        _bounded_text(
            sanitizer.sanitize(value).text,
            max_characters=_MAX_CATEGORY_CHARACTERS,
            max_bytes=_MAX_CATEGORY_BYTES,
            allow_empty=False,
        )
        for value in validated.categories
    ]
    if len(categories) != len(set(categories)):
        raise _MalformedDetectorOutputError

    metadata: dict[str, str | int | float | bool | None] = {}
    for key, value in validated.metadata.items():
        safe_key = _bounded_text(
            sanitizer.sanitize(key).text,
            max_characters=_MAX_METADATA_KEY_CHARACTERS,
            max_bytes=_MAX_METADATA_KEY_BYTES,
            allow_empty=False,
        )
        safe_value: str | int | float | bool | None
        if isinstance(value, str):
            safe_value = _bounded_text(
                sanitizer.sanitize(value).text,
                max_characters=_MAX_METADATA_VALUE_CHARACTERS,
                max_bytes=_MAX_METADATA_VALUE_BYTES,
                allow_empty=True,
            )
        else:
            safe_value = value
        if safe_key in metadata:
            raise _MalformedDetectorOutputError
        metadata[safe_key] = safe_value
    try:
        if len(canonical_json_bytes(metadata)) > _MAX_METADATA_SERIALIZED_BYTES:
            raise _DetectorOutputLimitError
        if validated.status is DetectorStatus.OK and validated.failure_class is not None:
            raise _MalformedDetectorOutputError
        message = _bounded_text(
            sanitizer.sanitize(validated.message).text,
            max_characters=_MAX_MESSAGE_CHARACTERS,
            max_bytes=_MAX_MESSAGE_BYTES,
            allow_empty=False,
        )
        hygienic = DetectorResult.model_validate(
            {
                **validated.model_dump(mode="python"),
                "result_id": new_id(),
                "execution_order": 0,
                "categories": categories,
                "message": message,
                "metadata": metadata,
                "failure_class": (
                    None if validated.status is DetectorStatus.OK else "DetectorReportedFailure"
                ),
                "latency_ms": 0,
                "recorded_at": format_utc(),
            }
        )
        if (
            len(canonical_json_bytes(hygienic.model_dump(mode="json")))
            > _MAX_RESULT_SERIALIZED_BYTES
        ):
            raise _DetectorOutputLimitError
    except _DetectorOutputLimitError:
        raise
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _MalformedDetectorOutputError from exc
    return hygienic


class DetectorRunner:
    def __init__(self, detectors: Sequence[Detector]) -> None:
        identifiers = [detector.detector_id for detector in detectors]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Duplicate detector ID")
        self.detectors = tuple(detectors)
        self.sanitizer = SecretSanitizer()

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
        async with span(
            "verity.detector.run",
            detector_id=detector.detector_id,
            candidate_id=candidate.candidate_id,
        ) as timing:
            result = await self._run_one_untraced(detector, candidate, timeout_seconds)
        return result.model_copy(update={"latency_ms": max(0, int(timing["latency_ms"]))})

    async def _run_one_untraced(
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
            return _hygienic_result(result, candidate, self.sanitizer)
        except _DetectorOutputLimitError:
            return self._failure(
                detector,
                candidate,
                DetectorStatus.MALFORMED,
                "OutputLimitExceeded",
            )
        except _MalformedDetectorOutputError:
            return self._failure(
                detector,
                candidate,
                DetectorStatus.MALFORMED,
                "MalformedOutput",
            )
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
