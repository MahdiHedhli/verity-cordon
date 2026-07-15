"""Async-first interfaces for replaceable Verity components."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from verity_cordon.core.models import (
    DetectorResult,
    EventEnvelope,
    EventInput,
    LedgerVerification,
    MemoryCandidate,
    MemoryRecord,
    SemanticAssessment,
)


@runtime_checkable
class EventStore(Protocol):
    async def initialize(self) -> None: ...

    async def append(self, events: Sequence[EventInput]) -> list[EventEnvelope]: ...

    async def list_events(self) -> list[EventEnvelope]: ...

    async def verify(self, *, verify_view: bool = True) -> LedgerVerification: ...


@runtime_checkable
class MemoryView(Protocol):
    async def list_active(self) -> list[MemoryRecord]: ...

    async def rebuild(self, *, dry_run: bool) -> Mapping[str, Any]: ...


@runtime_checkable
class Detector(Protocol):
    detector_id: str
    detector_version: str

    async def inspect(self, candidate: MemoryCandidate) -> DetectorResult: ...


@runtime_checkable
class CandidateExtractor(Protocol):
    provider_label: str

    async def extract(
        self,
        *,
        sanitized_evidence: str,
        evidence_id: str,
        evidence_digest: str,
        source_class: str,
        session_id: str,
        task_id: str | None,
    ) -> list[MemoryCandidate]: ...


@runtime_checkable
class SemanticAdjudicator(Protocol):
    provider_label: str

    async def assess(self, candidate: MemoryCandidate) -> SemanticAssessment: ...


@runtime_checkable
class PolicyProvider(Protocol):
    async def get_active(self) -> Any: ...

    async def activate(self, raw_policy: Mapping[str, Any]) -> Any: ...


@runtime_checkable
class EventSink(Protocol):
    async def emit(self, name: str, attributes: Mapping[str, Any]) -> None: ...


@runtime_checkable
class CodexAdapter(Protocol):
    async def submit_evidence(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...

    async def session_context(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> datetime: ...


@runtime_checkable
class KeyProvider(Protocol):
    @property
    def key_id(self) -> str: ...

    async def sign(self, digest: bytes) -> bytes: ...

    async def verify(self, digest: bytes, signature: bytes) -> None: ...

    async def export_public(self) -> Mapping[str, str]: ...

