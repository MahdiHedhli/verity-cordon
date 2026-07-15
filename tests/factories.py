"""Synthetic-only model factories shared by security tests."""

from __future__ import annotations

from verity_cordon.core.models import (
    MemoryCandidate,
    MemoryKind,
    Sensitivity,
    Signal,
    SourceClass,
    format_utc,
    new_id,
)
from verity_cordon.crypto.canonical import sha256_hex


def make_candidate(
    statement: str = "The release manifest is generated from release.yaml.",
    *,
    kind: MemoryKind = MemoryKind.FACT,
    namespace: str = "project.release",
    source_class: SourceClass = SourceClass.USER_INPUT,
    session_id: str | None = None,
    task_id: str | None = None,
    sensitivity: Sensitivity = Sensitivity.PUBLIC,
    persistence_requested: bool = False,
    authority_signal: Signal = Signal.NONE,
    secrecy_signal: Signal = Signal.NONE,
    contains_redactions: bool = False,
) -> MemoryCandidate:
    return MemoryCandidate(
        candidate_id=new_id(),
        namespace=namespace,
        kind=kind,
        statement=statement,
        source_class=source_class,
        source_refs=[
            {
                "evidence_id": new_id(),
                "evidence_digest": sha256_hex(b"synthetic evidence"),
            }
        ],
        session_id=session_id or new_id(),
        task_id=task_id,
        confidence=0.9,
        durability_rationale="Synthetic security-test candidate.",
        sensitivity=sensitivity,
        persistence_requested=persistence_requested,
        authority_signal=authority_signal,
        secrecy_signal=secrecy_signal,
        contains_redactions=contains_redactions,
        extractor_provider="deterministic",
        extractor_version="test-1",
        content_digest=sha256_hex(statement.encode()),
        created_at=format_utc(),
    )
