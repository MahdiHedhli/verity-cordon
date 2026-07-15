"""Compact deterministic detectors and secret-first evidence sanitization."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from verity_cordon.core.models import (
    DetectorResult,
    DetectorStatus,
    EvidenceOffset,
    MemoryCandidate,
    MemoryKind,
    Sensitivity,
    Severity,
    Signal,
    SourceClass,
    format_utc,
    new_id,
)
from verity_cordon.core.protocols import Detector


@dataclass(frozen=True, slots=True)
class SanitizedEvidence:
    text: str
    contains_secrets: bool
    redaction_count: int
    redaction_types: tuple[str, ...]


class SecretSanitizer:
    """Locally replace obvious secret material before any semantic call."""

    _patterns: ClassVar[tuple[tuple[str, re.Pattern[str]], ...]] = (
        (
            "PRIVATE_KEY",
            re.compile(
                r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?"
                r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            ),
        ),
        ("OPENAI_API_KEY", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}\b")),
        ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
        ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        (
            "ASSIGNED_SECRET",
            re.compile(
                r"(?i)\b(?:password|passphrase|api[_-]?key|access[_-]?token|secret)"
                r"\s*[:=]\s*[\"']?[^\s\"']{8,}[\"']?",
            ),
        ),
    )

    def sanitize(self, content: str) -> SanitizedEvidence:
        matches: list[tuple[int, int, str]] = []
        for secret_type, pattern in self._patterns:
            matches.extend(
                (item.start(), item.end(), secret_type) for item in pattern.finditer(content)
            )
        matches.sort(key=lambda item: (item[0], -(item[1] - item[0]), item[2]))

        selected: list[tuple[int, int, str]] = []
        cursor = -1
        for start, end, secret_type in matches:
            if start < cursor:
                continue
            selected.append((start, end, secret_type))
            cursor = end
        if not selected:
            return SanitizedEvidence(content, False, 0, ())

        counters: dict[str, int] = {}
        chunks: list[str] = []
        cursor = 0
        types: list[str] = []
        for start, end, secret_type in selected:
            counters[secret_type] = counters.get(secret_type, 0) + 1
            chunks.append(content[cursor:start])
            chunks.append(f"<REDACTED:{secret_type}_{counters[secret_type]}>")
            cursor = end
            types.append(secret_type)
        chunks.append(content[cursor:])
        return SanitizedEvidence("".join(chunks), True, len(selected), tuple(types))


def _discussion_context(statement: str) -> bool:
    lowered = statement.casefold()
    markers = (
        "is an example",
        "as an example",
        "the phrase",
        "the security guide",
        "explains that",
        "quoted text",
        "not an instruction",
        "do not follow",
    )
    return any(marker in lowered for marker in markers)


class _BuiltinDetector:
    detector_id: str
    detector_version = "1.0.0"
    category: str

    def _result(
        self,
        candidate: MemoryCandidate,
        *,
        matched: bool,
        severity: Severity,
        confidence: float,
        message: str,
        span: tuple[int, int] | None = None,
    ) -> DetectorResult:
        offsets = []
        if matched and span is not None:
            offsets = [
                EvidenceOffset(
                    source_ref=candidate.source_refs[0].evidence_id,
                    start=span[0],
                    end=span[1],
                )
            ]
        return DetectorResult(
            result_id=new_id(),
            candidate_id=candidate.candidate_id,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            execution_order=0,
            status=DetectorStatus.OK,
            matched=matched,
            severity=severity,
            confidence=confidence,
            categories=[self.category] if matched else [],
            message=message,
            evidence_offsets=offsets,
            metadata={},
            latency_ms=0,
            recorded_at=format_utc(),
        )


class CredentialMaterialDetector(_BuiltinDetector):
    detector_id = "credential-material"
    category = "credential_material"

    async def inspect(self, candidate: MemoryCandidate) -> DetectorResult:
        marker = re.search(r"<REDACTED:[A-Z0-9_]+_\d+>", candidate.statement)
        matched = bool(
            marker
            or candidate.contains_redactions
            or candidate.kind == MemoryKind.CREDENTIAL_MATERIAL
            or candidate.sensitivity == Sensitivity.CREDENTIAL
        )
        return self._result(
            candidate,
            matched=matched,
            severity=Severity.CRITICAL if matched else Severity.INFO,
            confidence=1.0 if matched else 0.99,
            message=(
                "Candidate contains or represents credential material."
                if matched
                else "No credential material indicator was found."
            ),
            span=(marker.start(), marker.end()) if marker else None,
        )


class PersistentInstructionDetector(_BuiltinDetector):
    detector_id = "persistent-instruction"
    category = "persistent_instruction"
    _pattern = re.compile(
        r"(?i)\b(?:for all future|future sessions?|permanent(?:ly)?|preserve this|"
        r"always|remember this|from now on)\b"
    )

    async def inspect(self, candidate: MemoryCandidate) -> DetectorResult:
        match = self._pattern.search(candidate.statement)
        matched = bool(match) and not _discussion_context(candidate.statement)
        return self._result(
            candidate,
            matched=matched,
            severity=Severity.HIGH if matched else Severity.INFO,
            confidence=0.94 if matched else 0.9,
            message=(
                "Candidate contains language requesting durable future behavior."
                if matched
                else "No actionable persistence request was found."
            ),
            span=(match.start(), match.end()) if match and matched else None,
        )


class ProtectedNamespaceDetector(_BuiltinDetector):
    detector_id = "protected-namespace"
    category = "protected_namespace"

    async def inspect(self, candidate: MemoryCandidate) -> DetectorResult:
        matched = candidate.namespace == "policies" or candidate.namespace.startswith("policies.")
        return self._result(
            candidate,
            matched=matched,
            severity=Severity.CRITICAL if matched else Severity.INFO,
            confidence=1.0,
            message=(
                "Candidate targets a protected policy namespace."
                if matched
                else "Candidate does not target a protected policy namespace."
            ),
        )


class CrossTaskDetector(_BuiltinDetector):
    detector_id = "cross-task-contamination"
    category = "cross_task_contamination"
    _pattern = re.compile(r"(?i)\b(?:unrelated|other|every|all)\s+(?:tasks?|projects?|sessions?)\b")

    async def inspect(self, candidate: MemoryCandidate) -> DetectorResult:
        match = self._pattern.search(candidate.statement)
        matched = bool(match) and not _discussion_context(candidate.statement)
        return self._result(
            candidate,
            matched=matched,
            severity=Severity.HIGH if matched else Severity.INFO,
            confidence=0.88 if matched else 0.85,
            message=(
                "Candidate attempts to cross a task or project boundary."
                if matched
                else "No cross-task scope expansion was found."
            ),
            span=(match.start(), match.end()) if match and matched else None,
        )


class SelfReinforcementDetector(_BuiltinDetector):
    detector_id = "self-reinforcement"
    category = "self_reinforcement"
    _pattern = re.compile(
        r"(?i)\b(?:i generated|model[- ]authored|agent[- ]authored|"
        r"must never be changed|cannot be changed|reinforce this rule)\b"
    )

    async def inspect(self, candidate: MemoryCandidate) -> DetectorResult:
        match = self._pattern.search(candidate.statement)
        source_risk = candidate.source_class == SourceClass.AGENT_OUTPUT
        matched = bool(match) and (source_risk or "i generated" in candidate.statement.casefold())
        return self._result(
            candidate,
            matched=matched,
            severity=Severity.HIGH if matched else Severity.INFO,
            confidence=0.9 if matched else 0.84,
            message=(
                "Agent-authored content attempts to reinforce its own authority."
                if matched
                else "No agent self-reinforcement pattern was found."
            ),
            span=(match.start(), match.end()) if match and matched else None,
        )


class UntrustedAuthorityDetector(_BuiltinDetector):
    detector_id = "untrusted-authority"
    category = "untrusted_authority"
    _pattern = re.compile(
        r"(?i)\b(?:mandatory|system policy|authoritative|override|higher priority|must obey)\b"
    )

    async def inspect(self, candidate: MemoryCandidate) -> DetectorResult:
        match = self._pattern.search(candidate.statement)
        untrusted = candidate.source_class in {
            SourceClass.TOOL_OUTPUT,
            SourceClass.AGENT_OUTPUT,
            SourceClass.IMPORTED_FILE,
            SourceClass.EXTERNAL_EVENT,
        }
        matched = bool(match) and untrusted and not _discussion_context(candidate.statement)
        return self._result(
            candidate,
            matched=matched,
            severity=Severity.HIGH if matched else Severity.INFO,
            confidence=0.92 if matched else 0.86,
            message=(
                "Untrusted content attempts to establish decision authority."
                if matched
                else "No untrusted authority claim was found."
            ),
            span=(match.start(), match.end()) if match and matched else None,
        )


class AnomalousSizeDetector(_BuiltinDetector):
    detector_id = "anomalous-size"
    category = "anomalous_size"

    def __init__(self, max_candidate_bytes: int) -> None:
        self.max_candidate_bytes = max_candidate_bytes

    async def inspect(self, candidate: MemoryCandidate) -> DetectorResult:
        size = len(candidate.statement.encode("utf-8"))
        matched = size > self.max_candidate_bytes
        return self._result(
            candidate,
            matched=matched,
            severity=Severity.HIGH if matched else Severity.INFO,
            confidence=1.0,
            message=(
                "Candidate exceeds the configured size boundary."
                if matched
                else "Candidate is within the configured size boundary."
            ),
        )


class ConcealedInstructionDetector(_BuiltinDetector):
    detector_id = "concealed-instruction"
    category = "concealed_instruction"
    _pattern = re.compile(
        r"(?i)\b(?:do not (?:tell|mention|disclose)|never (?:tell|mention|disclose)|"
        r"keep (?:this|the instruction) secret|hide this instruction)\b"
    )

    async def inspect(self, candidate: MemoryCandidate) -> DetectorResult:
        match = self._pattern.search(candidate.statement)
        signal = candidate.secrecy_signal in {Signal.IMPLIED, Signal.EXPLICIT}
        matched = (bool(match) or signal) and not _discussion_context(candidate.statement)
        return self._result(
            candidate,
            matched=matched,
            severity=Severity.HIGH if matched else Severity.INFO,
            confidence=0.96 if matched else 0.9,
            message=(
                "Candidate contains a concealment request."
                if matched
                else "No actionable concealment request was found."
            ),
            span=(match.start(), match.end()) if match and matched else None,
        )


def builtin_detectors(*, max_candidate_bytes: int = 8192) -> list[Detector]:
    return [
        AnomalousSizeDetector(max_candidate_bytes),
        ConcealedInstructionDetector(),
        CredentialMaterialDetector(),
        CrossTaskDetector(),
        PersistentInstructionDetector(),
        ProtectedNamespaceDetector(),
        SelfReinforcementDetector(),
        UntrustedAuthorityDetector(),
    ]
