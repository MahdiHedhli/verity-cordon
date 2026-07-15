"""Deterministic offline candidate extraction and semantic assessment fixtures."""

from __future__ import annotations

import re

from verity_cordon.core.models import (
    Action,
    MemoryCandidate,
    MemoryKind,
    PersistenceIntent,
    ProviderState,
    SemanticAssessment,
    Sensitivity,
    Signal,
    SourceClass,
    format_utc,
    new_id,
)
from verity_cordon.crypto.canonical import sha256_hex


def _compact(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _first_sentence(value: str) -> str:
    return re.split(r"(?<=[.!?])\s+", value.strip(), maxsplit=1)[0]


class FixtureCandidateExtractor:
    provider_label = "recorded_fixture"
    extractor_version = "verity-fixture-extractor-v1"

    async def extract(
        self,
        *,
        sanitized_evidence: str,
        evidence_id: str,
        evidence_digest: str,
        source_class: str,
        session_id: str,
        task_id: str | None,
    ) -> list[MemoryCandidate]:
        compact = _compact(sanitized_evidence)
        if not compact:
            return []
        source = SourceClass(source_class)
        lowered = compact.casefold()
        poison_start = min(
            (
                index
                for marker in ("for all future", "preserve this", "from now on")
                if (index := lowered.find(marker)) >= 0
            ),
            default=-1,
        )
        statements: list[tuple[str, MemoryKind, str, bool, Signal, Signal]] = []
        if poison_start > 0:
            safe_part = compact[:poison_start].strip(" .")
            unsafe_part = compact[poison_start:].strip()
            if safe_part:
                first_sentence = _first_sentence(safe_part)
                if not first_sentence.endswith((".", "!", "?")):
                    first_sentence += "."
                statements.append(
                    (
                        first_sentence,
                        MemoryKind.FACT,
                        "project.release",
                        False,
                        Signal.NONE,
                        Signal.NONE,
                    )
                )
            statements.append(
                (
                    unsafe_part,
                    MemoryKind.OPERATIONAL_INSTRUCTION,
                    "instructions.release",
                    True,
                    Signal.EXPLICIT,
                    (
                        Signal.EXPLICIT
                        if "do not mention" in unsafe_part.casefold()
                        else Signal.IMPLIED
                    ),
                )
            )
        else:
            first_sentence = _first_sentence(compact)
            if first_sentence and not first_sentence.endswith("."):
                first_sentence += "."
            is_preference = lowered.startswith(("i prefer", "please remember that i prefer"))
            is_credential = "<redacted:" in lowered
            statements.append(
                (
                    first_sentence or compact,
                    (
                        MemoryKind.CREDENTIAL_MATERIAL
                        if is_credential
                        else MemoryKind.USER_PREFERENCE
                        if is_preference
                        else MemoryKind.FACT
                    ),
                    "credentials.redacted"
                    if is_credential
                    else "preferences.general"
                    if is_preference
                    else "project.general",
                    "remember" in lowered,
                    Signal.NONE,
                    Signal.NONE,
                )
            )

        candidates: list[MemoryCandidate] = []
        for statement, kind, namespace, persistence, authority, secrecy in statements:
            contains_redactions = "<REDACTED:" in statement
            candidates.append(
                MemoryCandidate(
                    candidate_id=new_id(),
                    namespace=namespace,
                    kind=kind,
                    statement=statement,
                    source_class=source,
                    source_refs=[
                        {
                            "evidence_id": evidence_id,
                            "evidence_digest": evidence_digest,
                        }
                    ],
                    session_id=session_id,
                    task_id=task_id,
                    confidence=0.95,
                    durability_rationale="Atomic durable context from sanitized evidence.",
                    sensitivity=(
                        Sensitivity.CREDENTIAL if contains_redactions else Sensitivity.PUBLIC
                    ),
                    persistence_requested=persistence,
                    authority_signal=authority,
                    secrecy_signal=secrecy,
                    contains_redactions=contains_redactions,
                    extractor_provider="recorded_fixture",
                    extractor_version=self.extractor_version,
                    content_digest=sha256_hex(statement.encode("utf-8")),
                    created_at=format_utc(),
                )
            )
        return candidates


class FixtureSemanticAdjudicator:
    provider_label = "recorded_fixture"
    prompt_version = "semantic-risk-v1"

    async def assess(self, candidate: MemoryCandidate) -> SemanticAssessment:
        lowered = candidate.statement.casefold()
        persistent = bool(
            candidate.persistence_requested
            or any(
                marker in lowered
                for marker in ("for all future", "permanent", "preserve this", "from now on")
            )
        )
        concealed = any(
            marker in lowered for marker in ("do not mention", "do not tell", "keep this secret")
        )
        authority = bool(
            candidate.authority_signal == Signal.EXPLICIT
            or any(marker in lowered for marker in ("mandatory", "system policy", "override"))
        )
        exfiltration = any(
            marker in lowered for marker in ("send the release", "environment values", "exfiltrate")
        )
        categories: list[str] = []
        if persistent:
            categories.append("persistent_instruction")
        if authority:
            categories.append("privilege_escalation")
        if exfiltration:
            categories.extend(["tool_hijack", "data_exfiltration"])
        if concealed:
            categories.append("concealed_instruction")
        if candidate.contains_redactions or candidate.kind == MemoryKind.CREDENTIAL_MATERIAL:
            categories.append("secret_material")
        if not categories:
            categories.append(
                "benign_preference"
                if candidate.kind == MemoryKind.USER_PREFERENCE
                else "benign_fact"
            )
        malicious = bool(
            persistent
            or authority
            or exfiltration
            or concealed
            or "secret_material" in categories
        )
        risk = 0.97 if malicious else 0.06
        return SemanticAssessment(
            assessment_id=new_id(),
            candidate_id=candidate.candidate_id,
            provider_state=ProviderState.RECORDED_FIXTURE,
            requested_model=None,
            returned_model="verity-fixture-v1",
            prompt_version=self.prompt_version,
            risk_score=risk,
            categories=categories,
            persistence_intent=(
                PersistenceIntent.EXPLICIT if persistent else PersistenceIntent.NONE
            ),
            authority_claim=Signal.EXPLICIT if authority else Signal.NONE,
            exfiltration_risk=0.95 if exfiltration else 0.02,
            tool_hijack_risk=0.93 if exfiltration else 0.02,
            cross_task_risk=0.9 if persistent else 0.02,
            secret_risk=0.99 if "secret_material" in categories else 0.01,
            rationale=(
                "Fixture indicates persistent authority, concealment, or transfer risk."
                if malicious
                else "Fixture indicates low-risk durable context."
            ),
            recommended_disposition=Action.QUARANTINE if malicious else Action.ALLOW,
            sanitized_content_digest=candidate.content_digest,
            cache_hit=False,
            latency_ms=0,
            failure=None,
            assessed_at=format_utc(),
        )
