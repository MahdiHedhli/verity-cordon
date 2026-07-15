"""Conservative content projection for routine operator surfaces."""

from __future__ import annotations

from typing import Any

from verity_cordon.core.models import Action, MemoryCandidate, MemoryKind, Sensitivity
from verity_cordon.detectors.builtin import SecretSanitizer


def display_safe_statement(
    candidate: MemoryCandidate,
    *,
    action: Action | None = None,
) -> str:
    """Return content suitable for routine UI/CLI views, never raw secret material."""

    if action is Action.REDACT:
        return f"[REDACTED BY POLICY: {candidate.namespace}]"
    if (
        candidate.contains_redactions
        or candidate.kind is MemoryKind.CREDENTIAL_MATERIAL
        or candidate.sensitivity is Sensitivity.CREDENTIAL
    ):
        return "[REDACTED: detected credential material is hidden from routine views]"
    if candidate.sensitivity in {Sensitivity.SENSITIVE, Sensitivity.RESTRICTED}:
        return "[REDACTED: sensitive candidate content is hidden from routine views]"
    sanitized = SecretSanitizer().sanitize(candidate.statement)
    if sanitized.contains_secrets:
        return "[REDACTED: detected credential material is hidden from routine views]"
    return sanitized.text


def display_safe_candidate(candidate: MemoryCandidate) -> dict[str, Any]:
    projected = candidate.model_dump(mode="json")
    projected["statement"] = display_safe_statement(candidate)
    if (
        candidate.contains_redactions
        or candidate.kind is MemoryKind.CREDENTIAL_MATERIAL
        or candidate.sensitivity
        in {Sensitivity.CREDENTIAL, Sensitivity.SENSITIVE, Sensitivity.RESTRICTED}
    ):
        projected["durability_rationale"] = "Candidate rationale hidden for sensitive content."
    else:
        rationale = SecretSanitizer().sanitize(candidate.durability_rationale)
        projected["durability_rationale"] = (
            "Candidate rationale hidden because it contained credential-like material."
            if rationale.contains_secrets
            else rationale.text
        )
    return projected
