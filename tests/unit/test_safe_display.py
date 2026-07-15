"""Routine operator projections must not expose credential or sensitive content."""

from __future__ import annotations

from tests.factories import make_candidate
from verity_cordon.core.models import MemoryKind, Sensitivity
from verity_cordon.memory.safe_display import display_safe_candidate, display_safe_statement


def test_credential_candidate_is_hidden_from_routine_display() -> None:
    candidate = make_candidate(
        "Authorization: Bearer SYNTHETIC_ONLY_1234567890",
        kind=MemoryKind.CREDENTIAL_MATERIAL,
        namespace="credentials.redacted",
        sensitivity=Sensitivity.CREDENTIAL,
        contains_redactions=True,
    )

    statement = display_safe_statement(candidate)

    assert "SYNTHETIC_ONLY" not in statement
    assert statement.startswith("[REDACTED:")


def test_sensitive_candidate_is_hidden_while_benign_public_fact_remains_legible() -> None:
    sensitive = make_candidate(
        "Synthetic private preference detail.",
        sensitivity=Sensitivity.SENSITIVE,
    ).model_copy(
        update={"durability_rationale": "Synthetic private preference detail should be remembered."}
    )
    public = make_candidate("The project uses Python 3.12.")

    assert "private preference" not in display_safe_statement(sensitive)
    assert "private preference" not in display_safe_candidate(sensitive)["durability_rationale"]
    assert display_safe_candidate(public)["statement"] == "The project uses Python 3.12."
