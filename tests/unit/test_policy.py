"""Deterministic policy validation and decision tests."""

from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from verity_cordon.core.models import (
    Action,
    DetectorResult,
    DetectorStatus,
    MemoryCandidate,
    MemoryKind,
    PersistenceIntent,
    ProviderState,
    SemanticAssessment,
    Sensitivity,
    Severity,
    Signal,
    SourceClass,
    format_utc,
    new_id,
)
from verity_cordon.crypto.canonical import sha256_hex
from verity_cordon.policies.engine import LastKnownGoodPolicyProvider, PolicyEngine
from verity_cordon.policies.models import PolicyDocument


def policy_dict(*, mode: str = "enforce") -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "engine_profile": "VC-POLICY-1",
        "policy_id": "verity.default",
        "version": "1.0.0",
        "mode": mode,
        "default_action": "allow",
        "shadow_action": "allow",
        "protected_namespaces": ["policies.*"],
        "rules": [
            {
                "rule_id": "persistent-tool",
                "priority": 100,
                "description": "Quarantine persistent tool instructions.",
                "match": {
                    "source_classes": ["tool_output"],
                    "memory_kinds": ["operational_instruction"],
                    "detector_categories_any": ["persistent_instruction"],
                },
                "action": "quarantine",
                "manual_review_required": True,
                "ttl_seconds": None,
            },
            {
                "rule_id": "safe-fact",
                "priority": 200,
                "description": "Allow safe project facts.",
                "match": {
                    "memory_kinds": ["fact"],
                    "maximum_placeholder": [],
                },
                "action": "allow",
                "manual_review_required": False,
                "ttl_seconds": 3600,
            },
        ],
        "failure_behavior": {
            "detector_failure_high_risk": "quarantine",
            "detector_failure_lower_risk": "quarantine",
            "semantic_timeout_high_risk": "quarantine",
            "semantic_timeout_lower_risk": "quarantine",
            "semantic_invalid_high_risk": "block",
            "semantic_invalid_lower_risk": "quarantine",
            "ledger_unavailable": "refuse_commits_and_disable_injection",
            "ledger_corrupt": "refuse_commits_and_disable_injection",
            "invalid_policy": "refuse_new_commits",
            "daemon_unavailable": "continue_without_verity_memory",
            "codex_hook_failure": "continue_without_verity_memory",
        },
        "manual_review": {
            "required_actions": ["approve", "block", "revoke"],
            "reason_required": True,
            "actor_id_required": True,
            "confirmation_required": True,
        },
        "limits": {
            "max_candidate_bytes": 8192,
            "max_evidence_bytes": 1048576,
            "max_stream_bytes": 1048576,
            "max_stream_chunks": 256,
            "detector_timeout_ms": 500,
            "semantic_timeout_ms": 10000,
            "injection_token_budget": 2000,
            "default_ttl_seconds": None,
        },
        "created_at": "2026-07-15T00:00:00Z",
    }


def candidate(
    *,
    kind: MemoryKind = MemoryKind.FACT,
    namespace: str = "project.release",
    source: SourceClass = SourceClass.USER_INPUT,
    sensitivity: Sensitivity = Sensitivity.PUBLIC,
) -> MemoryCandidate:
    statement = "Release manifests use synthetic values."
    return MemoryCandidate(
        candidate_id=new_id(),
        namespace=namespace,
        kind=kind,
        statement=statement,
        source_class=source,
        source_refs=[
            {
                "evidence_id": new_id(),
                "evidence_digest": sha256_hex(b"evidence"),
            }
        ],
        session_id=new_id(),
        confidence=0.9,
        durability_rationale="Useful project context.",
        sensitivity=sensitivity,
        persistence_requested=False,
        authority_signal=Signal.NONE,
        secrecy_signal=Signal.NONE,
        contains_redactions=False,
        extractor_provider="deterministic",
        extractor_version="test-1",
        content_digest=sha256_hex(statement.encode()),
        created_at=format_utc(),
    )


def detector(
    target: MemoryCandidate,
    *,
    category: str = "persistent_instruction",
    severity: Severity = Severity.HIGH,
    status: DetectorStatus = DetectorStatus.OK,
    matched: bool | None = True,
) -> DetectorResult:
    return DetectorResult(
        result_id=new_id(),
        candidate_id=target.candidate_id,
        detector_id="test.detector",
        detector_version="1.0.0",
        execution_order=0,
        status=status,
        matched=matched,
        severity=severity,
        confidence=0.9,
        categories=[category],
        message="Safe test result.",
        failure_class="Timeout" if status != DetectorStatus.OK else None,
        latency_ms=1,
        recorded_at=format_utc(),
    )


def assessment(target: MemoryCandidate, *, risk: float = 0.8) -> SemanticAssessment:
    return SemanticAssessment(
        assessment_id=new_id(),
        candidate_id=target.candidate_id,
        provider_state=ProviderState.RECORDED_FIXTURE,
        requested_model=None,
        returned_model="fixture-v1",
        prompt_version="risk-v1",
        risk_score=risk,
        categories=["persistent_instruction"],
        persistence_intent=PersistenceIntent.EXPLICIT,
        authority_claim=Signal.EXPLICIT,
        exfiltration_risk=0.5,
        tool_hijack_risk=0.7,
        cross_task_risk=0.7,
        secret_risk=0.0,
        rationale="Synthetic fixture assessment.",
        recommended_disposition=Action.QUARANTINE,
        sanitized_content_digest=target.content_digest,
        latency_ms=1,
        assessed_at=format_utc(),
    )


def valid_policy(*, mode: str = "enforce") -> PolicyDocument:
    raw = policy_dict(mode=mode)
    safe_fact_rule = raw["rules"][1]  # type: ignore[index]
    safe_fact_rule["match"].pop("maximum_placeholder")  # type: ignore[index,union-attr]
    return PolicyDocument.model_validate(raw)


def test_policy_rejects_unknown_fields_and_duplicate_rules() -> None:
    raw = policy_dict()
    raw["rules"][1]["match"].pop("maximum_placeholder")  # type: ignore[index,union-attr]
    raw["unexpected"] = True
    with pytest.raises(ValidationError):
        PolicyDocument.model_validate(raw)

    duplicate = policy_dict()
    duplicate["rules"][1]["match"].pop("maximum_placeholder")  # type: ignore[index,union-attr]
    duplicate["rules"][1]["rule_id"] = "persistent-tool"  # type: ignore[index]
    with pytest.raises(ValidationError, match="Duplicate policy rule ID"):
        PolicyDocument.model_validate(duplicate)


def test_policy_rejects_empty_match_and_invalid_engine_profile() -> None:
    raw = policy_dict()
    raw["rules"][1]["match"] = {}  # type: ignore[index]
    with pytest.raises(ValidationError):
        PolicyDocument.model_validate(raw)

    raw = policy_dict()
    raw["rules"][1]["match"].pop("maximum_placeholder")  # type: ignore[index,union-attr]
    raw["engine_profile"] = "unsafe"
    with pytest.raises(ValidationError):
        PolicyDocument.model_validate(raw)


def test_rule_evaluation_is_sorted_by_priority_then_id() -> None:
    raw = policy_dict()
    raw["rules"] = [
        {
            "rule_id": "z-rule",
            "priority": 10,
            "description": "Later lexical rule.",
            "match": {"memory_kinds": ["fact"]},
            "action": "block",
            "manual_review_required": False,
            "ttl_seconds": None,
        },
        {
            "rule_id": "a-rule",
            "priority": 10,
            "description": "Earlier lexical rule.",
            "match": {"memory_kinds": ["fact"]},
            "action": "redact",
            "manual_review_required": False,
            "ttl_seconds": None,
        },
    ]
    evaluation = PolicyEngine(PolicyDocument.model_validate(raw)).evaluate(candidate(), [], None)

    assert evaluation.decision.matched_rule_id == "a-rule"
    assert evaluation.decision.would_have_action is Action.REDACT


@pytest.mark.parametrize(
    ("target", "finding"),
    [
        (candidate(kind=MemoryKind.CREDENTIAL_MATERIAL), None),
        (candidate(sensitivity=Sensitivity.CREDENTIAL), None),
        (candidate(), "credential_material"),
        (candidate(), "structural_invalidity"),
        (candidate(namespace="policies.system"), None),
    ],
)
def test_vc_policy_1_hard_guards_cannot_be_weakened(
    target: MemoryCandidate, finding: str | None
) -> None:
    findings = [detector(target, category=finding)] if finding else []
    evaluation = PolicyEngine(valid_policy()).evaluate(target, findings, None)

    assert evaluation.decision.actual_action is Action.BLOCK
    assert evaluation.decision.would_have_action is Action.BLOCK
    assert evaluation.decision.reason_codes[0].startswith("hard_guard.")


def test_rule_fields_are_anded_and_list_values_are_ored() -> None:
    target = candidate(
        kind=MemoryKind.OPERATIONAL_INSTRUCTION,
        source=SourceClass.TOOL_OUTPUT,
    )
    engine = PolicyEngine(valid_policy())

    matched = engine.evaluate(target, [detector(target)], assessment(target))
    missing_detector = engine.evaluate(target, [], assessment(target))

    assert matched.decision.would_have_action is Action.QUARANTINE
    assert matched.decision.matched_rule_id == "persistent-tool"
    assert missing_detector.decision.would_have_action is Action.ALLOW


def test_shadow_records_enforcement_action_but_applies_shadow_action() -> None:
    target = candidate(
        kind=MemoryKind.OPERATIONAL_INSTRUCTION,
        source=SourceClass.TOOL_OUTPUT,
    )
    evaluation = PolicyEngine(valid_policy(mode="shadow")).evaluate(
        target, [detector(target)], assessment(target)
    )

    assert evaluation.decision.would_have_action is Action.QUARANTINE
    assert evaluation.decision.actual_action is Action.ALLOW
    assert evaluation.decision.shadow_mode is True


def test_detector_failure_uses_explicit_high_risk_fallback() -> None:
    target = candidate(kind=MemoryKind.OPERATIONAL_INSTRUCTION)
    failed = detector(
        target,
        status=DetectorStatus.TIMEOUT,
        matched=None,
    )

    evaluation = PolicyEngine(valid_policy()).evaluate(target, [failed], None)

    assert evaluation.decision.would_have_action is Action.QUARANTINE
    assert "failure.detector.high_risk" in evaluation.decision.reason_codes


def test_semantic_predicates_require_successful_assessment() -> None:
    raw = policy_dict()
    raw["rules"] = [
        {
            "rule_id": "semantic-risk",
            "priority": 1,
            "description": "Block high semantic risk.",
            "match": {"minimum_semantic_risk": 0.7, "semantic_required": True},
            "action": "block",
            "manual_review_required": False,
            "ttl_seconds": None,
        }
    ]
    engine = PolicyEngine(PolicyDocument.model_validate(raw))
    target = candidate()

    assert engine.evaluate(target, [], None).decision.would_have_action is Action.ALLOW
    assert (
        engine.evaluate(target, [], assessment(target)).decision.would_have_action
        is Action.BLOCK
    )


def test_last_known_good_policy_survives_rejected_activation() -> None:
    initial = valid_policy()
    provider = LastKnownGoodPolicyProvider(initial)
    invalid = deepcopy(policy_dict())
    invalid["rules"] = []

    with pytest.raises(ValidationError):
        provider.activate_sync(invalid)

    assert provider.get_active_sync() is initial
    assert provider.last_rejection_class == "ValidationError"


def test_validated_policy_digest_is_stable() -> None:
    first = valid_policy()
    second = PolicyDocument.model_validate(first.model_dump(mode="json"))

    assert first.content_digest == second.content_digest
    assert len(first.content_digest) == 64
