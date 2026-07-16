"""Replay and public-contract compatibility for the subscription provider label."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, get_args

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from openapi_spec_validator import validate as validate_openapi
from pydantic import ValidationError

from verity_cordon.core.models import (
    MemoryCandidate,
    MemoryRecord,
    ProviderState,
    ProviderSummaryState,
    RequestedProvider,
    SemanticAssessment,
    SemanticFailure,
    provider_isolation_for,
)

REPOSITORY_ROOT = Path(__file__).parents[2]
CONTRACTS = REPOSITORY_ROOT / "specs/001-codex-memory-firewall/contracts"
SHA256 = "a" * 64
CREATED_AT = "2026-07-15T12:00:00Z"


def _candidate_payload(*, extractor_provider: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "candidate_id": "candidate-history-001",
        "namespace": "project.release",
        "kind": "fact",
        "statement": "Release manifests are generated from release.yaml.",
        "source_class": "tool_output",
        "source_refs": [
            {
                "evidence_id": "evidence-history-001",
                "evidence_digest": SHA256,
            }
        ],
        "session_id": "session-history-001",
        "task_id": "task-history-001",
        "confidence": 0.9,
        "durability_rationale": "Synthetic historical payload.",
        "sensitivity": "public",
        "requested_ttl_seconds": None,
        "persistence_requested": False,
        "authority_signal": "none",
        "secrecy_signal": "none",
        "contains_redactions": False,
        "extractor_provider": extractor_provider,
        "extractor_version": "historical-extractor-v1",
        "content_digest": SHA256,
        "created_at": CREATED_AT,
    }


def _assessment_payload(*, provider_state: str) -> dict[str, Any]:
    live = provider_state in {"live_openai", "live_codex_subscription"}
    return {
        "schema_version": "1.0.0",
        "assessment_id": "assessment-history-001",
        "candidate_id": "candidate-history-001",
        "provider_state": provider_state,
        "requested_model": "gpt-5.6" if live else None,
        "returned_model": "gpt-5.6" if provider_state == "live_openai" else None,
        "prompt_version": "semantic-risk-v1",
        "risk_score": 0.1,
        "categories": ["benign_fact"],
        "persistence_intent": "none",
        "authority_claim": "none",
        "exfiltration_risk": 0.0,
        "tool_hijack_risk": 0.0,
        "cross_task_risk": 0.0,
        "secret_risk": 0.0,
        "rationale": "Synthetic historical assessment.",
        "recommended_disposition": "allow",
        "sanitized_content_digest": SHA256,
        "cache_hit": False,
        "latency_ms": 5,
        "failure": None,
        "assessed_at": CREATED_AT,
    }


def _memory_payload(*, semantic_provider: str) -> dict[str, Any]:
    return {
        "memory_id": "memory-history-001",
        "commit_event_id": "event-commit-history-001",
        "candidate_id": "candidate-history-001",
        "session_id": "session-history-001",
        "safe_statement": "Release manifests are generated from release.yaml.",
        "namespace": "project.release",
        "kind": "fact",
        "source_class": "tool_output",
        "status": "active",
        "trust_decision": "allowed",
        "policy_id": "default-policy",
        "policy_version": "1.0.0",
        "actual_action": "allow",
        "would_have_action": "allow",
        "committed_at": CREATED_AT,
        "expires_at": None,
        "shadow_admitted": False,
        "manual_approval_event_id": None,
        "risk_categories": ["benign_fact"],
        "semantic_provider": semantic_provider,
        "last_event_id": "event-latest-history-001",
        "last_event_sequence": 12,
    }


def _load_json_schema(name: str) -> dict[str, Any]:
    value = json.loads((CONTRACTS / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_provider_state_adds_subscription_without_renaming_historical_values() -> None:
    assert ProviderState.LIVE_CODEX_SUBSCRIPTION.value == "live_codex_subscription"
    assert {"live_openai", "recorded_fixture", "failed"} <= {item.value for item in ProviderState}


def test_provider_summary_adds_subscription_without_renaming_historical_values() -> None:
    assert ProviderSummaryState.LIVE_CODEX_SUBSCRIPTION.value == "live_codex_subscription"
    assert {
        "live_openai",
        "recorded_fixture",
        "deterministic_only",
        "failed",
        "not_required",
    } <= {item.value for item in ProviderSummaryState}


def test_provider_isolation_mapping_matches_the_documented_boundary() -> None:
    expected = {
        "live_openai": "tool_free_api",
        "live_codex_subscription": "agentic_sandboxed",
        "recorded_fixture": "recorded_fixture",
        "deterministic_only": "local_deterministic",
        "not_required": "local_deterministic",
        "failed": "failed",
        "unknown_provider": "failed",
    }

    assert {provider: provider_isolation_for(provider).value for provider in expected} == expected


def test_candidate_extractor_accepts_the_additive_subscription_value() -> None:
    candidate = MemoryCandidate.model_validate(
        _candidate_payload(extractor_provider="live_codex_subscription")
    )

    assert candidate.extractor_provider == "live_codex_subscription"


def test_feature_001_json_schemas_accept_subscription_provider_payloads() -> None:
    candidate_schema = _load_json_schema("memory-candidate.schema.json")
    assessment_schema = _load_json_schema("semantic-assessment.schema.json")

    Draft202012Validator(
        candidate_schema,
        format_checker=FormatChecker(),
    ).validate(_candidate_payload(extractor_provider="live_codex_subscription"))
    Draft202012Validator(
        assessment_schema,
        format_checker=FormatChecker(),
    ).validate(_assessment_payload(provider_state="live_codex_subscription"))


def test_current_subscription_assessments_bind_requested_provider_on_success_and_failure() -> None:
    assessment_schema = _load_json_schema("semantic-assessment.schema.json")
    validator = Draft202012Validator(
        assessment_schema,
        format_checker=FormatChecker(),
    )
    successful = _assessment_payload(provider_state="live_codex_subscription")
    successful["requested_provider"] = "codex_subscription"
    successful["requested_model"] = "gpt-5.6-luna"
    validator.validate(successful)
    parsed_success = SemanticAssessment.model_validate(successful)
    assert parsed_success.requested_provider is RequestedProvider.CODEX_SUBSCRIPTION

    failed = {
        **successful,
        "provider_state": "failed",
        "risk_score": None,
        "categories": [],
        "persistence_intent": "unknown",
        "authority_claim": "unknown",
        "exfiltration_risk": None,
        "tool_hijack_risk": None,
        "cross_task_risk": None,
        "secret_risk": None,
        "rationale": None,
        "recommended_disposition": None,
        "failure": {"class": "timeout", "retryable": True},
    }
    validator.validate(failed)
    parsed_failure = SemanticAssessment.model_validate(failed)
    assert parsed_failure.provider_state is ProviderState.FAILED
    assert parsed_failure.requested_provider is RequestedProvider.CODEX_SUBSCRIPTION
    assert parsed_failure.requested_model == "gpt-5.6-luna"


@pytest.mark.parametrize(
    ("provider_state", "requested_provider"),
    [
        ("recorded_fixture", "openai"),
        ("live_openai", "codex_subscription"),
        ("live_codex_subscription", "fixture"),
    ],
)
def test_successful_provider_identity_mismatches_fail_schema_and_pydantic_equally(
    provider_state: str,
    requested_provider: str,
) -> None:
    payload = _assessment_payload(provider_state=provider_state)
    payload["requested_provider"] = requested_provider
    validator = Draft202012Validator(
        _load_json_schema("semantic-assessment.schema.json"),
        format_checker=FormatChecker(),
    )

    schema_errors = list(validator.iter_errors(payload))

    assert any(list(error.path) == ["requested_provider"] for error in schema_errors)
    with pytest.raises(ValidationError, match="provider identity is inconsistent"):
        SemanticAssessment.model_validate(payload)


@pytest.mark.parametrize("requested_provider", list(RequestedProvider))
def test_failed_assessment_may_preserve_any_attempted_provider(
    requested_provider: RequestedProvider,
) -> None:
    payload = _assessment_payload(provider_state="live_codex_subscription")
    payload.update(
        {
            "provider_state": "failed",
            "requested_provider": requested_provider.value,
            "risk_score": None,
            "categories": [],
            "persistence_intent": "unknown",
            "authority_claim": "unknown",
            "exfiltration_risk": None,
            "tool_hijack_risk": None,
            "cross_task_risk": None,
            "secret_risk": None,
            "rationale": None,
            "recommended_disposition": None,
            "failure": {"class": "timeout", "retryable": True},
        }
    )
    validator = Draft202012Validator(
        _load_json_schema("semantic-assessment.schema.json"),
        format_checker=FormatChecker(),
    )

    validator.validate(payload)
    parsed = SemanticAssessment.model_validate(payload)

    assert parsed.provider_state is ProviderState.FAILED
    assert parsed.requested_provider is requested_provider


def test_subscription_assessment_schema_rejects_remote_model_assertion() -> None:
    assessment_schema = _load_json_schema("semantic-assessment.schema.json")
    validator = Draft202012Validator(
        assessment_schema,
        format_checker=FormatChecker(),
    )
    subscription = _assessment_payload(provider_state="live_codex_subscription")
    subscription["returned_model"] = "unattested-remote-model"

    errors = list(validator.iter_errors(subscription))

    assert any(list(error.path) == ["returned_model"] for error in errors)
    validator.validate(_assessment_payload(provider_state="live_openai"))


def test_semantic_failure_schema_matches_every_runtime_failure_class() -> None:
    assessment_schema = _load_json_schema("semantic-assessment.schema.json")
    failure_schema = assessment_schema["properties"]["failure"]["anyOf"][0]
    contract_values = set(failure_schema["properties"]["class"]["enum"])
    runtime_values = set(get_args(SemanticFailure.model_fields["class_name"].annotation))

    assert contract_values == runtime_values


def test_feature_001_openapi_accepts_subscription_provider_summary() -> None:
    contract_path = CONTRACTS / "verity-ipc.openapi.yaml"
    document = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    validate_openapi(document, base_uri=contract_path.resolve().as_uri())
    provider_schema = document["components"]["schemas"]["SemanticProviderState"]

    Draft202012Validator(provider_schema).validate("live_codex_subscription")


def test_feature_001_openapi_accepts_the_runtime_subscription_status() -> None:
    contract_path = CONTRACTS / "verity-ipc.openapi.yaml"
    document = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    status_schema = dict(document["components"]["schemas"]["StatusResponse"])
    status_schema["components"] = document["components"]
    payload = {
        "schema_version": "1.0.0",
        "daemon": "healthy",
        "mode": "enforce",
        "policy": {
            "policy_id": "default-policy",
            "version": "1.0.0",
            "mode": "enforce",
            "digest": SHA256,
            "validation_state": "valid",
        },
        "ledger": "verified",
        "memory_view": "consistent",
        "semantic_provider": "live_codex_subscription",
        "semantic_provider_isolation": "agentic_sandboxed",
        "semantic_provider_ready": False,
        "semantic_provider_failure_class": "unsupported_auth",
        "counts": {
            "total_candidates": 0,
            "allowed": 0,
            "redacted": 0,
            "quarantined": 0,
            "blocked": 0,
            "revoked": 0,
            "pending_evidence": 0,
            "failed_evidence": 0,
        },
    }

    Draft202012Validator(status_schema).validate(payload)


def test_historical_live_provider_payloads_round_trip_without_mutation() -> None:
    candidate_payload = _candidate_payload(extractor_provider="live_openai")
    assessment_payload = _assessment_payload(provider_state="live_openai")
    memory_payload = _memory_payload(semantic_provider="live_openai")

    assert MemoryCandidate.model_validate(candidate_payload).model_dump(mode="json") == (
        candidate_payload
    )
    assessment = SemanticAssessment.model_validate(assessment_payload)
    assert assessment.requested_provider is None
    assert "requested_provider" not in assessment.model_fields_set
    assert assessment.model_dump(mode="json", exclude={"requested_provider"}) == assessment_payload
    assert MemoryRecord.model_validate(memory_payload).model_dump(mode="json") == memory_payload


def test_historical_fixture_payloads_round_trip_without_mutation() -> None:
    candidate_payload = _candidate_payload(extractor_provider="recorded_fixture")
    assessment_payload = _assessment_payload(provider_state="recorded_fixture")
    memory_payload = _memory_payload(semantic_provider="recorded_fixture")

    assert MemoryCandidate.model_validate(candidate_payload).model_dump(mode="json") == (
        candidate_payload
    )
    assessment = SemanticAssessment.model_validate(assessment_payload)
    assert assessment.requested_provider is None
    assert "requested_provider" not in assessment.model_fields_set
    assert assessment.model_dump(mode="json", exclude={"requested_provider"}) == assessment_payload
    assert MemoryRecord.model_validate(memory_payload).model_dump(mode="json") == memory_payload
