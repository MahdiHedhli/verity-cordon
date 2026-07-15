"""VC-POLICY-1 deterministic policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from pydantic import ValidationError

from verity_cordon.core.models import (
    SEVERITY_ORDER,
    Action,
    DetectorResult,
    DetectorStatus,
    MemoryCandidate,
    MemoryKind,
    Mode,
    PolicyDecision,
    ProviderState,
    SemanticAssessment,
    SourceClass,
    format_utc,
    new_id,
)
from verity_cordon.policies.models import PolicyDocument, PolicyRule, RuleMatch


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    decision: PolicyDecision
    ttl_seconds: int | None
    manual_review_required: bool


def _namespace_matches(namespace: str, pattern: str) -> bool:
    return fnmatchcase(namespace, pattern)


def _successful_semantic(assessment: SemanticAssessment | None) -> bool:
    return bool(
        assessment is not None
        and assessment.provider_state != ProviderState.FAILED
        and assessment.failure is None
        and assessment.risk_score is not None
    )


def _positive_findings(results: list[DetectorResult]) -> list[DetectorResult]:
    return [
        result
        for result in results
        if result.status == DetectorStatus.OK and result.matched is True
    ]


def _is_high_risk(candidate: MemoryCandidate) -> bool:
    return bool(
        candidate.kind
        in {
            MemoryKind.OPERATIONAL_INSTRUCTION,
            MemoryKind.POLICY_STATEMENT,
            MemoryKind.CREDENTIAL_MATERIAL,
            MemoryKind.UNKNOWN,
        }
        or candidate.namespace.split(".", 1)[0] in {"instructions", "policies", "credentials"}
        or (
            candidate.source_class
            in {SourceClass.TOOL_OUTPUT, SourceClass.AGENT_OUTPUT, SourceClass.PRIOR_MEMORY}
            and candidate.persistence_requested
        )
    )


class PolicyEngine:
    def __init__(self, policy: PolicyDocument) -> None:
        self.policy = policy

    def _hard_guard(
        self, candidate: MemoryCandidate, findings: list[DetectorResult]
    ) -> tuple[Action, str] | None:
        categories = {
            category for finding in _positive_findings(findings) for category in finding.categories
        }
        if "structural_invalidity" in categories:
            return Action.BLOCK, "hard_guard.structural_invalidity"
        if (
            candidate.kind == MemoryKind.CREDENTIAL_MATERIAL
            or candidate.sensitivity.value == "credential"
            or "credential_material" in categories
        ):
            return Action.BLOCK, "hard_guard.credential_material"
        if any(
            _namespace_matches(candidate.namespace, pattern)
            for pattern in self.policy.protected_namespaces
        ):
            return Action.BLOCK, "hard_guard.protected_namespace"
        return None

    def _failure_action(
        self,
        candidate: MemoryCandidate,
        findings: list[DetectorResult],
        semantic: SemanticAssessment | None,
    ) -> tuple[Action, str] | None:
        high_risk = _is_high_risk(candidate)
        if any(result.status != DetectorStatus.OK for result in findings):
            if high_risk:
                return (
                    self.policy.failure_behavior.detector_failure_high_risk,
                    "failure.detector.high_risk",
                )
            return (
                self.policy.failure_behavior.detector_failure_lower_risk,
                "failure.detector.lower_risk",
            )
        if semantic is None or semantic.failure is None:
            return None
        failure_class = semantic.failure.class_name
        if failure_class == "timeout":
            if high_risk:
                return (
                    self.policy.failure_behavior.semantic_timeout_high_risk,
                    "failure.semantic_timeout.high_risk",
                )
            return (
                self.policy.failure_behavior.semantic_timeout_lower_risk,
                "failure.semantic_timeout.lower_risk",
            )
        if high_risk:
            return (
                self.policy.failure_behavior.semantic_invalid_high_risk,
                "failure.semantic_invalid.high_risk",
            )
        return (
            self.policy.failure_behavior.semantic_invalid_lower_risk,
            "failure.semantic_invalid.lower_risk",
        )

    def _matches(
        self,
        match: RuleMatch,
        candidate: MemoryCandidate,
        findings: list[DetectorResult],
        semantic: SemanticAssessment | None,
    ) -> bool:
        positive = _positive_findings(findings)
        detector_categories = {category for result in positive for category in result.categories}
        successful_semantic = _successful_semantic(semantic)

        if match.source_classes is not None and candidate.source_class not in match.source_classes:
            return False
        if match.namespace_patterns is not None and not any(
            _namespace_matches(candidate.namespace, pattern) for pattern in match.namespace_patterns
        ):
            return False
        if match.memory_kinds is not None and candidate.kind not in match.memory_kinds:
            return False
        if match.sensitivities is not None and candidate.sensitivity not in match.sensitivities:
            return False
        if match.detector_categories_any is not None and not detector_categories.intersection(
            match.detector_categories_any
        ):
            return False
        if match.minimum_detector_severity is not None:
            threshold = SEVERITY_ORDER[match.minimum_detector_severity]
            highest = max((SEVERITY_ORDER[result.severity] for result in positive), default=-1)
            if highest < threshold:
                return False
        if match.semantic_categories_any is not None:
            if not successful_semantic or semantic is None:
                return False
            if not set(semantic.categories).intersection(match.semantic_categories_any):
                return False
        if match.minimum_semantic_risk is not None:
            if not successful_semantic or semantic is None or semantic.risk_score is None:
                return False
            if semantic.risk_score < match.minimum_semantic_risk:
                return False
        if (
            match.persistence_requested is not None
            and candidate.persistence_requested != match.persistence_requested
        ):
            return False
        if match.semantic_required is True and not successful_semantic:
            return False
        return True

    def _document_rule(
        self,
        candidate: MemoryCandidate,
        findings: list[DetectorResult],
        semantic: SemanticAssessment | None,
    ) -> PolicyRule | None:
        for rule in sorted(self.policy.rules, key=lambda item: (item.priority, item.rule_id)):
            if self._matches(rule.match, candidate, findings, semantic):
                return rule
        return None

    def evaluate(
        self,
        candidate: MemoryCandidate,
        detector_results: list[DetectorResult],
        semantic_assessment: SemanticAssessment | None,
    ) -> PolicyEvaluation:
        hard_guard = self._hard_guard(candidate, detector_results)
        failure = self._failure_action(candidate, detector_results, semantic_assessment)
        rule: PolicyRule | None = None
        reason_codes: list[str]

        if hard_guard is not None:
            would_have_action, reason = hard_guard
            reason_codes = [reason]
        elif failure is not None:
            would_have_action, reason = failure
            reason_codes = [reason]
        else:
            rule = self._document_rule(candidate, detector_results, semantic_assessment)
            if rule is None:
                would_have_action = self.policy.default_action
                reason_codes = ["policy.default"]
            else:
                would_have_action = rule.action
                reason_codes = [f"policy.rule.{rule.rule_id}"]
                if rule.manual_review_required:
                    reason_codes.append("policy.manual_review_required")
                    if would_have_action in {Action.ALLOW, Action.REDACT}:
                        would_have_action = Action.QUARANTINE

        shadow_mode = self.policy.mode == Mode.SHADOW
        actual_action = self.policy.shadow_action if shadow_mode else would_have_action
        ordered_results = sorted(
            detector_results,
            key=lambda result: (
                result.detector_id,
                result.detector_version,
                result.result_id,
            ),
        )
        decision = PolicyDecision(
            decision_id=new_id(),
            candidate_id=candidate.candidate_id,
            policy_id=self.policy.policy_id,
            policy_version=self.policy.version,
            policy_digest=self.policy.content_digest,
            matched_rule_id=rule.rule_id if rule is not None else None,
            mode=self.policy.mode,
            actual_action=actual_action,
            would_have_action=would_have_action,
            shadow_mode=shadow_mode,
            reason_codes=reason_codes,
            detector_result_ids=[result.result_id for result in ordered_results],
            semantic_assessment_id=(
                semantic_assessment.assessment_id if semantic_assessment is not None else None
            ),
            decided_at=format_utc(),
        )
        return PolicyEvaluation(
            decision=decision,
            ttl_seconds=(
                rule.ttl_seconds if rule is not None else self.policy.limits.default_ttl_seconds
            ),
            manual_review_required=bool(rule and rule.manual_review_required),
        )


class LastKnownGoodPolicyProvider:
    """In-memory LKG boundary used by the daemon; persistence is layered later."""

    def __init__(self, initial: PolicyDocument | None = None) -> None:
        self._active = initial
        self.last_rejection_class: str | None = None

    def get_active_sync(self) -> PolicyDocument:
        if self._active is None:
            raise RuntimeError("No valid local policy is active")
        return self._active

    async def get_active(self) -> PolicyDocument:
        return self.get_active_sync()

    def activate_sync(self, raw_policy: dict[str, Any]) -> PolicyDocument:
        try:
            proposed = PolicyDocument.model_validate(raw_policy)
        except ValidationError:
            self.last_rejection_class = "ValidationError"
            raise
        self._active = proposed
        self.last_rejection_class = None
        return proposed

    async def activate(self, raw_policy: dict[str, Any]) -> PolicyDocument:
        return self.activate_sync(raw_policy)
