# Security Requirements Checklist: Codex Desktop Subscription Defense

**Purpose**: Validate that feature-002 security requirements are complete,
clear, consistent, measurable, and bounded before implementation
**Created**: 2026-07-15
**Feature**: [spec.md](../spec.md)

> Checked items mean the requirement is adequately written. They do not mean
> the corresponding implementation or security test has passed.

## Trust Boundaries and Authority

- [x] CHK001 Is every Desktop prompt, MCP result, child response, historical memory, and imported benchmark artifact explicitly untrusted until adjudicated? [Completeness, Spec FR-002/FR-007 and SFR-001]
- [x] CHK002 Is deterministic versioned policy the sole final trust authority for fixture, direct API, and subscription semantic paths? [Consistency, Spec FR-017]
- [x] CHK003 Is the subscription provider distinguished from the direct tool-free API provider without weakening either provider's prior contract? [Clarity, Spec FR-010/FR-024 and SFR-003]
- [x] CHK004 Are provider identity, isolation class, model, prompt/schema version, timing, and failure class required as attributable decision metadata? [Completeness, Spec Key Entities]
- [x] CHK005 Is a signed terminal decision required before a later Desktop task can be described as protected? [Measurability, Spec FR-019 and SC-005]

## Credential and Content Safety

- [x] CHK006 Is local secret screening ordered before every subscription or direct API request? [Clarity, Spec SFR-004]
- [x] CHK007 Are credential-file reads, bearer-token capture, authentication-output persistence, and credential logging explicitly prohibited? [Coverage, Spec FR-012]
- [x] CHK008 Are process arguments, child output, temporary files, logs, telemetry, UI, screenshots, and Git all covered by the raw-content exclusion requirement? [Coverage, Spec SFR-004 and SC-008]
- [x] CHK009 Are the fixture and sink restricted to fixed synthetic values without environment, filesystem, personal-data, email, credential, or external-service access? [Completeness, Spec FR-004/FR-005 and SFR-007]
- [x] CHK010 Is sink rejection behavior specified for unexpected fields, non-synthetic values, and attempted host-data access? [Edge Case, Spec Edge Cases and SFR-007]

## Child Process and Failure Handling

- [x] CHK011 Are executable trust, fixed argument vectors, no-shell launch, private working state, restrictive modes, and descendant cleanup all required? [Completeness, Spec SFR-005]
- [x] CHK012 Are missing CLI, unsupported authentication, exhausted usage, nonzero exit, timeout, cancellation, malformed output, oversized output, refusal, and observed tool activity assigned explicit safe outcomes? [Coverage, Spec SFR-002]
- [x] CHK013 Is any observed semantic-child tool activity required to invalidate the entire assessment rather than only the affected event? [Clarity, Spec FR-014]
- [x] CHK014 Is the residual risk clear that rejecting observed tool activity does not prove or retroactively create a tool-free runtime? [Residual Risk, Spec SFR-003]
- [x] CHK015 Is recursion prevention required at both the provider launch and hook-adapter boundaries? [Defense in Depth, Spec FR-015 and SFR-006]
- [x] CHK016 Is silent provider substitution prohibited for every authentication, availability, capacity, and validation failure? [Consistency, Spec FR-009 and US2 Scenario 2]
- [x] CHK017 Is high-risk semantic failure tied to an explicit finding and quarantine behavior under a versioned policy? [Measurability, Spec FR-016 and SC-004]

## Integrity, Replay, and Recovery

- [x] CHK018 Is the new provider label required to remain additive and replay-compatible with existing signed events and materialized views? [Compatibility, Spec SFR-008]
- [x] CHK019 Are interrupted demo setup, unreadable receipts, configuration drift, staged-artifact drift, and partial state assigned refusal rather than guessed recovery? [Recovery, Spec Edge Cases and FR-020/FR-021]
- [x] CHK020 Are ledger, policy, daemon, and stale-view failures required to suppress both memory commit and injection? [Exception Flow, Spec US1 Scenario 4 and SFR-002]
- [x] CHK021 Is selective revocation defined to preserve unrelated memory and append-only history? [Consistency, Spec FR-023 and SC-006]
- [x] CHK022 Are benign, malicious, false-positive, dependency-failure, cross-session, recursion, privacy, and tamper cases required for the security stories? [Coverage, Spec SFR-009]

## Claims and Research Boundaries

- [x] CHK023 Is the demo explicitly described as an original Trojan Hippo-inspired scenario rather than a benchmark reproduction? [Clarity, Spec FR-003/FR-025]
- [x] CHK024 Are paper-reported attack rates and persistence results prohibited from being presented as Verity evaluation results? [Claims, Spec FR-026]
- [x] CHK025 Is the distinction between write-time memory defense and unimplemented outbound information-flow control documented? [Scope, Research Trojan Hippo Benchmark Inspection]
- [x] CHK026 Are Desktop-only observations required to remain manual smoke evidence rather than inferred automated proof? [Integrity, Spec SC-010]

## Notes

- Review completed against `spec.md`, `plan.md`, and `research.md` on
  2026-07-15. Implementation evidence is tracked in `tasks.md` and test output.
