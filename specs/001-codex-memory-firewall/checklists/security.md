# Security Requirements Checklist: Codex Memory Firewall

**Purpose**: Validate that security requirements are complete, clear,
consistent, measurable, and traceable before implementation

**Created**: 2026-07-15

**Audience**: Security reviewer at the pre-implementation gate

> Checked items mean the requirement is adequately written, not that the
> implementation has passed its security tests.

## Trust and Data Flow

- [x] CHK001 Are all inputs that may propose durable memory explicitly treated as untrusted? [Completeness, Spec FR-001]
- [x] CHK002 Are provenance requirements defined for source, session, task, evidence, extractor, detector, semantic, policy, and event history? [Completeness, Spec FR-002]
- [x] CHK003 Is the distinction between provenance, integrity, policy trust, and factual truth explicit? [Clarity, Spec CR-001/CR-002]
- [x] CHK004 Are raw secret handling and model-bound sanitization requirements explicit and ordered before semantic calls? [Coverage, Spec FR-004]
- [x] CHK005 Are routine UI, log, trace, metric, and screenshot content restrictions documented? [Coverage, Spec SFR-005/SFR-009]

## Policy and Semantic Authority

- [x] CHK006 Is deterministic policy identified as the sole final action authority in every mode? [Consistency, Spec FR-005/FR-006]
- [x] CHK007 Are shadow actual and would-have actions unambiguously distinguished? [Clarity, Spec FR-007]
- [x] CHK008 Are detector and semantic timeout, exception, refusal, and invalid-output fallbacks defined? [Exception Flow, Spec SFR-001/SFR-003]
- [x] CHK009 Are protected namespaces, credential material, and operational instructions assigned stronger trust requirements? [Coverage, Spec FR-003/FR-006]
- [x] CHK010 Is malformed-policy behavior consistent with last-known-good and fail-closed requirements? [Consistency, Spec FR-020/SFR-004]

## Ledger and Cryptography

- [x] CHK011 Are canonical representation, digest, signature, key ID, and verification requirements defined without an unsupported standards claim? [Clarity, Spec FR-009/SFR-006]
- [x] CHK012 Are payload alteration, event alteration, reordering, omission, invalid signature, and view drift all covered? [Scenario Coverage, Spec SC-004]
- [x] CHK013 Is ledger corruption behavior defined for commits, injection, audit access, and operator status? [Exception Flow, Spec SFR-002]
- [x] CHK014 Are revocation and reconstruction explicitly append-only and non-destructive? [Consistency, Spec FR-008/FR-012]
- [x] CHK015 Is the compromised-host and signing-key boundary explicit? [Assumption, Spec SFR-010]

## Codex and Local Service Boundary

- [x] CHK016 Is the supported Codex integration bounded to documented config and hook surfaces? [Clarity, Spec FR-018/FR-019]
- [x] CHK017 Are unavailable-daemon and hook-failure behaviors defined to produce no memory injection? [Exception Flow, Spec SFR-001]
- [x] CHK018 Are loopback binding, Host/Origin checks, mutation confirmation, and local authorization requirements specified? [Coverage, Plan Trust and authorization]
- [x] CHK019 Is the limitation that post-tool capture cannot undo current-session side effects documented? [Residual Risk, Research Codex Lifecycle Hooks]
- [x] CHK020 Are plugin failure isolation and duplicate detector ID behavior specified? [Coverage, Spec FR-026]

## Adversarial Coverage and Claims

- [x] CHK021 Are benign, malicious, false-positive, failure, cross-session, stream-split, and tamper scenarios represented? [Coverage, Spec User Stories/Edge Cases]
- [x] CHK022 Are public allowed and prohibited claims written as release requirements? [Traceability, Spec CR-001/CR-002]
- [x] CHK023 Are the synthetic fixture's no-environment-read and no-external-network properties explicit? [Coverage, Spec FR-024]
- [x] CHK024 Are residual risks required for every threat-model abuse case? [Completeness, Spec SFR-008]
