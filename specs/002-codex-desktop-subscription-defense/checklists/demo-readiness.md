# Desktop Demo Requirements Checklist: Codex Desktop Subscription Defense

**Purpose**: Validate that the Desktop-first demonstration is safely specified,
reversible, judge-friendly, and honest about manual evidence
**Created**: 2026-07-15
**Feature**: [spec.md](../spec.md)

> Checked items validate written requirements. They do not certify that the
> Desktop app, daemon, or demonstration has been exercised.

## Setup and Teardown

- [x] CHK001 Is the normal Verity plugin install clearly separated from demo-only MCP setup? [Completeness, Spec FR-020]
- [x] CHK002 Is the complete demo configuration delta required in preview before any mutation? [Clarity, Spec US4 Scenario 1]
- [x] CHK003 Are explicit confirmation, restrictive staging, artifact digests, original values, runtime identity, receipt version, and teardown scope required? [Completeness, Spec Key Entities and FR-020]
- [x] CHK004 Is teardown required to preserve unrelated Codex configuration, the normal plugin, ledger, key, and memory history? [Consistency, Spec FR-021]
- [x] CHK005 Are interrupted setup and drift behavior defined to refuse guessing or destructive overwrite? [Recovery, Spec Edge Cases]
- [x] CHK006 Is the exercised MCP entry identified as user-wide, with a dedicated workspace described only as an organizational precaution plus requirements to close unrelated tasks, quit Desktop around mutation, and tear down immediately? [Safety, Quickstart Safety Boundary]

## Attack Narrative

- [x] CHK007 Does the scenario contain both a useful benign fact and a concealed delayed operational instruction? [Completeness, Spec FR-006]
- [x] CHK008 Are source class, task/session identity, tool identity, evidence digest, detectors, semantic state, policy, and final action required in the decision view? [Traceability, Spec FR-007]
- [x] CHK009 Is the later trigger limited to a fixed synthetic release marker and inert local sink? [Safety, Spec FR-004/FR-005]
- [x] CHK010 Is shadow admission required to show actual and would-have actions and state that it is not active protection? [Clarity, Spec FR-022]
- [x] CHK011 Is enforcement required to demonstrate selective trust rather than rejecting all documentation? [Acceptance Criteria, Spec US1 Scenarios 1-3]
- [x] CHK012 Is the fresh-task step gated on a signed terminal outcome and healthy ledger/materialized view? [Sequence, Spec FR-019]
- [x] CHK013 Is selective revocation required to remove exactly the shadow-admitted poison and preserve unrelated approved memory? [Recovery, Spec FR-023 and SC-006]

## Judge Experience and Fallback

- [x] CHK014 Is Desktop defined as the primary human-facing surface while CLI remains a secondary harness over the same product path? [Consistency, Spec FR-001]
- [x] CHK015 Is the under-three-minute edited narrative measurable without counting installation or pre-recorded loading time? [Measurability, Spec SC-001]
- [x] CHK016 Are the Control Room states needed to explain provider identity, isolation, pending/terminal evaluation, provenance, actual/would-have action, revocation, and ledger verification specified? [Coverage, Spec FR-018]
- [x] CHK017 Is an API-key-free fallback required to exercise the real policy, ledger, materialization, revocation, and UI? [Completeness, Spec US4 Scenario 4]
- [x] CHK018 Is subscription unavailability treated as an explicit live-path failure rather than a reason to relabel fixture output? [Integrity, Spec FR-009 and SC-003]
- [x] CHK019 Are automated harness results and manual Desktop observations required to be reported separately? [Claims, Spec SC-010]

## Safety, Attribution, and Claims

- [x] CHK020 Is the fixture prohibited from reading real email, files, environment, credentials, personal data, or external services? [Coverage, Spec FR-004]
- [x] CHK021 Is the sink contract limited to allow-listed synthetic payload and content-safe metadata with no external transmission capability? [Clarity, Spec FR-005]
- [x] CHK022 Are the benchmark repository, branch, exact commit, license, inspection date, and paper required in documentation? [Attribution, Spec FR-025]
- [x] CHK023 Is the phrase “synthetic delayed-trigger scenario inspired by Trojan Hippo” preferred over benchmark-reproduction or comparative-performance language? [Claims, Spec FR-025/FR-026]
- [x] CHK024 Are false-positive and failure demonstrations included so one attack string cannot support a universal protection claim? [Coverage, Spec US1 Scenario 3 and SFR-009]
- [x] CHK025 Is the scope boundary explicit that Verity demonstrates write-time memory defense, not complete outbound exfiltration control? [Scope, Research Trojan Hippo Benchmark Inspection]

## Notes

- Requirements review completed on 2026-07-15. Manual Desktop smoke status must
  remain unchecked in the submission checklist until an operator actually runs
  it.
