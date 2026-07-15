# Subscription Provider Requirements Checklist: Codex Desktop Subscription Defense

**Purpose**: Validate the precision and completeness of the opt-in Codex
subscription semantic-provider requirements
**Created**: 2026-07-15
**Feature**: [spec.md](../spec.md)

> This is a requirements-quality checklist, not a subprocess test procedure.

## Provider Selection and Identity

- [x] CHK001 Is `codex_subscription` defined as an explicit configuration choice rather than an automatic preference or fallback? [Clarity, Spec FR-008/FR-009]
- [x] CHK002 Is `live_codex_subscription` required across ledger payloads, replay, API, CLI, evaluations, filters, and UI? [Completeness, Spec FR-010]
- [x] CHK003 Is the derived `agentic_sandboxed` isolation class distinguished from `tool_free_api`, recorded fixture, local deterministic, and failed states? [Clarity, Plan Provider identity and replay compatibility]
- [x] CHK004 Are requested and actual provider identities required to remain attributable when an assessment fails? [Coverage, Spec Key Entities]
- [x] CHK005 Is direct API behavior explicitly preserved rather than redefined through subscription mode? [Compatibility, Spec FR-024]

## Authentication Boundary

- [x] CHK006 Is supported status inspection the only allowed authentication-readiness surface? [Clarity, Spec FR-012]
- [x] CHK007 Is a successful ChatGPT sign-in required while API-key, absent, ambiguous, or credential-bearing status is rejected? [Coverage, Spec Edge Cases and Plan Subscription provider boundary]
- [x] CHK008 Is subscription availability explicitly subject to plan, workspace policy, model access, and usage limits? [Assumption, Spec Assumptions]
- [x] CHK009 Is it clear that subscription authentication is not a reusable OpenAI API credential? [Clarity, Spec Assumptions]
- [x] CHK010 Are readiness status and failure outputs constrained to content-safe booleans or classes without auth detail? [Privacy, Spec FR-018 and SFR-004]

## Invocation Isolation

- [x] CHK011 Are ephemeral execution, ignored user configuration and rules, private empty cwd, read-only sandboxing, disabled web search, hooks, and memories, and minimal environment all mandatory? [Completeness, Spec FR-011]
- [x] CHK012 Is sanitized evidence required on stdin rather than in command arguments or persistent prompt files? [Clarity, Spec SFR-005 and Plan Subscription provider boundary]
- [x] CHK013 Is the executable required to resolve to a trusted, stable absolute path before status or semantic execution? [Integrity, Spec SFR-005]
- [x] CHK014 Are strict deadlines, bounded stdout/stderr/JSONL/final output, restrictive temporary modes, and process-group cleanup quantified by the provider contract? [Measurability, Plan Subscription provider boundary]
- [x] CHK015 Is the child environment requirement compatible with supported authentication while excluding API-key and broad parent-environment inheritance? [Consistency, Spec FR-011/FR-012]
- [x] CHK016 Is the defense-in-depth child marker prohibited from becoming the only isolation or recursion control? [Clarity, Plan Subscription provider boundary]

## Output Validity and Tool Activity

- [x] CHK017 Are duplicate keys, non-finite values, malformed records, unrecognized oversize records, identity mismatch, digest mismatch, and schema mismatch all invalid outcomes? [Coverage, Spec Edge Cases and FR-013]
- [x] CHK018 Is second-pass local sanitization required before model-originated content can enter signed events or operator surfaces? [Defense in Depth, Spec FR-013 and SFR-004]
- [x] CHK019 Are command, shell, filesystem, web, MCP, and other tool events treated uniformly as whole-assessment failures? [Clarity, Spec FR-014]
- [x] CHK020 Is it explicit that post-hoc event rejection cannot undo a read that the child runtime already performed? [Residual Risk, Spec SFR-003]
- [x] CHK021 Are valid structured outputs bound to the originating evidence/candidate identity, content digest, schema version, prompt version, and provider state? [Integrity, Spec FR-013 and Key Entities]

## Failure and Measurability

- [x] CHK022 Are every absence, auth, capacity, timeout, cancellation, refusal, invalid-output, tool-event, termination, and cleanup failure distinguishable without exposing content? [Completeness, Spec SFR-002]
- [x] CHK023 Can the no-fallback requirement be objectively demonstrated for every provider failure class? [Acceptance Criteria, Spec US2 Scenario 2]
- [x] CHK024 Can a subscription-backed result be objectively distinguished from a fixture-backed or direct API result in every operator surface? [Acceptance Criteria, Spec US2 Scenario 3 and SC-003]
- [x] CHK025 Is the live test requirement scoped to sanitized synthetic evidence and explicitly separated from deterministic CI? [Safety, Quickstart Evidence to record]
- [x] CHK026 Are model and CLI version drift recorded as compatibility evidence rather than hidden behind a generic availability error? [Dependency, Research Codex Authentication and Subscription Use]

## Notes

- Review completed on 2026-07-15. Current exact CLI syntax is pinned in the
  provider contract and must remain covered by contract tests.
