<!--
Sync Impact Report
- Version change: 1.0.0 -> 1.1.0
- Modified principles: none
- Modified sections: Security and Delivery Constraints (active sprint promotion and
  subscription-provider isolation requirements)
- Added sections: none
- Removed sections: none; template placeholders were resolved
- Templates verified without changes:
  - ✅ .specify/templates/plan-template.md
  - ✅ .specify/templates/spec-template.md
  - ✅ .specify/templates/tasks-template.md
- Runtime guidance requiring feature-level propagation:
  - ✅ specs/002-codex-desktop-subscription-defense/ (specified, planned, and
    analyzed before implementation)
  - ✅ README.md and docs/security/ (implemented and verified)
- Follow-up TODOs: complete the operator-observed Desktop rehearsal and external
  submission actions; no repository-controlled implementation TODO remains
-->
# Verity Cordon Constitution

## Core Principles

### I. Memory Is Untrusted Until Adjudicated

No user prompt, tool output, imported file, model-generated statement, external
event, previous memory, or agent-authored summary may become durable trusted
context merely because it was observed or generated. Every proposed durable
memory MUST pass through the Verity Cordon lifecycle. Prior existence MUST NOT
increase a memory's authority.

### II. Provenance Before Persistence

Every committed memory MUST identify its originating evidence, source class,
session or task, candidate extractor version, detector versions, semantic
adjudicator version when used, policy version, final decision, event sequence,
and commitment time. A memory without sufficient provenance MUST be
quarantined or rejected.

### III. Append-Only History and Revocable Trust

Security history MUST NOT be destructively rewritten. Corrections MUST be new
events, including revocation, supersession, expiration, redaction,
reclassification, and policy migration. A revoked memory MUST disappear from
the active view while remaining represented in audit history according to the
retention policy.

### IV. Deterministic Policy Has Final Authority

Semantic models MAY extract candidates, assess intent, classify ambiguity,
identify suspicious persistence requests, recommend risk categories, and
produce structured evidence. A semantic model MUST NOT independently grant
durable trust. A deterministic, versioned policy engine MUST make the final
action decision.

### V. Failures Must Be Explicit

Every integration MUST define fail-open, fail-closed, timeout, detector-failure,
semantic-failure, ledger-unavailability, ledger-corruption,
policy-validation-failure, and Codex-hook-failure behavior. Silent bypass is
prohibited. A Verity Cordon failure MUST NOT cause unverified memory to be
injected.

### VI. Security Telemetry Must Not Become a New Leak

Logs, traces, metrics, audit summaries, and UI list views MUST exclude raw
secrets and sensitive memory content by default. Telemetry SHOULD use IDs,
digests, detector names, policy versions, source classes, actions, latency, and
error classes. Raw-content logging requires an explicit development-only opt-in
and MUST be visibly marked unsafe.

### VII. Claims Must Match Demonstrated Capabilities

Documentation and UI claims MUST distinguish provenance from truth, integrity
from confidentiality, detection from prevention, tamper evidence from tamper
prevention, policy trust from factual correctness, and demonstrated Codex
integration from theoretical portability. Every security claim MUST be backed
by a runnable test or clearly labeled as a design goal or limitation.

### VIII. Codex-First, Interface-Oriented

The hackathon product MUST be built for Codex using documented integration
surfaces. Internal abstractions MAY anticipate other agents, but another agent
integration MUST NOT enter active scope without a numbered scope amendment and
confirmation that the demo-critical path remains protected.

### IX. Test the Attack, Not Only the Happy Path

Every security-sensitive user story MUST include a benign case, malicious case,
false-positive case, failure-mode case, cross-session case when applicable, and
tampering case when applicable. Passing happy-path tests alone MUST NOT support
a protection claim.

### X. Hackathon Scope Is a Hard Boundary

Deferred capabilities MUST NOT silently enter the active implementation task
graph. Promotion requires a numbered Spec Kit feature, prioritized user stories,
independent acceptance criteria, a constitution-compliant plan, a generated
task graph, an explicit milestone, and confirmation that the current demo path
remains protected.

### XI. Uncommitted Streams Are Not Memory

Streaming content MUST remain uncommitted and invisible to readers until the
complete write passes final evaluation. Incremental scanning MAY terminate an
unsafe stream early, but final commit MUST evaluate the complete canonical
buffer. Blocked, aborted, or cancelled streams MUST NOT partially commit.

### XII. Cryptographic Evidence Must Be Verifiable

A cryptographic claim MUST define a canonical representation, digest algorithm,
signature algorithm, key identifier, verification procedure, and tests for
tampering, reordering, omission, and invalid signatures. Decorative hashes that
cannot be independently verified MUST NOT be used as security evidence.

## Security and Delivery Constraints

- The implemented security baseline is `001-codex-memory-firewall`. The only
  active implementation sprint is `002-codex-desktop-subscription-defense`.
  Feature 002 MAY extend the baseline but MUST NOT weaken or silently replace
  its tested controls, contracts, or claims.
- Only one incomplete implementation feature MAY be active at a time. A later
  feature MUST receive an explicit scope decision and MUST protect the current
  demo-critical path before becoming active.
- The product MUST use supported Codex configuration, hooks, skills, plugins, or
  other documented interfaces; undocumented Codex internals MUST NOT be patched.
- Subscription-backed Codex execution MUST be identified separately from a
  direct, tool-free OpenAI API semantic call. Until a documented control can
  remove built-in agent tools, subscription-backed semantic review MUST remain
  opt-in, isolated, fail closed on tool activity or malformed output, and MUST
  NOT inherit the stronger `no tools` claim.
- Secrets MUST be screened before model-bound content leaves the local trust
  boundary and MUST NOT appear in telemetry, fixtures, screenshots, or Git.
- Historical ledger events are authoritative; materialized views MUST be
  deterministic and rebuildable.
- The local Control Room MUST bind to loopback by default and MUST NOT expose raw
  secret material.
- Offline judge mode MUST exercise the real policy, ledger, materialization, and
  UI paths without an API key. Live mode MUST be explicit and fail safely.
- Donor-derived code, if any, MUST retain its license and provenance. Clean-room
  implementations are preferred when they are clearer and independently
  attributable.
- Approved claims and prohibited claims in the active feature specification are
  release gates, not marketing suggestions.

## Development Workflow and Quality Gates

1. Current primary sources MUST be recorded before architecture decisions that
   depend on Codex, GPT-5.6, Spec Kit, Build Week rules, or donor behavior.
2. Constitution, specification, clarification, research, plan, contracts,
   checklists, tasks, and consistency analysis MUST precede substantive
   implementation.
3. Security-critical tests MUST be written early enough to falsify claims and
   MUST cover failure and adversarial paths.
4. Each implementation phase MUST preserve a runnable vertical slice and update
   `tasks.md` truthfully.
5. Formatting, linting, type checks, unit, contract, integration, adversarial,
   end-to-end, frontend build, and browser smoke checks MUST pass before final
   handoff, or failures MUST be reported precisely.
6. Final convergence and consistency analysis MUST find no unresolved critical
   or high-severity gap before release.
7. Repository publication and submission actions MUST preserve credential
   safety and report the exact remote, branch, commit, and verification state.

## Feature 002 Consistency Sync *(Non-Normative)*

The 2026-07-15 Spec Kit analysis selected only
`002-codex-desktop-subscription-defense` and compared its four user stories,
requirements, measurable outcomes, plan, data model, contracts, checklists,
task graph, implementation, tests, and public claims against Constitution
v1.1.0. The final read-only pass mapped all 46 requirements and all 15
acceptance scenarios to 66 unique tasks with 100% traceability. All 93 feature
checklist items are complete; no deferred `VC-FUT-*` capability entered the
active task graph; and no unresolved ambiguity, duplication, constitution
violation, unmapped task, or high-severity inconsistency remained after
convergence. Convergence appended no task. The still-open timed,
operator-observed Desktop rehearsal (T056) is an acceptance-evidence gate, not
an exception to a constitutional MUST; remote review and public-main release
closure remain tracked by T066. This report changes no normative principle and
therefore does not amend the constitution version.

## Governance

This constitution supersedes informal project practices. Amendments require a
documented rationale, an explicit semantic-version change, an impact report,
and propagation to affected specifications, templates, plans, contracts,
checklists, tasks, tests, and runtime guidance. Major versions remove or
redefine governance guarantees, minor versions add or materially expand them,
and patch versions clarify wording without changing obligations.

Every feature plan and review MUST evaluate compliance. A MUST violation blocks
implementation or release unless the constitution is separately amended; it
cannot be waived inside a feature plan. Complexity and scope exceptions MUST be
recorded in the feature plan with the simpler alternative and why it cannot meet
the active acceptance criteria.

**Version**: 1.1.0 | **Ratified**: 2026-07-15 | **Last Amended**: 2026-07-15
