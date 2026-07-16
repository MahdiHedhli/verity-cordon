# Tasks: Codex Desktop Subscription Defense

**Input**: Design documents from
`specs/002-codex-desktop-subscription-defense/`

**Prerequisites**: `spec.md`, `plan.md`, `research.md`, `data-model.md`,
`contracts/`, `quickstart.md`, and the feature checklists

**Tests**: Security-sensitive stories use test-first slices. A completed task
must preserve the implemented `001-codex-memory-firewall` baseline. The
operator-authorized workspace cleanup that removed unrelated duplicate
`* 2.*` files is recorded separately in the hackathon work log.

**Organization**: Tasks are grouped by user story so each story has a distinct
goal and independent acceptance path. Deferred outbound information-flow
control, benchmark reproduction, hosted service, and non-Codex adapters are not
active tasks.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel because it uses different files and has no
  dependency on an unfinished task in the same phase
- **[Story]**: Maps the task to a prioritized user story in `spec.md`
- Security tests precede the implementation they are intended to falsify

## Phase 1: Spec Kit and Sprint Setup

**Purpose**: Establish the feature source of truth and record researched
constraints before implementation.

- [x] T001 Amend the active-sprint and subscription-isolation governance in `.specify/memory/constitution.md` and select feature 002 in `.specify/feature.json`
- [x] T002 [P] Complete the specification, plan, research, data model, quickstart, contracts, ADRs, and requirements-quality checklists in `specs/002-codex-desktop-subscription-defense/` and `docs/decisions/0006-codex-subscription-provider.md` through `docs/decisions/0007-desktop-first-demo.md`
- [x] T003 Record the tracked-file-only baseline, run and remediate the pre-implementation Spec Kit consistency analysis, and document the clean-source test strategy in `docs/hackathon/HACKATHON_WORK.md` and `specs/002-codex-desktop-subscription-defense/`

---

## Phase 2: Foundational Compatibility and Isolation

**Purpose**: Add the replay-compatible provider vocabulary, shared structured
contracts, and recursion boundary required by every story.

**Critical gate**: No user-story implementation begins until old signed values
still parse/replay and the hook recursion marker is proven content-free.

- [x] T004 [P] Add failing additive-enum, old-event replay, OpenAPI, and JSON Schema compatibility tests in `tests/contract/test_subscription_provider_compatibility.py`
- [x] T005 [P] Add failing all-hook-event recursion short-circuit tests with zero daemon I/O in `tests/contract/test_codex_hooks.py`
- [x] T006 Refactor strict candidate/risk schemas and bounded model-output helpers into `src/verity_cordon/semantic/structured.py` while preserving direct API behavior in `src/verity_cordon/semantic/openai_provider.py`
- [x] T007 Extend provider, extractor, summary, and content-safe failure enums additively in `src/verity_cordon/core/models.py`
- [x] T008 Extend validated subscription settings without changing existing constructor behavior in `src/verity_cordon/core/config.py`
- [x] T009 Update the canonical contracts additively in `specs/001-codex-memory-firewall/contracts/semantic-assessment.schema.json`, `specs/001-codex-memory-firewall/contracts/memory-candidate.schema.json`, and `specs/001-codex-memory-firewall/contracts/verity-ipc.openapi.yaml`
- [x] T010 Implement the exact `VERITY_SEMANTIC_CHILD=1` early no-op response in `src/verity_cordon/codex/hooks.py`
- [x] T011 Run the foundational contract and existing direct-API semantic tests from tracked paths and record the commands in `specs/002-codex-desktop-subscription-defense/tasks.md`

**Phase 2 verification (2026-07-15)**:

- `uv run pytest -q tests/contract/test_subscription_provider_compatibility.py tests/contract/test_codex_hooks.py tests/integration/test_openai_semantic.py tests/unit/test_semantic.py` — 79 passed.
- `uv run ruff check src/verity_cordon/core/config.py src/verity_cordon/core/models.py src/verity_cordon/semantic src/verity_cordon/codex/hooks.py tests/contract/test_subscription_provider_compatibility.py tests/contract/test_codex_hooks.py` — passed.
- `uv run mypy src/verity_cordon/core/config.py src/verity_cordon/core/models.py src/verity_cordon/semantic src/verity_cordon/codex/hooks.py` — passed.

**Checkpoint**: Historical fixture/direct-API events verify and replay unchanged;
new provider values validate; semantic-child hooks cannot capture or inject.

---

## Phase 3: User Story 1 — Stop a Delayed Attack in Codex Desktop (Priority: P1) MVP

**Goal**: Prove selective enforcement of one useful fact plus one dormant,
untrusted operational instruction through the real evidence-to-injection path.

**Independent Test**: Feed the bounded poisoned-docs MCP result through the
real `PostToolUse` hook contract in enforce mode, await a signed terminal
decision, then render `SessionStart`; the useful approved fact is eligible and
the poisoned instruction is absent.

### Tests for User Story 1

- [x] T012 [P] [US1] Add failing two-tool fixture, exact synthetic sink allow-list, forbidden-import, size-bound, and no-side-effect tests in `examples/poisoned-docs-mcp/tests/test_server.py`
- [x] T013 [P] [US1] Add failing benign-quote, conditional-command, weak-signal fact, compaction-origin, and procedural-instruction evaluation cases in `tests/adversarial/test_delayed_poisoning.py`
- [x] T014 [US1] Add a failing hook-to-queue-to-policy-to-ledger-to-fresh-session matrix covering benign, malicious, false-positive, daemon/policy/ledger/view failure, cross-session, and ledger-tamper cases in `tests/end_to_end/test_desktop_memory_defense.py`

### Implementation for User Story 1

- [x] T015 [US1] Extend the clean-room stdio fixture with inert `demo_artifact_sink` behavior and exact marker validation in `examples/poisoned-docs-mcp/src/poisoned_docs_mcp/server.py`
- [x] T016 [P] [US1] Document the fixture's synthetic Trojan Hippo-inspired boundary and no-host-data properties in `examples/poisoned-docs-mcp/README.md`
- [x] T017 [US1] Add the delayed-trigger taxonomy and expected outcomes to `evals/datasets/memory-poisoning-fixtures-v1.json` and `evals/expected/semantic-fixtures.json`
- [x] T018 [US1] Expose pending versus signed-terminal evidence status needed by the Desktop checkpoint in `src/verity_cordon/daemon/app.py` and `src/verity_cordon/ledger/queries.py`
- [x] T019 [US1] Make the complete US1 security matrix pass and verify fail-closed injection plus the signed ledger/materialized view in `tests/end_to_end/test_desktop_memory_defense.py`

**US1 verification (2026-07-15)**:

- The tracked backend suite passed after integration, including the delayed-poisoning adversarial and Desktop memory-defense matrices.
- `uv run --group test pytest -q -c pyproject.toml tests/test_server.py` from `examples/poisoned-docs-mcp/` — 9 passed.
- `PYTHONPATH=src uv run python evals/runners/run_fixture_evaluation.py --output-dir /tmp/verity-eval-results --check` — 20 synthetic samples, 0 fixture-scoped false positives, and 0 fixture-scoped false negatives.

**Checkpoint**: The fixture demonstrates selective memory trust under
enforcement without subscription access or Desktop UI automation.

---

## Phase 4: User Story 2 — Use a Codex Subscription for Semantic Review (Priority: P2)

**Goal**: Add an explicit, lower-isolation subscription provider with bounded
child execution, strict structured output, tool-event rejection, and no
fallback.

**Independent Test**: A fake trusted Codex executable and temporary Codex home
produce a schema-valid subscription assessment without `OPENAI_API_KEY`; every
auth, tool, output, timeout, cleanup, and drift failure remains explicit and
does not call another provider.

### Tests for User Story 2

- [x] T020 [P] [US2] Add failing exact argv, stdin-only prompt, allow-listed environment, private-path mode, executable identity, HOME/CODEX_HOME ancestor ownership/mode, symlink, replacement, and drift tests in `tests/unit/test_codex_subscription_runner.py`
- [x] T021 [P] [US2] Add failing ChatGPT-login acceptance and API-key, absent, ambiguous, oversized, nonzero, and timeout status rejection tests in `tests/unit/test_codex_subscription_auth.py`
- [x] T022 [P] [US2] Add failing JSONL lifecycle allow-list plus known-tool, unknown-item, duplicate-key, malformed, partial-line, and output-cap rejection tests in `tests/unit/test_codex_subscription_events.py`
- [x] T023 [P] [US2] Add failing extraction/assessment schema, identity, digest, sanitization, provider-label, daemon readiness API, and no-fallback tests in `tests/integration/test_codex_subscription_semantic.py` and `tests/contract/test_control_room_api.py`
- [x] T024 [P] [US2] Add failing timeout, cancellation, process-group descendant cleanup, executable drift, and recursion adversarial tests in `tests/adversarial/test_codex_subscription_isolation.py`

### Implementation for User Story 2

- [x] T025 [US2] Implement trusted executable resolution, bounded auth readiness, fixed child launch, concurrent output caps, JSONL allow-listing, process-group cleanup, and private temporary I/O in `src/verity_cordon/semantic/codex_subscription.py`
- [x] T026 [US2] Implement strict subscription candidate extraction and semantic assessment envelopes in `src/verity_cordon/semantic/codex_subscription.py`
- [x] T027 [US2] Wire explicit provider construction with a shared runner and no silent fallback in `src/verity_cordon/semantic/factory.py` and `src/verity_cordon/daemon/runtime.py`
- [x] T028 [US2] Map the additive provider state through commit, rescan, materialization, and candidate queries in `src/verity_cordon/memory/service.py`, `src/verity_cordon/memory/rescan.py`, `src/verity_cordon/memory/materializer.py`, and `src/verity_cordon/ledger/queries.py`
- [x] T029 [US2] Add content-safe Codex subscription readiness and isolation status to the daemon status API, `verity doctor`, and `verity status` in `src/verity_cordon/daemon/app.py` and `src/verity_cordon/cli/main.py`
- [x] T030 [P] [US2] Add failing Control Room provider-label and lower-isolation warning tests in `apps/control-room/src/routes/CandidateDetailPage.test.tsx` and `apps/control-room/src/routes/OverviewPage.test.tsx`
- [x] T031 [US2] Add `live_codex_subscription` types, filters, status, and the `agentic_sandboxed` warning in `apps/control-room/src/api/types.ts`, `apps/control-room/src/routes/MemoryInventoryPage.tsx`, `apps/control-room/src/routes/OverviewPage.tsx`, and `apps/control-room/src/routes/CandidateDetailPage.tsx`
- [x] T032 [US2] Run all fake-child unit, integration, adversarial, replay, direct API, frontend type, and frontend component tests and record results in `specs/002-codex-desktop-subscription-defense/tasks.md`
- [x] T033 [US2] Exercise one explicitly selected, sanitized synthetic live subscription assessment when supported and record exact version/provider/outcome evidence without raw child output in `docs/hackathon/HACKATHON_WORK.md`

**US2 verification (2026-07-15)**:

- Fake-child, auth, event-gate, structured-provider, isolation, hook, and Control Room API tests passed together. After security review added success-path descendant cleanup, stdin-deadline, opened-output identity, and post-rescan checkpoint regressions, the canonical repository gate passed all 400 backend tests.
- Control Room: ESLint and TypeScript passed; 6 Vitest files / 9 tests passed; Vite production build passed with 1,855 modules transformed.
- Live subscription smoke: Codex CLI `0.144.4`, ChatGPT sign-in, model `gpt-5.6-luna`, provider `live_codex_subscription`, 11,026 ms, synthetic operational instruction recommended `quarantine`, no fallback. The separately attempted base `gpt-5.6` identifier failed content-safely as unavailable for this identity.

**Checkpoint**: Subscription mode either returns a strictly bound advisory
result labeled `live_codex_subscription` or fails content-safely without
another provider; deterministic policy remains final authority.

---

## Phase 5: User Story 3 — Shadow Admission and Selective Recovery (Priority: P3)

**Goal**: Demonstrate shadow admission, safe delayed influence, enforcement,
one-memory revocation, deterministic rebuild, and ledger verification.

**Independent Test**: Seed one benign fact and the synthetic poison under
shadow mode, observe actual/would-have actions, revoke only the poison under
enforcement, rebuild, and verify that the benign fact remains.

### Tests for User Story 3

- [x] T034 [P] [US3] Add a failing shadow/recovery matrix covering benign unrelated memory, malicious poison, a false-positive trap, dependency failure, cross-session activation, tampered history, revocation, and rebuild in `tests/end_to_end/test_desktop_shadow_recovery.py`
- [x] T035 [P] [US3] Add failing UI coverage for shadow-not-protection, a neutral decision-and-recovery timeline, delayed-attack effects when present, and post-revocation state in `apps/control-room/src/routes/CandidateDetailPage.test.tsx`

### Implementation for User Story 3

- [x] T036 [US3] Extend demo orchestration with the two fixed sink markers and safe delayed-attempt metadata in `src/verity_cordon/demo.py`
- [x] T037 [US3] Present actual/would-have action, shadow warning, typed related events, and revocation outcome as a concise decision-and-recovery timeline in `apps/control-room/src/routes/CandidateDetailPage.tsx`
- [x] T038 [US3] Make the complete US3 security matrix pass without adding outbound information-flow-control claims in `tests/end_to_end/test_desktop_shadow_recovery.py`
- [x] T039 [US3] Update the under-three-minute Desktop-primary narrative in `docs/hackathon/DEMO_SCRIPT.md`

**US3 verification (2026-07-15)**:

- `uv run pytest -q tests/end_to_end/test_desktop_shadow_recovery.py` — 4 passed, covering shadow admission, the fixed inert sink attempt, enforcement, selective revocation/rebuild, dependency failure, cross-task activation, false-positive handling, and tampered history.
- Control Room lint/type checks and 6 Vitest files / 10 tests passed; the candidate detail view presents a neutral four-step decision-and-recovery timeline, shows real signed event types, and never labels shadow admission as protection.
- The Desktop-primary narration is 2:55 by its explicit cue sheet and keeps the fixed synthetic sink separate from any outbound information-flow-control claim.

**Checkpoint**: One shadow-admitted poison can be removed without destructive
history rewrite or loss of unrelated approved memory.

---

## Phase 6: User Story 4 — Judge-Ready Desktop Demonstration (Priority: P4)

**Goal**: Provide explicit, reversible demo-only MCP configuration and a
rehearsable Desktop-first path with the existing offline fallback.

**Independent Test**: Against a temporary Codex home, preview setup with no
side effects, apply one receipt-bound MCP entry, verify doctor readiness, change
an unrelated config key, tear down, and prove that the unrelated change and
Verity history remain.

### Tests for User Story 4

- [x] T040 [P] [US4] Add failing receipt-schema sample and state-transition tests in `tests/contract/test_desktop_demo_receipt.py`
- [x] T041 [P] [US4] Add failing benign install, malicious/false-positive drift, dependency failure, restart/new-task, receipt/config tamper, preview, confirmation, reserved-name, interrupted-setup, symlink, mode, digest, and teardown tests in `tests/contract/test_desktop_demo_setup.py`
- [x] T042 [P] [US4] Add a failing bounded fixture-probe and normal-installer-separation test in `tests/end_to_end/test_desktop_demo_contract.py`

### Implementation for User Story 4

- [x] T043 [US4] Implement preview/apply/reconcile/status/teardown with no-follow paths, atomic TOML mutation, strict receipt validation, and exact-entry drift checks in `src/verity_cordon/codex/demo_installer.py`
- [x] T044 [US4] Export Desktop demo integration types and functions without changing normal installer behavior in `src/verity_cordon/codex/__init__.py`
- [x] T045 [US4] Add `verity demo desktop-setup`, `desktop-status`, and `desktop-teardown` with explicit confirmation and content-safe output in `src/verity_cordon/cli/main.py`
- [x] T046 [P] [US4] Add the non-automating Desktop startup/rehearsal helper in `scripts/demo-desktop.sh`
- [x] T047 [US4] Make the temporary-home Desktop setup and bounded-probe end-to-end tests pass in `tests/end_to_end/test_desktop_demo_contract.py`
- [x] T048 [P] [US4] Update the judge path and explicit restart/new-task/manual-smoke boundary in `specs/002-codex-desktop-subscription-defense/quickstart.md` and `README.md`
- [x] T049 [US4] Re-run the existing no-key offline demo acceptance test and prove normal `install-codex` never stages the attack fixture in `tests/end_to_end/test_demo.py` and `tests/contract/test_codex_hooks.py`

**US4 verification (2026-07-15)**:

- The receipt, setup, and bounded-probe contract set passed 33 tests against temporary Codex homes, including zero-side-effect preview, explicit confirmation, interruption recovery, config/artifact/runtime drift, exact teardown, and normal-installer separation.
- The complete repository gate passed 437 backend tests, 13 isolated example/plugin tests, and 6 frontend files / 10 tests. The existing no-key offline demo acceptance remained green.
- `scripts/demo-desktop.sh` is intentionally non-automating: it performs a read-only preview and prints the exact confirmation, restart/new-task, status, service, and teardown commands.

**Checkpoint**: The Desktop fixture can be installed and removed safely while
the normal plugin, unrelated Codex config, ledger, and offline judge path remain
intact.

---

## Phase 7: Security, Product, and Submission Convergence

**Purpose**: Propagate the implemented boundaries, run the complete quality
gate, and leave only honest operator-owned submission work.

- [x] T050 [P] Update delayed-poisoning abuse cases, subscription-child trust boundary, MCP/sink boundary, failures, and residual risks in `docs/security/threat-model.md` and `docs/security/trust-boundaries.md`
- [x] T051 [P] Update the exact provider and demo cryptographic/non-cryptographic claims in `docs/security/cryptographic-claims.md` and `docs/product/positioning.md`
- [x] T052 [P] Record Trojan Hippo attribution and clean-room non-reuse status in `docs/hackathon/BASELINE_COMPARISON.md` and `THIRD_PARTY_NOTICES.md`
- [x] T053 [P] Update subscription runtime use, Desktop demo, Codex collaboration, limitations, testing, and submission language in `README.md`, `docs/hackathon/CODEX_COLLABORATION.md`, `docs/hackathon/SUBMISSION_DRAFT.md`, and `docs/hackathon/SUBMISSION_CHECKLIST.md`
- [x] T054 Run the curated evaluation, report fixture-only metrics, and update `evals/results/latest.json` and `evals/results/latest.md`

**Phase 7 convergence evidence through T054 (2026-07-15)**:

- The delayed-attack, subscription-child, fixed synthetic sink, Desktop installer, unsigned-receipt, signed-ledger, and residual-risk boundaries are explicit across the security and positioning documents; the focused security matrix passed 41 tests.
- Trojan Hippo is attributed at inspected commit `a67d3261338120c606fcf6afda2547f622809922` as threat-model inspiration only. No benchmark code, dataset, prompts, implementation, or reported result was copied or executed.
- `uv run python evals/runners/run_fixture_evaluation.py` recorded 20 original synthetic samples: 7/7 benign allowed, 13/13 risky protected, 0 fixture-scoped false positives, 0 fixture-scoped false negatives, 326 verified events, and a consistent materialized view. `uv run python evals/runners/run_fixture_evaluation.py --check` and the three evaluation-runner tests passed.
- [x] T055 Run Ruff, mypy, tracked backend unit/contract/integration/adversarial/end-to-end tests with coverage, frontend lint/type/test/build, schema/OpenAPI validation, dependency audit, and `./scripts/verify.sh` from a clean checkout; record exact outcomes in `docs/hackathon/HACKATHON_WORK.md`
- [ ] T056 Perform browser smoke/accessibility checks and a timed manual Codex Desktop attack-enforcement-clean-task-revocation-ledger rehearsal; record elapsed time and clearly separate automated from manual evidence in `docs/hackathon/HACKATHON_WORK.md`
- [x] T057 Run Spec Kit consistency analysis and convergence, append and complete any remaining build tasks in `specs/002-codex-desktop-subscription-defense/tasks.md`, and update the constitution sync report in `.specify/memory/constitution.md`
- [x] T058 Record branch, final commit, tests, known limitations, deferred roadmap confirmation, submission status, exact operator actions, and the real `/feedback` reminder in `docs/hackathon/HACKATHON_WORK.md`

**T057 Spec Kit analysis/convergence (2026-07-15)**:

- Prerequisite discovery selected only `002-codex-desktop-subscription-defense`; all 93 feature checklist items are complete and no `VC-FUT-*` capability appears in the active task graph.
- Cross-artifact analysis covered 4 user stories, 26 functional requirements, 10 security/failure requirements, 10 measurable outcomes, the plan, data model, contracts, checklists, and task graph. The review found no unresolved critical or high-severity inconsistency after the Desktop readiness, path, receipt, fixture-probe, config-secret, typed-event, and claims remediations.
- Convergence found no remaining unbuilt implementation requirement. T056 remains operator-observed acceptance evidence rather than a product gap; T058 is complete.

**T055 clean-checkout and T056 browser evidence (2026-07-15)**:

- Pushed remote checkpoint `104e0f06d3d2b3be5d36e2f3884af1adf3076c04` passed bootstrap and the no-key offline demo from a fresh clone beneath a private trusted parent. The demo exercised real policy, ledger, and materialization logic and ended with 65 verified events and a consistent view.
- The clean-checkout `./scripts/verify.sh` gate passed 506 backend tests, 13 isolated example/plugin tests, 10 frontend tests, 80% coverage, formatting, linting, type checking, frontend build, schema/OpenAPI validation, dependency audits, and the 20-fixture evaluation at 0 fixture-scoped false positives and 0 fixture-scoped false negatives.
- Verification-hardening checkpoint `c70db7296427f1525d52e0b2a0854fa34f123d2d` passed bootstrap and the same complete gate from a second fresh private clone after pinning checks to the bootstrapped `.venv`, removing inherited `PYTHONPATH`, and enforcing the declared Node.js engine.
- A clone below `/tmp` was intentionally rejected by the trusted-root security boundary; acceptance moved to a private trusted parent instead of weakening that control.
- Browser smoke verified Overview, a typed `MemoryRevoked` detail event, quarantine Block, selective revocation with unrelated memory preserved, enforce-to-shadow-to-enforce mode changes ending on policy `1.0.2`, and a 69-event ledger with anchored completeness and a consistent view. At 1280x720 it showed no horizontal overflow, 0 console errors or warnings, the expected main/navigation/heading/skip-link structure, 0 unlabeled controls, and 0 duplicate IDs.
- T056 remains open because the timed, operator-visible Codex Desktop app rehearsal has not been performed. The completed Control Room browser smoke is recorded separately and is not treated as Desktop app evidence.
- T058 records public branch checkpoint `79a12d0c8058d579664c90740a8bd44ae3359c68`, the complete verification and limitation set, deferred-scope confirmation, unsubmitted status, the exact operator sequence, and the required reminder to run `/feedback` without inventing a Session ID.
### Phase 10: Release closure tasks

- [x] T059 Refresh current Desktop terminology, exact-hash hook-trust guidance, the canonical shadow-trigger-enforce-revoke run order, judge testing instructions, and the blank manual evidence record in `README.md`, `docs/hackathon/DEMO_SCRIPT.md`, `docs/hackathon/SUBMISSION_DRAFT.md`, `docs/hackathon/DESKTOP_REHEARSAL_RECORD.md`, and `specs/002-codex-desktop-subscription-defense/{spec.md,research.md,quickstart.md,contracts/desktop-demo-contract.md}`.
- [x] T060 Exercise the full no-key subscription pipeline, fix the strict candidate-extraction schema rejected by the live runtime, add regression assertions, and record the successful extraction-assessment-ledger evidence without claiming remote-model attestation in `src/verity_cordon/semantic/structured.py`, `tests/integration/test_codex_subscription_semantic.py`, `tests/integration/test_openai_semantic.py`, `README.md`, `docs/hackathon/HACKATHON_WORK.md`, and `docs/hackathon/SUBMISSION_DRAFT.md`.
- [x] T061 Capture and publish a content-safe real Control Room screenshot from the offline deterministic fixture, label it accurately, and verify zero browser console warnings or errors in `docs/assets/control-room-overview.jpg` and `README.md`.
- [x] T062 Align the runtime provider-isolation mapping, `/api/v1/status` OpenAPI contract, frontend status type, and semantic failure JSON Schema with executable regression tests in `src/verity_cordon/core/models.py`, `src/verity_cordon/daemon/app.py`, `src/verity_cordon/cli/main.py`, `apps/control-room/src/api/types.ts`, `specs/001-codex-memory-firewall/contracts/{verity-ipc.openapi.yaml,semantic-assessment.schema.json}`, and `tests/contract/test_subscription_provider_compatibility.py`.

### Phase 11: Release review hardening

- [x] T063 Serialize subscription-runner health, bind executable trust across each invocation, enforce constructor resource ceilings, normalize setup failures, and add concurrency/drift/non-disclosure regressions in `src/verity_cordon/semantic/{codex_subscription.py,readiness.py}`, the semantic contracts, and focused tests.
- [x] T064 Make normal Codex installation and removal fully receipt-journaled and retry-safe, bind every executable staging state, validate complete trusted path chains, and add interruption/partial-command/path-drift regressions in `src/verity_cordon/codex/installer.py`, the hook contract, security documentation, and focused tests.
- [x] T065 Bind Desktop fixture receipt, artifact, archive, configuration, normal-integration, and teardown transitions to expected state; preserve restrictive modes; prevent drift laundering and deletion races; and add recovery/race regressions in `src/verity_cordon/codex/demo_installer.py`, its contracts, and focused tests.
- [ ] T066 Run independent cross-review, a fresh sanitized subscription smoke after runtime hardening, Spec Kit analysis and convergence, the complete release verification gate, remote review closure, and public-main verification; record exact evidence in `docs/hackathon/HACKATHON_WORK.md`.

**T063 verification (2026-07-15)**:

- Independent remediation review closed concurrent cleanup-health bypass,
  pre/post child trust drift, constructor type/range, and private setup-error
  disclosure cases. The final lifecycle review passed 13 targeted tests; the
  implementation author's last complete focused runner/event/adversarial gate
  passed 168 tests, with Ruff, targeted mypy, and diff checks clean.
- A fresh API-key-free subscription assessment on Codex CLI `0.144.4` exercised
  the production validator. The child emitted its exact failure lifecycle and
  returned code 1; an authorized local fixed-category classifier identified
  external rate limiting without printing or retaining raw child content.
  Verity returned retryable `failed/process_exit` in 3,704 ms, produced no
  disposition, retained no final document, and reported clean cleanup health.
  This is fail-closed classification evidence, not a successful live assessment
  or remote-model attestation.

**T064 verification (2026-07-15)**:

- Independent remediation review verified deterministic receipt-bound staging,
  retired, and removal trees; exact tombstone digest checks; journaled partial
  add/remove retries; retry-safe phased uninstall; strict plugin refresh on
  upgrade; full path owner/mode/symlink validation; and fail-closed incomplete
  journals. The complete hook contract suite passed 85 tests, with Ruff,
  targeted installer mypy, and diff checks clean.
- The residual crash window after an external Codex command succeeds but before
  its local journal transition is durable is explicit for process interruption
  and atomic write/sync/replacement failure. Readiness remains disabled and
  controlled local state is retained for operator reconciliation.

**T065 verification (2026-07-15)**:

- `uv run pytest -q tests/contract/test_desktop_demo_receipt.py tests/contract/test_desktop_demo_setup.py tests/end_to_end/test_desktop_demo_contract.py` — 89 passed. This includes expected-existence/digest writes, receipt and archive inode races, normal-v2 receipt/doctor rebinding, non-finalizable projection failure and retry, interrupted `prepared` to `failed` recovery followed by exact teardown, `0400` preservation, source-before-staging recovery, teardown typed-value rechecks, and anchored replacement-safe artifact removal.
- `uv run ruff check src/verity_cordon/codex/demo_installer.py tests/contract/test_desktop_demo_setup.py tests/contract/test_desktop_demo_receipt.py` — passed.
- `uv run ruff format --check src/verity_cordon/codex/demo_installer.py tests/contract/test_desktop_demo_setup.py tests/contract/test_desktop_demo_receipt.py` — passed.
- `uv run mypy src/verity_cordon/codex/demo_installer.py` and `git diff --check` — passed.

**T066 partial verification (2026-07-15)**:

- Three independent release-hardening re-reviews found no remaining P1 or P2
  issue across the subscription runner, normal Codex installer, Desktop demo
  installer, and integrated provider-provenance contract.
- The fresh API-key-free hardened subscription probe failed closed under an
  external rate limit as recorded under T063; successful hardened live
  completion remains pending and is not inferred.
- Final read-only Spec Kit analysis mapped 46/46 requirements and 15/15
  acceptance scenarios to 66 tasks, found no ambiguity, duplication,
  constitution violation, unmapped task, or deferred-scope leakage, and added no
  convergence task.
- `./scripts/verify.sh` passed 708 backend tests with 81% coverage, 13 isolated
  example/plugin tests, 11 Control Room tests, formatting, lint, mypy, contracts,
  frontend build, dependency audits, and the 20-sample fixture evaluation.
- PR #3's stale stdin/EOF finding was answered by existing drain, close,
  `wait_closed()`, and blocked-stdin tests. Its directory-mode findings were
  remediated with explicit per-segment `0700` creation plus parent validation;
  152 installer contract tests and the complete gate passed afterward.
- Pushed commit `18e04942a637af9eacc3b491fce8c7a9540f21c9` passed no-key bootstrap,
  the 65-event offline demo, and the same complete gate from a new private
  trusted clone.
- T066 remains open for remote review closure and post-merge public-main
  verification.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1**: Complete.
- **Phase 2**: Depends on Phase 1 and blocks all runtime changes.
- **US1 / Phase 3**: Depends on Phase 2; this is the first runnable MVP.
- **US2 / Phase 4**: Depends on Phase 2 and can be developed with fake Codex
  children in parallel with US1 after the shared schemas/enums land.
- **US3 / Phase 5**: Depends on the US1 fixture and baseline revocation path;
  it does not require a successful live subscription call.
- **US4 / Phase 6**: Depends on Phase 2 and the two-tool fixture from US1; its
  installer tests can proceed independently of US2.
- **Phase 7**: Depends on all desired story checkpoints.

### User Story Dependencies

- **US1 (P1)**: Independent after Phase 2 using recorded fixtures.
- **US2 (P2)**: Independent after Phase 2 using fake child executables; one
  real subscription smoke is an explicit environment-dependent verification.
- **US3 (P3)**: Uses US1's attack fixture but remains independent of US2.
- **US4 (P4)**: Uses US1's staged fixture and existing normal Codex installer;
  it remains functional when subscription capacity is unavailable.

### Within Each User Story

1. Write the listed tests and observe the relevant failure.
2. Implement the smallest contract-complete behavior.
3. Run the story's independent acceptance path and baseline regressions.
4. Mark tasks complete only after commands actually pass.
5. Commit one intentional logical slice without staging unrelated files.

### Parallel Opportunities

- T004 and T005 can run in parallel.
- T012 and T013 can run in parallel before T014.
- T020 through T024 are separate fake-child test files and can be authored in
  parallel; T025 and T026 then converge in one provider module.
- T030 can proceed after T007 while backend child execution is implemented.
- T034 and T035 can proceed in parallel.
- T040 through T042 can proceed in parallel before T043.
- T050 through T053 are separate documentation boundaries and can proceed in
  parallel after implementation stabilizes.

## Parallel Examples

### User Story 1

```text
Task T012: Fixture tool/sink contract tests
Task T013: Delayed-poisoning taxonomy adversarial tests
```

### User Story 2

```text
Task T020: Exact process boundary tests
Task T021: Authentication-status tests
Task T022: JSONL event-gate tests
Task T023: Structured semantic integration tests
Task T024: Cancellation/recursion/drift adversarial tests
```

### User Story 4

```text
Task T040: Receipt schema/state tests
Task T041: Setup and teardown mutation tests
Task T042: Bounded fixture probe and install-separation test
```

## Implementation Strategy

### MVP First

1. Complete the replay/isolation foundation.
2. Deliver US1 using the existing recorded semantic provider.
3. Demonstrate a real delayed poison being selectively quarantined and absent
   from a fresh-session injection before adding subscription complexity.

### Incremental Delivery

1. **Foundation**: additive labels, shared strict schemas, recursion guard.
2. **US1**: real attack/defense vertical slice through policy and signed ledger.
3. **US2**: opt-in subscription semantic advice with explicit lower isolation.
4. **US3**: shadow risk and selective recovery narrative.
5. **US4**: reversible Desktop setup and judge operations.
6. **Convergence**: clean-checkout verification, browser evidence, claims, and
   submission artifacts.

## Notes

- Provider failure never authorizes memory and never changes providers.
- Desktop UI steps remain manual observations; automated CLI/hook tests prove
  only the shared contracts they execute.
- The benchmark is a research source only. No external benchmark code or data
  is required by this task graph.
- Run `git status --short` before every commit and stage explicit paths only.
