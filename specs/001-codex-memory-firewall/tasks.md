# Tasks: Codex Memory Firewall

**Input**: Design documents in `specs/001-codex-memory-firewall/`

**Tests**: Tests are mandatory. Security-sensitive stories include benign,
malicious, false-positive, failure-mode, cross-session, streaming, and tamper
coverage as applicable.

**Organization**: Tasks are grouped by user story. The feature is implemented
in priority order so every completed phase leaves a runnable vertical slice.
Deferred `VC-FUT-*` capabilities are not implementation tasks.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel because it changes different files and has no incomplete dependency.
- **[Story]**: Maps the task to a feature user story.
- Every task names its primary file or directory.

## Phase 1: Setup

**Purpose**: Establish an attributable, reproducible repository without creating security-sensitive runtime state inside Git.

- [x] T001 Create the planned source, test, app, example, evaluation, and script directories with package markers under `src/verity_cordon/`, `tests/`, `apps/control-room/`, `examples/`, `evals/`, and `scripts/`
- [x] T002 Configure the Python 3.12 package, runtime dependencies, developer checks, CLI entry point, and build metadata in `pyproject.toml`
- [x] T003 [P] Configure repository exclusions and placeholder-only environment documentation in `.gitignore` and `.env.example`
- [x] T004 [P] Add Apache-2.0 licensing and clean-room attribution in `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md`
- [x] T005 [P] Add vulnerability-reporting, supported-platform, and local threat-boundary guidance in `SECURITY.md`
- [x] T006 Resolve and record reproducible Python and frontend dependency locks in `uv.lock` and `apps/control-room/package-lock.json`

**Checkpoint**: A clean checkout can install dependencies without generating or committing keys, bearer capabilities, databases, or real credentials.

---

## Phase 2: Foundational Security Core

**Purpose**: Build the shared contracts and safety boundaries that block all user-story implementation.

**CRITICAL**: No memory may become active before this phase is complete.

- [x] T007 [P] Implement strict shared enums, identifiers, timestamps, evidence, candidate, detector, semantic, policy, decision, and event models in `src/verity_cordon/core/models.py`
- [x] T008 [P] Define async protocols for `EventStore`, `MemoryView`, `Detector`, `CandidateExtractor`, `SemanticAdjudicator`, `PolicyProvider`, `EventSink`, `CodexAdapter`, `Clock`, and `KeyProvider` in `src/verity_cordon/core/protocols.py`
- [x] T009 [P] Implement bounded configuration, runtime paths outside Git, and content-free error classes in `src/verity_cordon/core/config.py` and `src/verity_cordon/core/errors.py`
- [x] T010 Write canonicalization and key-handling unit tests, including duplicate keys, non-finite values, timestamp normalization, restrictive permissions, and padded Base64, in `tests/unit/test_crypto.py`
- [x] T011 Implement `VC-CJ-1`, SHA-256 helpers, Ed25519 file-key fallback, public export, and permission validation in `src/verity_cordon/crypto/canonical.py` and `src/verity_cordon/crypto/keys.py`
- [x] T012 Write policy-schema, priority, hard-guard, shadow-action, malformed-policy, and last-known-good tests in `tests/unit/test_policy.py`
- [x] T013 Implement Pydantic v2 policy validation, `VC-POLICY-1` hard guards, deterministic match semantics, shadow/enforce decisions, failure fallbacks, and default policies in `src/verity_cordon/policies/models.py`, `src/verity_cordon/policies/engine.py`, and `src/verity_cordon/policies/default-*.yaml`
- [x] T014 Write SQLite initialization, concurrent sequence, rollback, append-only trigger, payload-binding, and interruption tests in `tests/integration/test_event_store.py`
- [x] T015 Implement versioned async SQLite initialization, restrictive no-symlink/current-owner database-path validation, evidence digest/excerpt records, bounded pending evidence, event transactions, signed expected-head sidecar state, and projection tables in `src/verity_cordon/ledger/schema.py` and `src/verity_cordon/ledger/store.py`
- [x] T016 [P] Implement privacy-safe span/counter interfaces and a no-op/default OpenTelemetry API bridge in `src/verity_cordon/telemetry/instrumentation.py`
- [x] T017 [P] Establish synthetic-secret, clock, temporary-key/database, schema, OpenAPI, and content-safe API test helpers in `tests/factories.py`, `tests/contract/`, and focused test modules

**Checkpoint**: Policies validate deterministically, signed events append only inside atomic transactions, and no test artifact contains a real secret.

---

## Phase 3: User Story 1 — Prevent Persistent Memory Poisoning (Priority: P1) MVP

**Goal**: Evaluate safe and poisoned evidence through the real local pipeline, commit only eligible memory, and provide only eligible memory to a later session.

**Independent test**: Submit a safe project fact and the synthetic poisoned-docs response. In enforce mode the fact is active and injectable while the persistent tool instruction is quarantined and absent from the next-session context.

### Tests for User Story 1

- [x] T018 [P] [US1] Test credentials, persistent instructions, protected namespaces, cross-task content, self-reinforcement, untrusted authority, size, concealment, and benign quoted false positives in `tests/unit/test_detectors.py`
- [x] T019 [P] [US1] Test fixture extraction/assessment, live-mode-no-substitution, timeout, invalid schema, and candidate-digest binding in `tests/unit/test_semantic.py`
- [x] T020 [P] [US1] Test safe evidence, poisoned tool output, component failure, cross-session injection, secret/source-label non-retention, and durable queue failure/integrity behavior in `tests/integration/test_memory_pipeline.py`
- [x] T021 [P] [US1] Validate candidate, detector, semantic, policy, event, and IPC artifacts in `tests/contract/test_artifact_schemas.py`

### Implementation for User Story 1

- [x] T022 [P] [US1] Implement local secret-first sanitization and compact deterministic detectors with safe offsets and messages in `src/verity_cordon/detectors/builtin.py`
- [x] T023 [US1] Implement concurrent detector fan-out, deadlines, cancellation, failure isolation, and deterministic aggregation in `src/verity_cordon/detectors/runner.py`
- [x] T024 [P] [US1] Implement deterministic recorded candidate extraction and semantic assessment fixtures with explicit provider labels in `src/verity_cordon/semantic/fixture.py` and `evals/expected/semantic-fixtures.json`
- [x] T025 [US1] Implement signed evidence capture with sanitized source labels, bounded durable sanitized queueing, atomic candidate evaluation, event emission, quarantine/block handling, explicit `MemoryExpired` lifecycle sweeps, active materialization, and safe statement storage in `src/verity_cordon/memory/service.py` and `src/verity_cordon/memory/materializer.py`
- [x] T026 [US1] Implement deterministic, budgeted, delimiter-safe approved-memory rendering in `src/verity_cordon/memory/injection.py`
- [x] T027 [US1] Implement the loopback FastAPI health, status, statistics, hook-evidence, session-start, candidate, and memory read endpoints in `src/verity_cordon/daemon/app.py`
- [x] T028 [US1] Implement working `doctor`, `status`, `serve`, `memory list`, and `memory show` commands in `src/verity_cordon/cli/main.py`
- [x] T029 [US1] Create the inert stdio-only synthetic poisoned documentation fixture without environment or external-network access in `examples/poisoned-docs-mcp/`

**Checkpoint**: The minimum vertical slice is runnable through API and CLI and the demonstrated poisoned instruction cannot enter enforcement-mode injection.

---

## Phase 4: User Story 2 — Understand Every Memory Decision (Priority: P2)

**Goal**: Expose safe provenance, detector, semantic, policy, action, and ledger status in the local Control Room.

**Independent test**: Open a candidate detail and trace its safe representation from evidence digest through detector and semantic inputs to actual/would-have actions and signed events without exposing raw evidence.

### Tests for User Story 2

- [x] T030 [P] [US2] Test content-safe health/status/statistics, queue health, request-size bounds, foreign Host/Origin, browser proof, nonce replay, CSRF/cookie flags, rate limiting, idempotent hook capture, attack decisions, and secret-free errors in `tests/contract/test_control_room_api.py`
- [x] T031 [P] [US2] Test passphrase proof/clearing, overview, untrusted candidate rendering, quarantine approval, and revocation preview in `apps/control-room/src/**/*.test.tsx`

### Implementation for User Story 2

- [x] T032 [US2] Complete content-safe candidate, memory, event, statistics, policy, and auxiliary-projection queries in `src/verity_cordon/ledger/queries.py` and `src/verity_cordon/daemon/app.py`
- [x] T033 [US2] Implement strict loopback peer, Host, same-origin, JSON content-type, non-browser bearer capability, minimum-length PBKDF2-HMAC browser proof, one-time challenge expiry, constant-time comparison, failed-proof cooldown, idle-expiring HttpOnly session, CSRF, idempotency, and content-free errors in `src/verity_cordon/daemon/security.py` and `src/verity_cordon/daemon/idempotency.py`
- [x] T034 [P] [US2] Build the accessible React/TypeScript Control Room shell, restrained visual system, routing, and API client in `apps/control-room/src/`
- [x] T035 [US2] Build Overview, Memory Inventory, Event Timeline, Candidate Detail, Policies, and Ledger Verification pages in `apps/control-room/src/routes/`
- [x] T036 [US2] Serve the built Control Room from the loopback daemon with no public bind or wildcard CORS in `src/verity_cordon/daemon/static.py`

**Checkpoint**: Every demonstrated decision is inspectable without turning the Control Room, logs, or errors into a raw-evidence leak.

---

## Phase 5: User Story 3 — Revoke Previously Trusted Memory (Priority: P3)

**Goal**: Append one reasoned revocation and reconstruct a correct active view without deleting unrelated knowledge or historical events.

**Independent test**: Revoke one shadow-admitted malicious memory among several legitimate memories, replay, and prove only the target disappears.

### Tests for User Story 3

- [x] T037 [P] [US3] Test malicious-target revocation, benign preservation, unconfirmed no-op, tampered-history refusal, stale-view repair, approval, and block behavior in `tests/integration/test_revocation.py`
- [x] T038 [P] [US3] Test Control Room quarantine confirmation and revocation preview in `apps/control-room/src/routes/QuarantinePage.test.tsx` and `apps/control-room/src/routes/RevocationPage.test.tsx`

### Implementation for User Story 3

- [x] T039 [US3] Implement reasoned approve, block, revoke, preview, and deterministic rebuild operations as append-only events in `src/verity_cordon/memory/trust_actions.py`
- [x] T040 [US3] Implement authenticated candidate-review, revocation-preview, revoke, and memory-rebuild endpoints in `src/verity_cordon/daemon/app.py`
- [x] T041 [US3] Implement working `memory revoke` and `memory rebuild` CLI commands with explicit confirmation and safe output in `src/verity_cordon/cli/main.py`
- [x] T042 [US3] Build Quarantine and Revocation pages with reason entry, explicit confirmation, preview, refetch-on-unknown, and verification state in `apps/control-room/src/routes/`

**Checkpoint**: Revocation is event-specific, historical events remain, the rebuilt view is deterministic, and stale projections disable injection.

---

## Phase 6: User Story 4 — Evaluate Safely in Shadow Mode (Priority: P4)

**Goal**: Record and display the distinction between actual admission and the enforcement action that would have applied.

**Independent test**: The poisoned fixture is shadow-admitted with `actual_action=allow`, `would_have_action=quarantine`, and `shadow_mode=true`, then the same fixture is quarantined under enforcement.

### Tests and Implementation for User Story 4

- [x] T043 [P] [US4] Cover benign parity and malicious actual/would-have divergence in `tests/integration/test_memory_pipeline.py`, then exercise the same shadow-admitted attack through confirmed one-memory enforcement rescan in `tests/integration/test_rescan.py` and `tests/end_to_end/test_demo.py`; automatic policy-wide rescan remains explicitly out of scope
- [x] T044 [US4] Persist and project actual action, would-have action, admission mode, policy version, and semantic assessment identity for every decision in `src/verity_cordon/memory/service.py`
- [x] T045 [US4] Implement working `policy validate`, `policy show`, and confirmed `policy activate` commands plus safe rejection events through `src/verity_cordon/daemon/app.py` and `src/verity_cordon/cli/main.py`
- [x] T046 [US4] Add unmistakable Shadow and Enforcement state, fixture/live provider state, and action comparison to Control Room pages in `apps/control-room/src/routes/`

**Checkpoint**: Shadow mode is useful for evaluation but never presented as active protection.

---

## Phase 7: User Story 5 — Verify Ledger Integrity (Priority: P5)

**Goal**: Independently verify canonical payload binding, event order, chain links, Ed25519 signatures, expected head, and materialized-view consistency.

**Independent test**: A valid ledger verifies; modifying a payload or event, reordering or omitting an event, changing a signature, or drifting the active view fails at the first attributable event without repairing history.

### Tests and Implementation for User Story 5

- [x] T047 [P] [US5] Test intact verification, byte-level payload/event/signature/wrong-key tampering, reordering, interior omission, expected-head truncation, unanchored tail, equivalent serialization, and view drift in `tests/adversarial/test_ledger_tampering.py`, with Unicode/duplicate-key canonicalization in `tests/unit/test_crypto.py`
- [x] T048 [US5] Implement full-chain, payload/evidence/auxiliary-projection verification, exact signed terminal-queue verification, expected-head checks, public-key resolution, first-failure reporting, and replay comparison in `src/verity_cordon/ledger/verify.py`
- [x] T049 [US5] Disable new commits and session injection on ledger, queue-integrity, or view failure; preserve signed queue-integrity failure across restart; and start a tested content-safe read-only Control Room without loading detector plugins or treating fallback policy as valid in `src/verity_cordon/ledger/store.py`, `src/verity_cordon/ledger/verify.py`, `src/verity_cordon/memory/service.py`, and `src/verity_cordon/daemon/runtime.py`
- [x] T050 [US5] Implement working `ledger init-key`, `ledger verify`, and `ledger export-public-key` commands and ledger verification/public-key endpoints in `src/verity_cordon/cli/main.py` and `src/verity_cordon/daemon/app.py`
- [x] T051 [US5] Connect verification details, first-invalid-event state, key ID, fingerprint, and last verification time to `apps/control-room/src/routes/LedgerPage.tsx`

**Checkpoint**: The tested tamper-evidence claim matches `docs/security/cryptographic-claims.md`, including the documented terminal-tail limitation.

---

## Phase 8: User Story 6 — Transactional Streaming Memory Writes (Priority: P6)

**Goal**: Keep chunks isolated until a complete final evaluation succeeds, and make every terminal stream outcome auditable.

**Independent test**: Split a persistent instruction across chunks, confirm no chunk is visible before commit, and prove block/abort/double-commit/cancellation cannot create partial memory.

### Tests and Implementation for User Story 6

- [x] T052 [P] [US6] Test benign commit, split/full-buffer attacks, quoted false positives, sanitized abort reason, double commit, byte/chunk limits, concurrency, policy rejection, projection rollback, terminal state, and no partial commit in `tests/adversarial/test_streaming.py`
- [x] T053 [US6] Implement isolated bounded stream state, ordered append, incremental overlap scanning, final full-buffer evaluation, cancellation safety, and terminal transitions in `src/verity_cordon/streaming/session.py`
- [x] T054 [US6] Persist `StreamStarted`, `StreamAborted`, and `StreamCommitted` outcomes without persisting partial active memory in `src/verity_cordon/streaming/service.py`
- [x] T055 [US6] Implement authenticated begin, append, commit, and abort API operations in `src/verity_cordon/daemon/app.py`
- [x] T056 [US6] Document and exercise transactional streaming acceptance through `tests/adversarial/test_streaming.py` and `specs/001-codex-memory-firewall/quickstart.md`

**Checkpoint**: A stream is invisible until one successful final commit and no terminal stream can be committed twice.

---

## Phase 9: User Story 7 — Judge-Friendly Demonstration (Priority: P7)

**Goal**: Provide a clean-checkout offline judge path, an explicit live GPT-5.6 path, a supported Codex plugin contract, and a polished local demo.

**Independent test**: From a clean checkout, bootstrap and run the offline demo without an API key, exercise attack, shadow, enforcement, session injection, revocation, replay, and verification in the real backend and UI; separately confirm live mode calls the configured model when credentials are present.

### Tests for User Story 7

- [x] T057 [P] [US7] Test structured extraction/assessment for sanitized input, re-sanitized bounded model free text, no tools or memory, `store=False`, returned-model recording, bounded retry, refusal, incomplete, and unavailable states in `tests/integration/test_openai_semantic.py`
- [x] T058 [P] [US7] Test selected Codex events, duplicate keys, size limits, idempotency, timeout, daemon failure, malformed response, delimiters, healthy/unhealthy session injection, installer, uninstaller, and doctor in `tests/contract/test_codex_hooks.py`
- [x] T059 [P] [US7] Test allow-listed detector discovery, missing/malformed/duplicate plugins, bounded and sanitized plugin results, content-safe detail projection, and failure isolation in `tests/integration/test_detector_plugins.py` and `tests/integration/test_projection_integrity.py`, with runner timeout/schema behavior in `tests/unit/test_detectors.py`
- [x] T060 [P] [US7] Test the offline path's real bounded-stdio fixture invocation, shadow/enforce outcomes, targeted rescan/revocation, rebuild/verify, and approved-only simulated `SessionStart` rendering in `tests/end_to_end/test_demo.py`; also test explicit no-fixture live-mode failure, while a credentialed live API run remains a separate unchecked gate

### Implementation for User Story 7

- [x] T061 [P] [US7] Implement isolated OpenAI structured candidate extraction and semantic assessment with the official async SDK, local input/output sanitization, strict schemas and free-text bounds, `gpt-5.6`, `store=False`, and explicit failures in `src/verity_cordon/semantic/openai_provider.py`
- [x] T062 [P] [US7] Implement trusted Python entry-point detector discovery, duplicate rejection, and the bounded reference plugin in `src/verity_cordon/detectors/plugins.py` and `examples/detector-plugin/`
- [x] T063 [US7] Implement the thin bounded Codex hook adapter and documented plugin manifest/hook definitions in `src/verity_cordon/codex/hooks.py`, `.codex-plugin/plugin.json`, and `hooks/hooks.json`
- [x] T064 [US7] Implement and isolate-test reviewable `install-codex` and `uninstall-codex` commands with backups, native-memory disablement, hook trust instructions, receipt scope/current-Python pinning, and doctor drift checks in `src/verity_cordon/codex/installer.py` and `src/verity_cordon/cli/main.py`
- [x] T065 [US7] Implement deterministic demo seeding and working `demo offline` and `demo live` commands in `src/verity_cordon/demo.py` and `src/verity_cordon/cli/main.py`
- [x] T066 [US7] Create source-checkout bootstrap, offline demo, live demo, and critical verification scripts in `scripts/bootstrap.sh`, `scripts/demo-offline.sh`, `scripts/demo-live.sh`, and `scripts/verify.sh`; the final fresh-clone execution is T074
- [x] T067 [US7] Curate licensed synthetic benign, malicious, indirect, persistence, tool, cross-task, false-positive, and secret-handling fixtures plus a real evaluation runner in `evals/datasets/` and `evals/runners/`
- [x] T068 [US7] Execute the evaluation and write fixture-scoped metrics and latency results to `evals/results/latest.json` and `evals/results/latest.md`

**Checkpoint**: Offline mode requires no key and uses the real policy, ledger, view, API, and UI; live mode visibly and exclusively uses the configured OpenAI provider.

---

## Phase 10: Polish, Verification, and Submission Readiness

**Purpose**: Converge implementation, claims, docs, usability, and public repository state without performing the operator-only Devpost or video steps.

- [x] T069 [P] Reconcile the top-level architecture, quickstart, offline/live usage, Codex integration, threat limits, donor attribution, testing, Codex collaboration, runtime GPT-5.6 role, roadmap, and license in `README.md`
- [x] T070 [P] Reconcile implementation status and verified results across `docs/hackathon/`, `docs/security/`, `docs/product/`, `docs/decisions/`, and `specs/001-codex-memory-firewall/`
- [x] T071 Run Python formatting, lint, type checking, unit, contract, integration, adversarial, end-to-end, and coverage gates through `scripts/verify.sh`
- [x] T072 Run frontend type checking, linting, unit/component tests, and production build through `scripts/verify.sh`; run keyboard/focus accessibility and console-error checks in the separate browser smoke
- [x] T073 Run a real desktop-width browser smoke of Overview, candidate detail, quarantine/block, revocation/replay, policy, and ledger verification and record the result in `docs/hackathon/HACKATHON_WORK.md`
- [ ] T074 Run the offline demo from a fresh isolated clone, verify no real credential is required or logged, and record exact commands/results in `docs/hackathon/HACKATHON_WORK.md`
- [ ] T075 Run final Spec Kit consistency analysis and convergence; close only verified checklist items in `specs/001-codex-memory-firewall/checklists/` and `docs/hackathon/SUBMISSION_CHECKLIST.md`
- [ ] T076 Audit tracked files and Git history under `.` for credentials, private keys, mutation capabilities, raw evidence, generated databases, and unsupported claims before publication
- [ ] T077 Create intentional feature commits, integrate without force-push, create the authorized public GitHub repository, push the verified default branch, and record the exact repository URL and commit in `docs/hackathon/HACKATHON_WORK.md`

---

## Phase 11: Convergence Findings

**Purpose**: Close gaps found by the final Spec Kit analysis without expanding
the product scope or concealing an environment-dependent validation gap.

- [x] T078 Add and verify the missing privacy-safe extraction, policy, ledger-append, materialization, revocation, and ledger-verification spans promised by `plan.md`
- [x] T079 Record the elapsed critical verification-suite time for SC-010 and reconcile the plan-only Control Room responsiveness target by measuring it or removing an unsupported hard SLO
- [ ] T080 Exercise the live OpenAI semantic path with the configured GPT-5.6 model and record the provider result; leave this task open and disclose it when no operator-provided API key is available
- [x] T081 Record the final clarification-pass outcome and confirm that no material ambiguity required an operator decision before implementation

---

## Dependencies and Execution Order

### Phase dependencies

- **Setup** has no dependencies.
- **Foundational Security Core** depends on Setup and blocks all stories.
- **US1** depends on the foundation and is the minimum viable product.
- **US2** depends on US1 projections and API state.
- **US3** depends on US1 event/materialization behavior; its UI depends on US2.
- **US4** depends on US1 policy decisions and US2 presentation.
- **US5** depends on foundation ledger writes and US1 materialization.
- **US6** depends on the US1 pipeline and US5-safe terminal event writes.
- **US7** integrates the completed vertical slice and must not bypass it.
- **Polish and publication** depend on all selected story checkpoints.

### Within each user story

- Write the listed tests first and confirm the new assertions fail for the expected reason.
- Implement models and pure logic before persistence and API boundaries.
- Make state-changing endpoints depend on validated server-side logic rather than duplicate decisions in the UI or adapter.
- Run the story's independent test before advancing.

### Parallel opportunities

- Setup documentation tasks T003-T005 can run in parallel.
- Foundational model/protocol/config tasks T007-T009 can run in parallel, as can T016-T017.
- Within a story, test files and isolated modules marked `[P]` can proceed after their shared prerequisite exists.
- Final documentation reconciliation T069-T070 can proceed in parallel only after behavior is stable.

## Implementation Strategy

1. Complete Setup and the Foundational Security Core.
2. Deliver and verify US1 before adding UI breadth.
3. Add decision visibility, revocation, shadow mode, and ledger verification while preserving the runnable US1 path.
4. Add streaming and plugin/live integrations only through the established policy and ledger path.
5. Converge the offline demo first; exercise live GPT-5.6 separately and label any unavailable operator-only step honestly.
6. Publish only after the security and claim audit passes.

## Notes

- `[P]` means different files and no incomplete dependency, not permission to weaken sequence or security gates.
- No task implements Redis, PostgreSQL, vector databases, other agent adapters, remote policy, multi-tenancy, enterprise identity, HSMs, hosted telemetry, a public SaaS, or any other `VC-FUT-*` capability.
- Each completed task is marked only after its artifact or command is verified.
- Commit after logical groups using `spec:`, `docs:`, `feat:`, `test:`, `fix:`, or `chore:` prefixes.
