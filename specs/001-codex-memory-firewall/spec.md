# Feature Specification: Codex Memory Firewall

**Feature Branch**: `feat/001-codex-memory-firewall`

**Created**: 2026-07-15

**Status**: Implemented local MVP and published public repository; credentialed
live-model validation and operator submission actions remain pending

**Input**: Build Verity Cordon, a tamper-evident memory firewall for Codex,
as a complete OpenAI Build Week Developer Tools submission.

## Product Positioning

**Project name**: Verity Cordon

**Descriptor**: A tamper-evident memory firewall for Codex.

**Tagline**: Verifiable memory. Revocable trust.

Verity Cordon protects Codex from persistent memory poisoning by making durable
memory explicit, attributable, policy-governed, and revocable. It does not
claim to prove arbitrary factual truth, prevent every prompt injection, or
protect a fully compromised host.

## User Scenarios & Testing

### User Story 1 - Prevent Persistent Memory Poisoning (Priority: P1)

As a developer using Codex, I need content proposed for durable memory to be
inspected before it is reused, so malicious instructions from tools, files,
model output, or prior sessions cannot silently survive into future work.

**Why this priority**: This is the minimum viable security outcome and the core
cross-session attack the product exists to address.

**Independent Test**: Feed a synthetic documentation result containing both a
legitimate project fact and a disguised persistent exfiltration instruction,
then start a new session and inspect the approved memory supplied to it.

**Acceptance Scenarios**:

1. **Given** trusted-looking external-tool evidence containing a legitimate fact
   and a persistent malicious instruction, **When** it is evaluated in
   enforcement mode, **Then** the legitimate candidate may become active while
   the instruction is quarantined or blocked and remains absent from a new
   session.
2. **Given** a benign project fact with complete provenance, **When** it is
   evaluated under the default policy, **Then** it becomes active memory and is
   available in the next eligible session.
3. **Given** benign documentation that quotes prompt-injection phrases for
   educational purposes, **When** it is evaluated, **Then** contextual evidence
   prevents an automatic malicious classification solely because of those
   words.
4. **Given** a high-risk candidate whose semantic review times out, **When** the
   final decision is made, **Then** the candidate is quarantined and no
   unverified content is injected.
5. **Given** an unavailable local memory service or an invalid ledger, **When**
   a session starts, **Then** Codex continues without Verity-provided memory and
   receives a content-free health warning.

**Security Test Matrix**: Benign fact, malicious persistent instruction,
benign quoted false positive, semantic/daemon failure, next-session exclusion,
and invalid-ledger injection denial are all required P1 cases.

---

### User Story 2 - Understand Every Memory Decision (Priority: P2)

As a developer or security operator, I need to see where a memory came from and
why it was allowed, redacted, quarantined, blocked, approved, or revoked.

**Why this priority**: Security decisions that cannot be explained or traced
cannot be tuned, reviewed, or credibly demonstrated.

**Independent Test**: Open a candidate detail view after an evaluation and
trace it from safe content representation through evidence, detectors,
semantic assessment, policy, actions, events, and ledger verification.

**Acceptance Scenarios**:

1. **Given** any evaluated candidate, **When** an operator opens its detail,
   **Then** the safe representation, namespace, kind, source, session, task,
   evidence reference and digest, detector results, semantic provider state,
   policy rule and version, actual action, would-have action, event IDs, and
   chain status are visible where applicable.
2. **Given** candidate content containing a synthetic credential, **When** it is
   listed or inspected, **Then** the raw credential is absent from list views,
   telemetry, model-bound evidence, and screenshots.
3. **Given** a detector or semantic provider failure, **When** an operator
   inspects the decision, **Then** the failed component and fallback action are
   explicit rather than represented as a clean pass.

**Security Test Matrix**: Inspect benign and malicious decisions, a benign
quoted false positive, a failed component, cross-session provenance, and a
tampered-chain status; every view must remain content-safe.

---

### User Story 3 - Revoke Previously Trusted Memory (Priority: P3)

As a security operator, I need to revoke one previously committed memory and
reconstruct the active memory view without deleting unrelated knowledge.

**Why this priority**: Detection improves over time; durable trust must be
selectively reversible without destructive history edits.

**Independent Test**: Commit several legitimate memories and one shadow-admitted
malicious memory, revoke the malicious event, rebuild, and compare the result.

**Acceptance Scenarios**:

1. **Given** several legitimate active memories and one malicious memory
   admitted in shadow mode, **When** the operator revokes the malicious memory
   with a reason, **Then** a new revocation event is appended, the malicious
   memory disappears after replay, and unrelated memories remain.
2. **Given** a revoked memory and intact event history, **When** the active view
   is rebuilt, **Then** the rebuilt view is deterministic and matches the stored
   materialized view.
3. **Given** a stale materialized view that still contains revoked memory,
   **When** consistency is checked, **Then** injection is disabled until rebuild
   removes the stale entry.

**Security Test Matrix**: Cover legitimate memory preservation, malicious
target revocation, a false-positive preview cancelled without mutation,
transaction failure, later-session exclusion, and tampered-history refusal.

---

### User Story 4 - Evaluate Safely in Shadow Mode (Priority: P4)

As a team evaluating Verity Cordon, I need to observe what enforcement would do
without immediately disrupting Codex workflows.

**Why this priority**: Teams need honest, low-risk policy tuning before enabling
enforcement.

**Independent Test**: Evaluate the same synthetic attack in shadow and enforce
modes and compare recorded and applied actions.

**Acceptance Scenarios**:

1. **Given** a policy in shadow mode, **When** a malicious candidate would be
   quarantined, **Then** the configured shadow action is recorded as the actual
   action, quarantine is recorded as the would-have action, and the admitted
   memory is visibly labeled as shadow-admitted.
2. **Given** a shadow-admitted malicious memory, **When** a later enforcement
   policy identifies it, **Then** it can be rescanned and selectively revoked.
3. **Given** the Control Room in shadow mode, **When** an operator views status,
   **Then** the interface does not present shadow evaluation as active
   protection.

**Security Test Matrix**: Cover benign parity, malicious action divergence, a
false-positive candidate, semantic failure fallback, cross-session
shadow-admission labeling, and decision-event tamper detection.

**Implemented scope**: A confirmed targeted rescan loads one active memory's
verified candidate history, derives and signs a fresh sanitized rescan
candidate, runs the current detector/semantic/policy path, and atomically
appends a revocation when the enforcement action is unsafe. The offline demo
uses this path for the earlier shadow admission. Policy activation does not
automatically discover or sweep every historical memory.

---

### User Story 5 - Verify Ledger Integrity (Priority: P5)

As an operator or judge, I need a straightforward way to verify that covered
memory-security events and their bound payloads have not been altered,
reordered, omitted relative to a trusted expected head, or signed by an
unexpected key.

**Why this priority**: Tamper evidence is a central product claim and must be
independently checkable.

**Independent Test**: Verify an intact ledger against its signed expected-head
sidecar, then separately alter a payload, alter an event, reorder events, remove
an event, and corrupt a signature. Verify that the same chain without an
expected head reports terminal completeness as unproven.

**Acceptance Scenarios**:

1. **Given** an intact event history and materialized view, **When** verification
   runs, **Then** sequence, previous-event links, event digests, payload digests,
   signatures, key identifiers, and view consistency all pass.
2. **Given** any covered tampering case, **When** verification runs, **Then** it
   fails, identifies the first invalid event or view mismatch, disables new
   commits and memory injection, and preserves safe read-only audit access.
3. **Given** the installation public key, **When** a judge independently verifies
   an exported event, **Then** the documented canonical representation and
   signature procedure reproduce the stored result.
4. **Given** a self-contained chain with no expected head or external
   checkpoint, **When** verification runs, **Then** covered records may pass
   cryptographic checks but the overall result is not fully verified and tail
   completeness is explicitly `unproven`.

**Security Test Matrix**: Cover an intact benign chain, each malicious mutation,
equivalent-serialization false positives, key/storage failure, an expected-head
check across sessions, and payload/order/omission/signature/view tampering.

---

### User Story 6 - Transactional Streaming Memory Writes (Priority: P6)

As an agent integration developer, I need streamed candidate memory to remain
uncommitted until it has passed incremental and final evaluation.

**Why this priority**: A partial write must never bypass the policy boundary,
including when malicious text is split across chunks.

**Independent Test**: Begin isolated streams, append split attack fragments,
abort or commit them, and inspect active memory and audit history.

**Acceptance Scenarios**:

1. **Given** an open stream, **When** chunks are appended, **Then** no chunk is
   visible as active memory before successful commit.
2. **Given** an attack divided across chunk boundaries, **When** incremental and
   final evaluation run, **Then** the combined attack is detected and no partial
   content commits.
3. **Given** an aborted, blocked, cancelled, oversized, or timed-out stream,
   **When** a later commit is attempted, **Then** it is refused and an auditable
   outcome exists without active memory.
4. **Given** concurrent streams, **When** one fails and another succeeds, **Then**
   their buffers and outcomes remain isolated.

**Security Test Matrix**: Cover a benign stream, split malicious stream, benign
quoted attack text, cancellation/storage failure, next-session visibility only
after commit, and tampering with stream events.

---

### User Story 7 - Judge-Friendly Demonstration (Priority: P7)

As a hackathon judge, I need to run a representative demonstration in minutes
without a production Codex configuration, real secrets, or a mandatory API key.

**Why this priority**: A reproducible, coherent experience is required for
judging and prevents architectural promises from substituting for a product.

**Independent Test**: Start from a clean checkout, run the documented offline
path, inspect the Control Room, reproduce shadow, enforce, revoke, rebuild, and
verify flows, then optionally run the explicitly labeled live path.

**Acceptance Scenarios**:

1. **Given** a clean checkout with supported local runtimes, **When** the judge
   runs the offline demo path, **Then** real evidence, policy, ledger,
   materialization, API, and UI code run using recorded semantic fixtures and no
   OpenAI key.
2. **Given** a configured OpenAI key, **When** live mode runs, **Then** the
   verified GPT-5.6 model performs structured extraction and risk assessment,
   its provider state is visible, and deterministic policy retains final
   authority.
3. **Given** an unavailable live provider, **When** live mode runs, **Then** it
   fails safely and never silently substitutes a fixture.
4. **Given** the synthetic poisoned documentation tool, **When** it runs, **Then**
   it uses bounded stdin/stdout only, opens no network listener, reads no real
   environment values, sends no network traffic externally, and clearly
   identifies itself as inert demo code.

**Offline integration note**: The deterministic demo invokes the real stdio
fixture and calls `MemoryService.session_start_context` to assert approved-only
rendering. It labels that result as a simulated `SessionStart`; it does not
claim to launch Codex. The installed hook boundary is exercised separately by
contract tests and isolated Codex CLI verification.

**Security Test Matrix**: The judge path includes benign seed data, the
malicious tool fixture, a false-positive trap, offline/live dependency failure,
cross-session injection behavior, and an isolated ledger-tamper demonstration.

### Edge Cases

- Two concurrent event appends contend for the next sequence number.
- Storage fails after evaluation but before atomic event and view commit.
- A detector exceeds its deadline, raises, returns malformed evidence, or uses
  a duplicate identifier.
- Semantic output is late, malformed, schema-invalid, or unavailable.
- A policy is malformed, missing, downgraded, or changes between evaluation and
  commit.
- A candidate is oversized, empty, Unicode-normalization-sensitive, encoded,
  indirect, self-reinforcing, or split across stream chunks.
- A candidate quotes malicious text benignly or discusses prompt injection.
- A direct user preference contains a credential or high-risk instruction.
- An instruction is hidden inside a fact or tool-observation field.
- A historical payload, event, signature, order, or chain link is modified.
- A prior policy allowed memory that a new policy blocks.
- The materialized view is stale, unavailable, or inconsistent with replay.
- The signing key is missing or has unsafe permissions.
- The local daemon is unavailable when a session starts or stops.
- The UI loses API connectivity during a review or revocation action.
- The memory injection budget cannot fit every approved item.

## Requirements

### Functional Requirements

- **FR-001**: Every proposed durable memory MUST be captured as evidence and
  evaluated before it can become active or be supplied to a future session.
- **FR-002**: Candidate memories MUST be atomic, attributable, typed, namespaced,
  and linked to source, session, task, evidence, extractor, detector, semantic,
  and policy versions where applicable.
- **FR-003**: Deterministic detectors MUST cover credential material, persistence
  attempts, protected namespaces, cross-task contamination, self-reinforcement,
  untrusted authority claims, anomalous size, and concealed-instruction patterns.
- **FR-004**: Detected credentials and obvious secrets MUST be replaced with
  typed placeholders before any model-bound request and excluded from default
  telemetry and UI list views.
- **FR-005**: Candidate extraction and semantic risk assessment MUST be distinct,
  schema-constrained functions, and semantic recommendations MUST NOT directly
  grant durable trust.
- **FR-006**: A versioned deterministic policy MUST choose allow, redact,
  quarantine, or block from source, namespace, kind, detector, semantic,
  sensitivity, mode, and failure inputs.
- **FR-007**: Enforcement mode MUST apply the computed action. Shadow mode MUST
  record both `actual_action` and `would_have_action`, label admitted content as
  shadow-admitted, and MUST NOT be described as active protection.
- **FR-008**: The system MUST maintain an append-only security event history in
  which corrections are represented by new events rather than edits or
  deletions; due TTLs MUST become explicit expiration events before they affect
  replay or injection.
- **FR-009**: Each persisted event MUST bind its canonical envelope, prior event,
  exact payload digest, signature, and signing-key identifier.
- **FR-010**: Operators MUST be able to verify event order, chain links, event
  digests, payload digests, signatures, key identifiers, and materialized-view
  consistency, with the first failure identified. Full verification MUST bind
  to a signed local expected head or supplied checkpoint; without one, terminal
  completeness MUST be reported as unproven.
- **FR-011**: Active memory MUST be derived deterministically from committed,
  eligible events and exclude blocked, quarantined, revoked, superseded,
  expired, or invalid memories.
- **FR-012**: Operators MUST be able to revoke one committed memory by appending
  a reasoned event, preview the impact, rebuild the view, and preserve unrelated
  active memories and historical evidence.
- **FR-013**: Streamed writes MUST support begin, append, commit, and abort;
  remain invisible before commit; detect cross-chunk attacks; enforce resource
  limits; and prohibit double or post-abort commit.
- **FR-014**: Detector execution MUST support concurrent fan-out, bounded
  deadlines, cancellation, error isolation, deterministic aggregation, and
  explicit failure findings.
- **FR-015**: The product MUST expose a loopback-only local service and Memory
  Control Room with overview, inventory, timeline, detail, quarantine,
  revocation, policy, and ledger-verification views backed by real system state.
- **FR-016**: Manual approve, block, and revoke actions MUST require confirmation,
  actor identity, and a reason, and MUST append auditable events.
- **FR-017**: Approved memory supplied to Codex MUST be delimited, typed,
  provenance-aware, and accompanied by instructions that facts and tool
  observations are not higher-priority authority. The rendered UTF-8 byte
  length MUST NOT exceed the configured `injection_token_budget`; this is a
  conservative token-count upper bound rather than an exact model tokenizer.
  Whole records that do not fit MUST be omitted, never truncated.
- **FR-018**: The Codex integration MUST use current documented memory controls
  and lifecycle hooks, disable native memory generation and use for the
  controlled demo plane, and MUST NOT edit Codex-generated memory files as its
  primary control mechanism.
- **FR-019**: The thin Codex adapter MUST use bounded local requests, contain no
  policy logic, perform no model loading or remote database work, write no
  active memory directly, and inject no unverified evidence.
- **FR-020**: Operators MUST be able to validate, inspect, and activate local
  policies; invalid policy MUST fail closed for new commits; activation MUST be
  recorded; rejected activation MUST append a content-safe failure event when
  the ledger is available; and last-known-good behavior MUST be explicit.
- **FR-021**: The product MUST provide working health, status, policy, memory,
  revocation, rebuild, signing-key initialization, ledger verification,
  public-key export, offline demo, and live demo operator paths without
  placeholder success responses.
- **FR-022**: The offline demo MUST require no API key and exercise real policy,
  ledger, memory view, service, and UI code using deterministic semantic
  fixtures.
- **FR-023**: The live demo MUST use the current verified GPT-5.6 model and
  structured outputs, clearly label live results, bound retries and timeouts,
  and fail safely without silent fixture fallback.
- **FR-024**: The synthetic poisoned-tool fixture MUST use bounded stdio only,
  open no network listener, use only synthetic values, read no real process
  environment, make no external request, and document its inert purpose.
- **FR-025**: Privacy-safe statistics MUST report decision counts, revocations,
  semantic timeouts, detector failures, ledger state, and evaluation latency
  without raw memory or prompt content.
- **FR-026**: Detector plugin discovery MUST reject duplicate IDs, isolate plugin
  failures, retain deterministic ordering, and include one bounded reference
  plugin only if it does not destabilize the vertical slice.
- **FR-027**: The project MUST include a clean-checkout judge path, supported
  platforms, install instructions, security limitations, threat model, donor
  comparison, hackathon work boundary, Codex collaboration record, submission
  draft, and sub-three-minute demo script.

### Security and Failure Requirements

- **SFR-001**: No dependency failure, malformed output, hook failure, or service
  outage may cause unverified memory to be committed or injected.
- **SFR-002**: Ledger verification failure MUST disable injection and new commits,
  expose a critical state, and retain safe read-only audit access. Startup with
  an invalid ledger MUST NOT load detector plugins or treat a fallback policy as
  validated; any policy summary used to render the degraded UI MUST be labeled
  invalid and MUST NOT authorize writes or injection.
- **SFR-003**: High-risk ambiguous candidates MUST default to quarantine after
  detector or semantic failure; lower-risk fallback requires explicit policy.
- **SFR-004**: New commits MUST fail closed when the active policy is invalid;
  policy failure MUST be visible and auditable. A rejected proposed policy MAY
  leave an intact last-known-good policy active, but no valid policy means no
  commit and no injection.
- **SFR-005**: Private signing material, API keys, credentials, raw secrets, and
  unsafe development logs MUST be absent from the repository and default output.
- **SFR-006**: The signing-key threat boundary, local-host assumptions,
  canonicalization, algorithms, key identifier, and verification procedure MUST
  be documented and test-backed.
- **SFR-007**: The Control Room MUST bind to loopback by default, use accessible
  interaction states, and require confirmation for trust-changing actions.
- **SFR-008**: All in-scope abuse cases in the threat model MUST map to a control,
  test or documented residual risk.
- **SFR-009**: The MVP MUST NOT retain original evidence bytes. It MUST bind
  their digest, keep only a bounded pattern-sanitized excerpt in permanent
  capture history, bound and purge the transient full sanitized queue body, and
  use content-safe representations for routine operator views. Sanitizer false
  negatives MUST remain an explicit residual risk.
- **SFR-010**: A fully compromised host, compromised user account or signing
  key, malicious OS or Codex binary, hardware attack, remote multi-tenant attack,
  perfect factual truth determination, and side-channel resistance MUST remain
  explicit non-goals.

### Public Claim Requirements

- **CR-001**: Public materials MAY claim tamper-evident memory history,
  verifiable provenance, versioned policy enforcement, explicit trust decisions,
  selective revocation, view reconstruction, shadow evaluation, demonstrated
  cross-session protection, and a controlled Codex memory plane.
- **CR-002**: Public materials MUST NOT claim impenetrability, tamper-proof
  storage, factual truth verification, complete prompt-injection prevention,
  undocumented interception, protection from a fully compromised host or
  malicious Codex binary, untested framework support, unsupported enterprise
  readiness, or that signatures prove factual correctness.

### Key Entities

- **Evidence**: Locally captured source material with source class, session,
  task, safe representation, digest, retention state, and capture time.
- **Memory Candidate**: Atomic proposed durable knowledge with namespace, kind,
  statement, sensitivity, source references, confidence, rationale, requested
  lifetime, extractor version, and creation time.
- **Detector Result**: Versioned deterministic finding with match state,
  severity, confidence, categories, safe references, metadata, and failure state.
- **Semantic Assessment**: Schema-validated risk recommendation with provider
  state, model, prompt version, categories, scores, rationale, and disposition.
- **Policy**: Versioned validated rules, mode, actions, thresholds, protected
  namespaces, failure behavior, review requirements, and content digest.
- **Policy Decision**: Computed actual and would-have actions with matched rule,
  policy version, mode, inputs, and reason.
- **Ledger Event**: Ordered signed security record binding its canonical fields,
  payload digest, prior event, actor, policy context, and signing key.
- **Active Memory**: Materialized eligible memory derived from ledger history.
- **Quarantined Memory**: Ineligible candidate awaiting review or final block.
- **Stream**: Isolated transactional candidate buffer with lifecycle, limits,
  state, and auditable outcome.
- **Signing Key**: Per-installation Ed25519 identity represented publicly by key
  ID and fingerprint; the private component never enters Git.

## Clarifications

### Session 2026-07-15

- The final formal clarification pass found no unresolved
  `[NEEDS CLARIFICATION]` markers and no material ambiguity that required an
  operator decision before implementation.
- The directive already fixed the active feature, threat boundary, supported
  platform claim, local-only architecture, donor relationship, public-claim
  limits, and scope-cut order. Implementation assumptions that did not alter
  ownership or public claims are recorded in this specification, the plan,
  research, ADRs, and threat model.

## Non-Goals

The active feature excludes general LLM proxying, non-Codex agent adapters,
hosted multi-tenant service, enterprise identity or RBAC, remote policy
distribution, SIEM integrations, production HSM or key lifecycle, distributed
consensus, cross-host federation, detector marketplace, arbitrary factual
verification, undocumented Codex patching, OWASP repository reorganization,
full local model packaging, public SaaS deployment, and production compliance
certification.

## Success Criteria

### Measurable Outcomes

- **SC-001**: In the curated evaluation fixtures, every explicit and indirect
  persistent-instruction attack is quarantined or blocked in enforce mode, with
  false positives and false negatives reported rather than generalized.
- **SC-002**: A new session receives all eligible seeded memory and none of the
  blocked, quarantined, revoked, superseded, expired, or invalid seeded memory.
- **SC-003**: Revoking one seeded malicious memory and rebuilding preserves 100%
  of unrelated eligible seeded memories and removes the target.
- **SC-004**: Every covered payload alteration, event alteration, reordering,
  interior omission, expected-head-relative terminal omission, invalid
  signature, and stale-view fixture causes verification to fail at the first
  attributable inconsistency; an unanchored tail is reported as unproven rather
  than complete.
- **SC-005**: No synthetic secret value from the adversarial fixtures appears in
  model-bound content, routine logs, telemetry attributes, list views, or demo
  screenshots.
- **SC-006**: Every shadow decision exposes mode, actual action, would-have
  action, policy version, detector findings, and semantic assessment reference
  when used.
- **SC-007**: The offline demonstration completes shadow admission,
  enforcement, session injection, revocation, rebuild, and ledger verification
  from a clean setup with no API key.
- **SC-008**: A judge can reach a working product state using the top-level
  quickstart in no more than five documented commands and without rebuilding
  the architecture from source concepts.
- **SC-009**: All trust-changing Control Room actions are keyboard reachable,
  require confirmation, and show their recorded outcome without console errors
  at a common desktop viewport.
- **SC-010**: The critical verification suite completes within five minutes on
  a supported developer laptop, excluding optional live-model latency.
- **SC-011**: At least 95% of deterministic candidate evaluations in the bundled
  fixture dataset complete within 250 milliseconds on a supported developer
  laptop; results are labeled fixture-specific.
- **SC-012**: The final repository passes formatting, lint, type, unit, contract,
  integration, adversarial, end-to-end, frontend build, accessibility smoke,
  console, and clean-checkout demo gates, or each non-passing gate is accurately
  disclosed.

## Assumptions

- The exercised judge platform is macOS with Python 3.12+ and a compatible
  Node.js runtime. Linux is an intended local target but is not yet recorded as
  exercised; Windows is unverified.
- SQLite is sufficient for the single-user local demonstration and remains the
  authoritative local event store for this feature.
- Codex local memories remain disabled for the controlled demo plane; operators
  explicitly review and trust installed project hooks.
- The documented Codex `SessionStart` hook is the supported injection point;
  the product does not claim a native memory read/write interception hook.
- GPT-5.6 access and an OpenAI API key are optional for live mode and unnecessary
  for offline judging.
- Synthetic data is sufficient to demonstrate secret handling and exfiltration
  intent without exposing real credentials.
- The operator will record the real `/feedback` Session ID and upload the final
  public YouTube video; neither value may be fabricated.
- Verity Cordon is new work begun during the Build Week submission period; the
  donor project is prior art rather than a renamed baseline.
- Deferred capabilities may be promoted only through the constitution's numbered
  Spec Kit feature process and must remain absent from this feature's tasks.
