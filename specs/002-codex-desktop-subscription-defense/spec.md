# Feature Specification: Codex Desktop Subscription Defense

**Feature Branch**: `codex/002-desktop-subscription-defense`

**Created**: 2026-07-15

**Status**: Implementation complete; timed operator-observed Desktop acceptance rehearsal pending

**Input**: User description: "Use the Codex subscription model, make the Codex
Desktop app the main demo, and demonstrate the defense with a Trojan
Hippo-inspired persistent-memory poisoning attack."

**Surface terminology**: In this feature, **Codex Desktop** is concise project
shorthand for the Codex experience in the supported ChatGPT desktop app. It
does not name a separate Verity runtime or imply access to undocumented Desktop
internals.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Stop a delayed attack in Codex Desktop (Priority: P1)

As a developer using Codex Desktop, I want Verity Cordon to identify and
quarantine a dormant operational instruction hidden in an otherwise useful tool
response so it cannot silently influence a later task.

**Why this priority**: This is the sprint's judge-facing vertical slice and the
clearest demonstration of cross-session memory risk and defense.

**Independent Test**: Use the local synthetic documentation tool from a Codex
Desktop task, wait for the resulting memory decision, and start a fresh task.
The useful project fact is available, the delayed instruction is absent, and
the Control Room shows its provenance and quarantine decision.

**Acceptance Scenarios**:

1. **Given** enforcement mode and a local documentation response containing
   legitimate release guidance plus a concealed permanent instruction, **When**
   Codex observes the tool response, **Then** Verity captures its external-tool
   provenance and quarantines or blocks the operational instruction.
2. **Given** one approved benign project fact and one quarantined poisoned
   candidate, **When** a fresh Codex Desktop task starts, **Then** only the
   eligible approved fact appears in Verity-provided memory.
3. **Given** documentation that discusses memory poisoning as quoted security
   education without requesting persistence or authority, **When** it is
   evaluated, **Then** the decision is distinguishable from the malicious case
   and the false-positive outcome is recorded.
4. **Given** the daemon, policy, ledger, or materialized view is unhealthy,
   **When** a Desktop task starts, **Then** no Verity memory is injected and a
   content-free degraded-state warning is available.

---

### User Story 2 - Use a Codex subscription for semantic review (Priority: P2)

As a local Codex subscriber, I want an explicit semantic-provider option that
uses my supported Codex sign-in so I can exercise live semantic review without
configuring a separate OpenAI API key.

**Why this priority**: It makes the live demonstration accessible to Codex
subscribers while preserving the existing offline and direct API paths.

**Independent Test**: With no OpenAI API key present and a supported Codex
subscription sign-in available, select subscription mode and evaluate sanitized
synthetic evidence. The decision records the subscription provider distinctly,
and deterministic policy retains final authority.

**Acceptance Scenarios**:

1. **Given** an authenticated local Codex subscription and no OpenAI API key,
   **When** sanitized synthetic evidence is evaluated in subscription mode,
   **Then** a schema-valid assessment is recorded as subscription-backed and
   supplied only as advisory policy input.
2. **Given** subscription mode, **When** authentication is absent, usage is
   unavailable, execution times out, output is malformed, output exceeds a
   bound, or agent tool activity is observed, **Then** the evaluation fails
   explicitly, no fixture or API provider is substituted, and high-risk memory
   is quarantined.
3. **Given** a subscription-backed assessment, **When** an operator views its
   detail, **Then** the UI distinguishes it from both the direct no-tools API
   provider and recorded fixtures and displays the reduced-isolation warning.
4. **Given** a configured direct OpenAI API provider or offline fixture
   provider, **When** the sprint is installed, **Then** their prior behavior and
   labels remain available and unchanged.

---

### User Story 3 - Demonstrate shadow admission and selective recovery (Priority: P3)

As a security operator, I want to show how a delayed poison can be observed in
shadow mode, removed later, and audited without deleting unrelated memory.

**Why this priority**: Shadow evaluation and selective revocation make the
product's value broader than one-time blocking.

**Independent Test**: Admit the synthetic attack under shadow mode, demonstrate
only a simulated delayed influence using synthetic data, switch to enforcement,
revoke the admitted memory, rebuild the view, and verify the ledger.

**Acceptance Scenarios**:

1. **Given** shadow mode, **When** the synthetic poisoned candidate is
   evaluated, **Then** `actual_action` records the configured shadow admission,
   `would_have_action` records quarantine or block, and the UI states that
   shadow mode is not active protection.
2. **Given** the shadow-admitted memory and a later synthetic release task,
   **When** the delayed trigger is demonstrated, **Then** any attempted sink
   action remains local and inert and contains only allow-listed synthetic
   markers.
3. **Given** a newly enforced policy, **When** the operator revokes and replays
   the shadow-admitted memory, **Then** that memory leaves the active view,
   unrelated approved memory remains, and the signed ledger verifies.

---

### User Story 4 - Run a judge-ready Desktop demonstration (Priority: P4)

As a hackathon judge or evaluator, I want a short, reversible setup that makes
the Codex Desktop flow primary while retaining a deterministic command-line
fallback.

**Why this priority**: The primary demo should feel native to Codex Desktop
without sacrificing reproducibility when a judge cannot configure the app.

**Independent Test**: Preview and apply the dedicated demo setup, start a new
Desktop task, complete the documented attack-and-defense sequence, then remove
the fixture without changing unrelated Codex configuration or Verity history.

**Acceptance Scenarios**:

1. **Given** a supported local Codex installation, **When** the operator
   previews Desktop demo setup, **Then** the exact demo-only fixture change is
   shown before confirmation and any normal-integration readiness failure
   directs the operator to run the separate `verity install-codex` preview.
2. **Given** confirmed setup, **When** the operator starts a new Desktop task,
   **Then** the Verity plugin and the explicitly installed synthetic demo tool
   are available through documented Codex surfaces.
3. **Given** completed or partially completed setup, **When** teardown is
   confirmed, **Then** demo-only integration is removed safely, unrelated Codex
   settings remain, and the Verity ledger is preserved.
4. **Given** Desktop is unavailable, **When** the evaluator runs the offline
   fallback, **Then** the same policy, ledger, memory-view, revocation, and UI
   paths remain testable without an API key.

### Edge Cases

- A subscription child process inherits the parent environment or installed
  Verity hooks and attempts to re-enter the evidence pipeline.
- The operator is signed into Codex with usage-based API credentials rather
  than ChatGPT subscription authentication.
- A model response is valid JSON but contains the wrong candidate identity,
  content digest, provider label, or schema version.
- The semantic child emits a tool event before a final response.
- The local Codex executable changes between setup, doctor, and evaluation.
- The Desktop task begins before asynchronous evaluation of captured evidence
  reaches a terminal signed outcome.
- Demo setup is interrupted after one configuration mutation but before its
  receipt is complete.
- Demo teardown is interrupted after its receipt enters `removing`, or a later
  setup encounters a prior `removed` receipt/archive.
- Codex Desktop or another non-cooperating writer changes the user-wide config
  while a confirmed operation is running.
- The synthetic sink receives unexpected content, a non-synthetic value, or a
  request to read local files or process environment data.
- Subscription usage is rate limited or exhausted during a live demonstration.
- Historical events created before the new provider label are replayed after
  the additive contract change.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The product MUST present Codex Desktop as the primary interactive
  demonstration surface while preserving CLI as a secondary deterministic
  harness.
- **FR-002**: The existing Verity plugin MUST support the Desktop and CLI flows
  through documented Codex plugin, hook, MCP, memory-control, and configuration
  surfaces only.
- **FR-003**: The sprint MUST provide an original synthetic delayed-trigger
  memory-poisoning scenario inspired by the Trojan Hippo attack model.
- **FR-004**: The synthetic scenario MUST use only fixed, visibly synthetic
  values; it MUST NOT read real email, files, environment variables,
  credentials, personal data, or external services.
- **FR-005**: The demo sink MUST remain local and inert, accept only an
  allow-listed synthetic payload, record only safe metadata, and have no
  external transmission capability.
- **FR-006**: The poisoned tool response MUST contain both a useful benign fact
  and a dormant operational instruction so the demonstration proves selective
  trust rather than wholesale rejection.
- **FR-007**: Captured Desktop tool evidence MUST retain source class, session,
  task, tool identity, safe evidence reference, digest, detector findings,
  semantic state, policy version, and final action.
- **FR-008**: The system MUST expose an explicit `codex_subscription` semantic
  provider that uses supported local Codex authentication without requiring an
  `OPENAI_API_KEY`.
- **FR-009**: Provider selection MUST be explicit. The system MUST NOT silently
  substitute fixture, direct API, or subscription providers for one another.
- **FR-010**: Subscription-backed decisions MUST be labeled distinctly from
  direct OpenAI API, recorded fixture, deterministic-only, and failed semantic
  decisions throughout contracts, ledger payloads, replay, API responses, CLI,
  evaluations, and UI.
- **FR-011**: The subscription provider MUST use bounded sanitized input,
  ephemeral execution, an isolated working context, a minimal environment,
  disabled web search, disabled durable memory, disabled hooks and plugins,
  strict structured output, a strict deadline, and bounded output capture.
- **FR-012**: Subscription authentication checks MUST use supported status
  surfaces and MUST NOT read, copy, parse, print, or persist Codex credential
  files or bearer tokens.
- **FR-013**: Subscription output MUST pass the same schema, identity, digest,
  length, sanitization, and deterministic-policy checks as other semantic
  providers.
- **FR-014**: Any observed or attempted semantic-child tool activity MUST make
  the subscription assessment fail; the provider MUST NOT claim that the
  underlying Codex runtime is tool-free.
- **FR-015**: A defense-in-depth recursion guard MUST prevent semantic child
  execution from producing new Verity hook evidence even if installed hooks are
  unexpectedly loaded.
- **FR-016**: Semantic failure in a high-risk namespace MUST produce an explicit
  failure finding and quarantine outcome according to versioned policy.
- **FR-017**: Deterministic versioned policy MUST retain final authority for
  subscription-backed assessments.
- **FR-018**: The Control Room MUST show provider identity, isolation class,
  authentication readiness without credential content, terminal evaluation
  state, actual action, would-have action, and a neutral decision-and-recovery
  timeline that identifies delayed-attack effects when they are actually present.
- **FR-019**: The Desktop flow MUST wait for or visibly report a terminal signed
  evidence outcome before claiming that a fresh task is protected.
- **FR-020**: Demo-only MCP or tool setup MUST be separate from normal product
  installation, previewable, confirmation-gated, receipt-bound, drift-aware,
  and reversible. Mutation MUST require the exact digest from a separately
  reviewed preview and an explicit operator hook-trust assertion.
- **FR-021**: Desktop setup and teardown MUST preserve unrelated Codex
  configuration and MUST preserve the Verity ledger, signing key, and memory
  history.
- **FR-022**: Shadow mode MUST record both actual and would-have actions and MUST
  not be described as active protection.
- **FR-023**: Revocation and replay MUST remove only the selected poisoned memory
  and preserve unrelated approved memory.
- **FR-024**: The existing fixture and direct OpenAI API semantic paths MUST
  remain supported and retain their existing security labels.
- **FR-025**: Documentation MUST identify the benchmark repository, exact
  inspected commit, license, inspection date, and primary paper while stating
  that the demo is an original synthetic scenario rather than a benchmark
  reproduction.
- **FR-026**: Protection and performance claims MUST be limited to tests and the
  included evaluation fixtures; paper-reported attack rates MUST not be
  presented as Verity results.

### Security and Failure Requirements

- **SFR-001**: Every path that captures, evaluates, admits, injects, revokes, or
  demonstrates poisoned memory MUST retain deterministic policy authority and
  append-only provenance.
- **SFR-002**: The specification MUST define safe behavior for missing Codex,
  unsupported authentication, rate limits, timeout, cancellation, malformed or
  oversized output, observed tool activity, child-process termination, daemon
  outage, invalid policy, corrupted history, stale view, and interrupted demo
  setup or teardown.
- **SFR-003**: The subscription provider MUST be documented as a lower-isolation
  agentic provider and MUST NOT inherit the direct API provider's `no tools` or
  request-storage claims.
- **SFR-004**: Secret screening MUST run before any subscription or direct API
  request, and raw evidence, credential material, child output, and auth state
  MUST be excluded from routine logs, telemetry, screenshots, and Git.
- **SFR-005**: Child execution MUST use fixed argument vectors without a shell,
  an executable resolved from a trusted path, restrictive temporary-file
  permissions, bounded process cleanup, and explicit descendant termination.
- **SFR-006**: The recursion guard MUST be enforced by both provider launch and
  hook-adapter behavior and MUST be covered by an adversarial test.
- **SFR-007**: The synthetic fixture and sink MUST bind only to loopback or use
  bounded stdio, MUST NOT inspect the host environment, and MUST reject any
  non-synthetic payload.
- **SFR-008**: Historical provider-state additions MUST remain replay-compatible
  and MUST NOT invalidate prior signed events or materialized views.
- **SFR-009**: Every security-sensitive story MUST include benign, malicious,
  false-positive, dependency-failure, cross-session, and tamper coverage where
  applicable.
- **SFR-010**: Desktop documentation MUST state that the exercised
  `$CODEX_HOME/config.toml` MCP entry is user-wide, not project-local. Confirmed
  operations MUST serialize cooperating Verity mutations, reject expected-head
  drift, recover only exact `prepared`/`removing` states, and leave the
  non-cooperating-writer race explicit.

### Key Entities

- **Semantic Provider Identity**: The requested provider, actual provider state,
  isolation class, requested model, returned model when verifiable, prompt and
  schema versions, timing, and explicit failure class.
- **Desktop Demo Installation**: The reviewed demo-only configuration scope,
  original values, staged artifact digests, runtime identity, confirmation,
  preview digest, receipt version, write-ahead state, archived removed receipt,
  and teardown state.
- **Delayed Attack Scenario**: The synthetic benign fact, dormant instruction,
  trigger, safe sink marker, source provenance, expected policy outcome, and
  attribution metadata.
- **Evidence Evaluation State**: The durable progression from capture through
  pending evaluation to a signed terminal decision or explicit failure.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An operator can complete the edited Desktop attack, enforcement,
  clean-task, revocation, and ledger-verification narrative in under three
  minutes excluding installation and pre-recorded loading time.
- **SC-002**: Every included malicious delayed-trigger fixture is quarantined or
  blocked in enforcement mode, and every included false-positive fixture has a
  recorded, reviewable outcome without being misrepresented as an attack.
- **SC-003**: With supported ChatGPT subscription authentication and no OpenAI
  API key, subscription mode can produce a schema-valid advisory assessment or
  an explicit content-safe failure without switching providers.
- **SC-004**: All tested subscription failure modes result in no new active
  high-risk memory and no Verity-provided injection of the affected candidate.
- **SC-005**: A fresh Desktop task receives all eligible benign demo memories
  and zero blocked, quarantined, revoked, expired, or superseded demo memories.
- **SC-006**: Revoking the shadow-admitted attack removes exactly that memory,
  preserves all unrelated approved demo memories, and leaves the ledger and
  rebuilt view verified.
- **SC-007**: Demo setup and teardown complete without changing any unrelated
  Codex configuration key in the tested installation fixture.
- **SC-008**: Automated privacy checks find no raw synthetic secret marker,
  credential, bearer token, auth-file content, or unredacted child output in
  generated runtime artifacts, routine logs, telemetry, ledger list views, UI
  snapshots, or evaluation reports. Designated source fixture, schema,
  contract, and test-definition files MAY contain the fixed synthetic marker
  literals they validate, but MUST contain no real secret.
- **SC-009**: The existing offline demo, direct API provider tests, ledger
  verification, and materialized-view rebuild tests remain passing.
- **SC-010**: Desktop-only observations are labeled as manual smoke evidence;
  automated harness results are not presented as proof of unautomated UI steps.

## Assumptions

- The primary exercised platform remains macOS with a current Codex Desktop app
  and local Codex runtime; Linux remains an intended secondary target and
  Windows remains unverified unless this sprint records otherwise.
- The exercised Codex `0.144.4` demo MCP configuration is user-wide in
  `$CODEX_HOME/config.toml`. A dedicated workspace and MCP `cwd` minimize
  exposure operationally but do not enforce project-local scope.
- A Desktop user may need a one-time supported Codex login even when already
  signed into another OpenAI surface; the product does not assume or copy
  credentials between products.
- Subscription access is subject to the user's plan, workspace policy, model
  availability, and usage limits and is not a general OpenAI API credential.
- The direct OpenAI API provider remains the strongest demonstrated semantic
  isolation path because it explicitly uses no tools.
- The original offline demonstration remains the guaranteed no-key judge path.
- The benchmark and paper are prior art and research sources only; all sprint
  attack content and synthetic data are authored for Verity Cordon.

## Scope Boundaries

- No automation or scraping of the Codex Desktop user interface.
- No real email, exfiltration, credential collection, environment inspection,
  public sink, or external transmission.
- No claim that subscription-backed Codex execution is tool-free.
- No full reproduction, vendoring, or performance comparison of the Trojan
  Hippo benchmark.
- No new agent framework, hosted service, multi-tenant control plane, outbound
  information-flow-control system, or public plugin-marketplace submission.
- No replacement or removal of the existing fixture or direct API providers.
