# Implementation Plan: Codex Memory Firewall

**Branch**: `feat/001-codex-memory-firewall` | **Date**: 2026-07-15 |
**Spec**: [spec.md](./spec.md)

**Input**: Feature specification from
`specs/001-codex-memory-firewall/spec.md`

## Summary

Build Verity Cordon as a local, async-first controlled memory plane for Codex.
Supported Codex hooks capture selected user/tool/turn evidence and inject only a
bounded, typed active-memory view at `SessionStart`. Evidence is sanitized,
split into atomic candidates, evaluated by deterministic detectors and an
optional isolated GPT-5.6 semantic provider, and decided by deterministic
versioned policy. Every lifecycle decision is appended to a signed SHA-256 and
Ed25519 event chain in SQLite; active memory is a rebuildable materialized view.
A loopback daemon, CLI, React Control Room, synthetic poisoned-tool fixture, and
offline fixture provider form the judge-ready vertical slice.

## Technical Context

**Language/Version**: Python 3.12-3.14; TypeScript 7; Node.js 22 LTS

**Primary Dependencies**: Pydantic 2.13, FastAPI 0.139, aiosqlite 0.22,
cryptography 49, OpenAI Python 2.45, Typer 0.26, Uvicorn 0.51,
OpenTelemetry API 1.43; React 19.2, Vite 8.1, Vitest 4.1

**Storage**: Local SQLite in WAL mode; restrictive local Ed25519 key file and
capability-token file outside Git; YAML policy validated by Pydantic

**Testing**: pytest, pytest-asyncio, pytest-cov, mypy, Ruff; Vitest, Testing
Library, axe-core; browser smoke verification against the built Control Room

**Target Platform**: macOS and Linux desktop/local Codex hosts; Windows is
documented as unverified unless exercised

**Project Type**: Installable Python daemon/CLI/Codex plugin with a local
single-page web application served by the daemon

**Performance Goals**: 95% of bundled deterministic fixture evaluations under
250 ms; critical verification suite under five minutes; hook client deadline
three seconds; UI interaction response under one second for bundled data

**Constraints**: Loopback-only by default; offline demo requires no API key;
secret scanning precedes remote calls; no undocumented Codex interception;
event and view writes are atomic; streamed content is invisible until commit;
security claims remain fixture- and threat-boundary-specific

**Scale/Scope**: Single local operator, tens to low thousands of events and
memories for the judge path, bounded concurrent candidate and stream evaluation;
no multi-tenant or distributed operation

## Constitution Check

*GATE: Passed before Phase 0 research. Re-checked after Phase 1 design.*

- [x] Untrusted memory cannot persist or inject before adjudication.
- [x] Provenance fields are captured before persistence.
- [x] History is append-only; revocation and reconstruction are event-driven.
- [x] Deterministic, versioned policy makes the final action decision.
- [x] Every dependency and integration failure mode is explicit and safe.
- [x] Telemetry excludes raw secrets and sensitive content by default.
- [x] Security and product claims map to acceptance tests and limitations.
- [x] Codex integration uses only documented, verified surfaces.
- [x] Adversarial, false-positive, failure, cross-session, and tamper tests are planned.
- [x] Deferred capabilities are absent from the active task graph.
- [x] Streamed writes remain invisible until complete final evaluation.
- [x] Canonicalization, hashing, signatures, keys, and verification are specified.

No constitution exception is required. The separate frontend is justified by
the required polished Control Room but is compiled to static assets and served
by the same loopback daemon, avoiding a second production service.

## Architecture

```text
Supported Codex lifecycle hook (thin command client)
        │ JSON over bounded loopback HTTP
        ▼
verityd / FastAPI on 127.0.0.1:8765
        │
        ├─ evidence capture and local secret sanitization
        ├─ candidate extractor (fixture or isolated GPT-5.6)
        ├─ concurrent deterministic detector bundle
        ├─ semantic risk assessor when policy requires it
        ├─ deterministic Pydantic policy engine
        ├─ VC-CJ-1 canonical event builder + Ed25519 signer
        ├─ SQLite append-only ledger + materialized views
        └─ privacy-safe spans, statistics, and Control Room API
                │
                └─ built React Control Room (same origin)
```

### Trust and authorization

- The daemon binds to `127.0.0.1:8765` by default and rejects unexpected Host
  and Origin values.
- Non-browser mutation clients require a locally generated bearer capability
  stored with restrictive permissions. The same-origin browser uses a separate
  short-lived passphrase challenge, server-managed HttpOnly, SameSite=Strict
  session, and in-memory CSRF header. The passphrase is collected through a
  non-echoing server prompt or secret environment input; the operator enters
  the same value into a dedicated browser password field that is cleared after
  local derivation. PBKDF2-HMAC-SHA256 proves possession without sending the
  passphrase over HTTP. The browser never receives the
  bearer capability or session cookie value. None of these values is logged or
  committed. Passphrases require at least 12 characters; challenges are
  limited to 20 per minute, one-time, and expire after 60 seconds; proof checks use constant-time
  comparison; five failures in five minutes trigger a five-minute global
  cooldown; and sessions expire after 15 minutes idle.
- Read endpoints never return raw retained evidence or credentials. The daemon
  may expose safe candidate representations, digests, IDs, and findings.
- The OpenAI API is outside the local trust boundary. Only sanitized, bounded
  evidence is sent with `store=False`, no tools, no prior response, and no
  durable memory.
- A semantic cache key includes sanitized digest and provenance-sensitive
  source, namespace, kind, session/task, persistence, authority, and secrecy
  inputs plus provider/prompt/schema versions; identical text from different
  trust contexts is not interchangeable.
- The signing key establishes tamper evidence only while the host, user account,
  and key remain uncompromised.

### Async protocols

The core defines runtime-checkable async protocols for `EventStore`,
`MemoryView`, `Detector`, `SemanticAdjudicator`, `CandidateExtractor`,
`PolicyProvider`, `EventSink`, `CodexAdapter`, `Clock`, and `KeyProvider`.
Outer CLI and hook commands may use `asyncio.run`; synchronous database and
network APIs are not exposed as the primary core interface.

Detectors execute in a bounded `asyncio.TaskGroup`. Each has a deadline and
failure isolation. Results are always sorted by detector ID and version before
policy evaluation so concurrency cannot change the decision input.

### Evidence and semantic flow

1. Validate source event, size, structure, and source class.
2. Persist a safe evidence record and digest through the ledger transaction.
3. Detect and redact obvious credentials before extraction or semantic calls.
4. Extract zero or more atomic candidates with fixture or live provider.
5. Run deterministic detectors concurrently.
6. Invoke semantic assessment only when the active policy requires it.
7. Apply deterministic policy to sanitized candidate and versioned findings.
8. Append decision and outcome events; atomically update eligible derived view.
9. Expose safe details and statistics; never log raw content by default.

### Ledger and materialization

- A single global event sequence starts at 1. The genesis previous hash is 64
  lowercase zero hexadecimal characters.
- `VC-CJ-1` canonical bytes are UTF-8 JSON with lexicographically sorted keys,
  compact separators, preserved array order, finite numbers only, normalized
  UTC timestamps, no BOM, and no Unicode normalization. Duplicate JSON keys are
  rejected. This is not an RFC 8785 claim.
- The signed body excludes `event_hash` and `signature`, includes the prior hash
  and exact payload SHA-256 digest, and is hashed with SHA-256. Ed25519 signs the
  raw 32 digest bytes.
- SQLite `BEGIN IMMEDIATE` plus one async process write lock allocates sequence,
  inserts payload and event, and updates the derived view atomically. Database
  uniqueness constraints remain the second line of defense.
- Verification recomputes payload and event digests, key IDs, signatures, chain
  links, contiguous sequence, an externally stored or supplied signed expected
  head, and a replayed view. Any failure disables commits and injection until
  repaired or an isolated clean store is selected. Without an expected head,
  terminal completeness is reported as unproven, never fully verified.
- Revocation is a new event referencing one committed memory event. Rebuild
  replays history deterministically and compares canonical rows with the stored
  view before replacement.
- TTL is scheduled metadata, not a wall-clock replay rule. Before injection, a
  lifecycle sweep appends `MemoryExpired` for every due entry while the ledger
  is healthy; replay excludes memory only after that event exists.

### Policy

- YAML is the operator format; JSON is accepted through the same Pydantic model.
- Policy contains ID, semantic version, mode, default action, source/namespace/
  kind/category matches, severity and semantic thresholds, protected
  namespaces, TTL, manual-review requirements, and explicit failure behavior.
  `VC-POLICY-1` applies mandatory structural, credential, and protected-policy
  namespace guards first. Other populated match fields are ANDed, list values
  are ORed, duplicate rule IDs are rejected, and rules sort by
  `(priority, rule_id)`.
- The engine computes enforce action first. Enforce applies it; shadow records it
  as `would_have_action` and applies the configured shadow action as
  `actual_action`.
- Invalid activation appends `PolicyActivationRejected` with only a request
  digest and safe issue codes when the ledger is healthy; it never appends
  `PolicyActivated` and leaves the last-known-good policy active. If no valid
  last-known-good policy exists, both new commits and injection fail closed.
  Successful activation appends `PolicyActivated` with the validated digest.

### Codex integration

- The plugin sets native `memories = false` and defense-in-depth generation/use
  flags for its controlled environment. `doctor` verifies effective state.
- `UserPromptSubmit`, supported `PostToolUse`, compaction markers, and `Stop`
  deliver bounded evidence envelopes to the daemon. The unstable transcript
  file is not parsed for core correctness.
- `SessionStart` asks for eligible memory and prints only the documented JSON
  `additionalContext` response. Memory is typed and delimited, facts are not
  elevated to system authority, operational instructions need stronger trust,
  and the result fits a configurable character/token budget.
- Hook definitions use short explicit timeouts and do not rely on ordering with
  other hooks. An unavailable daemon yields no memory, not raw fallback.

### Transactional streaming

`begin` creates an isolated bounded buffer and `StreamStarted` event. `append`
runs incremental structural, size, secret, and overlapping pattern checks.
`commit` atomically freezes the buffer, performs complete canonical evaluation,
and can commit exactly once. `abort`, block, timeout, cancellation, and resource
limit failures produce an auditable terminal event and no active memory. Buffer
content is not readable through memory APIs before successful commit.

### Observability

OpenTelemetry API spans cover capture, extraction, evaluation, each detector,
semantic review, policy, ledger append, materialization, injection, revocation,
and verification. Attributes are limited to IDs, versions, source, action,
length, safe digest prefix, latency, and error class. The local statistics API
derives counts and latency aggregates without exporting raw prompts or content.

## Failure Behavior

| Failure | Commit behavior | Injection behavior | Operator signal |
|---|---|---|---|
| Daemon unavailable | No commit | Continue without Verity memory | Hook health warning without content |
| Hook timeout or invalid output | No implicit commit | No fallback injection | Codex hook failure plus doctor result |
| Detector timeout/exception | Failure finding; high-risk defaults quarantine | Ineligible result excluded | Candidate detail and failure metric |
| Semantic timeout/refusal/schema error | Policy fallback; high-risk defaults quarantine | Ineligible result excluded | Provider state and timeout count |
| OpenAI unavailable | Live run fails safely; no fixture substitution | Previously verified active view may inject | Live provider degraded |
| Proposed policy validation failure | Append safe rejection when possible; retain an intact last-known-good policy, otherwise fail closed | Continue only under the still-valid last-known-good policy; with no valid policy, inject nothing | Rejection event or content-free critical policy status |
| Ledger append interruption | Transaction rolls back; no partial event/view | Existing verified view only | Storage error event where possible |
| Ledger corruption | Refuse all new commits | Disabled | Critical state, first invalid event |
| Missing/unsafe signing key | Refuse signed append | Disabled; a due TTL could not be made an explicit signed expiry event | Key health failure |
| Materialized-view drift | Refuse commit until rebuild | Disabled | Consistency failure and rebuild action |
| Plugin detector crash | Failure result; remaining detectors continue | Policy determines eligibility | Plugin ID and error class only |
| Control Room API loss | No browser-side optimistic trust change | Unchanged | Recoverable connection state |

## Project Structure

### Documentation (this feature)

```text
specs/001-codex-memory-firewall/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── tasks.md
├── contracts/
└── checklists/
```

### Source Code (repository root)

```text
src/verity_cordon/
├── core/          # models, enums, protocols, errors, clock
├── daemon/        # FastAPI app, dependencies, mutation authorization
├── codex/         # hook envelopes, thin client, installer, injection format
├── ledger/        # SQLite schema/store, append, verify, replay
├── memory/        # candidate lifecycle, materialized view, revocation
├── detectors/     # deterministic detectors, runner, plugin discovery
├── policies/      # Pydantic policy models, engine, default YAML/schema
├── semantic/      # fixture and OpenAI extractors/adjudicators
├── streaming/     # begin/append/commit/abort session lifecycle
├── telemetry/     # safe spans and aggregate statistics
├── crypto/        # VC-CJ-1, key provider, SHA-256, Ed25519
└── cli/           # Typer entry point and commands

apps/control-room/
├── src/           # React views, components, API client, accessible actions
├── tests/
└── dist/          # committed judge-ready production build

tests/
├── unit/
├── contract/
├── integration/
├── adversarial/
└── end_to_end/

evals/
├── datasets/
├── expected/
├── results/
└── runners/

examples/
├── poisoned-docs-mcp/
└── detector-plugin/

scripts/
├── bootstrap.sh
├── demo-offline.sh
├── demo-live.sh
└── verify.sh

.codex-plugin/
hooks/
```

**Structure Decision**: One Python installable repository owns all security and
storage logic. One TypeScript app consumes the local API and compiles into
daemon-served static assets. Examples are inert and never imported by the core.

## Delivery Phases

1. **Foundation**: package, configuration, domain protocols, SQLite migrations,
   policy validation, fixture provider, health/status API, CLI shell, UI shell.
2. **P1 vertical slice**: safe evidence capture, candidate extraction, detectors,
   deterministic policy, signed event append, active view, inventory UI.
3. **Security demonstration**: poisoned tool, shadow/enforce outcomes,
   quarantine/detail UI, privacy-safe telemetry, adversarial tests.
4. **Codex integration**: plugin manifest, trusted hook configs, thin client,
   native memory controls, approved-memory injection, installer/uninstaller and
   doctor.
5. **Live GPT-5.6**: sanitized structured extraction and assessment, bounded
   failures, provider labeling and live-mode test.
6. **Revocation and replay**: revoke preview/action, rebuild/compare, stale-view
   failure and UI flow.
7. **Streaming/plugins/OTel**: transactional streams, split attacks, one detector
   entry point, safe spans.
8. **Polish and submission**: eval results, clean-checkout demo, browser and
   accessibility smoke, docs, final Spec Kit analysis and convergence.

Each phase must keep the offline critical path runnable. If schedule pressure
requires reduction, UI streaming controls, animations, exporter examples, and
keychain breadth are cut before any core security claim or judge path.

## Complexity Tracking

| Choice | Why needed | Simpler alternative rejected because |
|---|---|---|
| Python daemon plus compiled React app | The product requires both security-critical local services and a polished, interactive Control Room. | Server-rendered static pages would reduce design and interaction quality; a separate frontend server would add runtime complexity. |
| Append-only event store plus derived tables | Selective revocation, chain verification, and deterministic reconstruction are core acceptance criteria. | Mutable memory rows or whole-store snapshots cannot explain or revoke one historical decision without destructive rewrite. |
| Fixture and live semantic providers | Offline judging and meaningful live GPT-5.6 use are both mandatory. | A fixture-only product would not use GPT-5.6 at runtime; live-only would make judging brittle and credential-dependent. |
