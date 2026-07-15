# Implementation Plan: Codex Desktop Subscription Defense

**Branch**: `codex/002-desktop-subscription-defense` | **Date**: 2026-07-15 |
**Spec**: [spec.md](./spec.md)

**Input**: Feature specification from
`specs/002-codex-desktop-subscription-defense/spec.md`

## Summary

Extend the implemented `001-codex-memory-firewall` baseline with a Codex
Desktop-first attack-and-defense demonstration and an opt-in semantic provider
that uses the operator's supported Codex ChatGPT-subscription sign-in. The
provider launches the local Codex runtime as a bounded, ephemeral child process
over a fixed argument vector, passes only locally sanitized synthetic evidence
through stdin, validates strict structured output, rejects any observed tool
activity, and never falls back to another provider. Deterministic Verity policy
continues to make every trust decision.

The judge-facing scenario is a clean-room, synthetic delayed-trigger poisoning
attack inspired by Trojan Hippo: a stdio MCP documentation tool returns one
useful project fact plus a concealed permanent operational instruction. Shadow
mode exposes the unsafe would-have decision, enforcement quarantines the
instruction, a fresh Desktop task receives only eligible memory, and selective
revocation removes the earlier shadow-admitted memory while preserving the
signed event history. Demo-only MCP configuration is separate from normal
product installation, previewed, confirmation-gated, receipt-bound,
drift-aware, and reversible.

## Technical Context

**Language/Version**: Python 3.12+; TypeScript 6.0.3; Node.js `^20.19.0` or
`>=22.13.0`

**Primary Dependencies**: Existing Pydantic 2.13, FastAPI 0.139, aiosqlite
0.22, cryptography 49, OpenAI Python 2.45, Typer 0.26, tomlkit 0.14,
OpenTelemetry API 1.43; React 19.2, Vite 8.1, Vitest 4.1; supported local Codex
runtime `0.144.4` was exercised during research

**Storage**: Existing authoritative SQLite ledger and derived views; existing
restrictive Ed25519 key and capability files; one restrictive demo-install
receipt and staged stdio fixture outside Git; existing local TOML Codex config

**Testing**: pytest, pytest-asyncio, pytest-cov, mypy, Ruff, JSON Schema and
OpenAPI validation; Vitest, TypeScript, ESLint, Vite build; deterministic hook
and subprocess harnesses; manual Codex Desktop smoke explicitly recorded as
manual evidence

**Target Platform**: Codex Desktop on macOS is the primary exercised demo;
Codex CLI on macOS is the secondary deterministic harness. Linux remains an
intended product target but is not a sprint demo claim; Windows is unverified.

**Project Type**: Existing installable Python daemon/CLI/Codex plugin and
loopback React Control Room, extended by one opt-in local child-process provider
and one explicit demo-only MCP installer

**Performance Goals**: Preserve the existing 250 ms deterministic-fixture
evaluation target; bound subscription semantic calls to a configurable 30
seconds by default; keep captured stdout/stderr and structured output below
contracted byte limits; complete the edited Desktop narrative in under three
minutes excluding installation and recorded loading time

**Constraints**: No OpenAI API key for subscription mode; no credential-file
inspection; no shell; no inherited project rules, plugins, hooks, memory, web
search, or broad environment; no claim that the Codex child is tool-free; any
tool event, malformed or oversized output, timeout, rate limit, missing
subscription authentication, or child cleanup failure is explicit and cannot
admit high-risk memory; synthetic data only; normal installation must not add
the attack fixture

**Scale/Scope**: One local operator and one child process per bounded semantic
operation for the hackathon path; one dedicated demo MCP entry; additive
provider-state migration across existing signed events, API responses, CLI,
evaluation output, and Control Room; no UI automation, hosted service, or
outbound information-flow control

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

No constitution exception is required. The subscription child is a distinct,
lower-isolation provider and cannot weaken the existing direct Responses API or
offline fixture providers. The Desktop demo adds no new source of durable
authority: its MCP result still enters the same evidence, detector, semantic,
policy, ledger, and materialization pipeline.

## Architecture

```text
Codex Desktop task
    │ documented plugin hook events
    ├──────────────────────────────────────────┐
    │                                          │
    │ explicit demo-only stdio MCP             │ bounded loopback hook IPC
    ▼                                          ▼
poisoned-docs fixture                    verityd async daemon
(synthetic values only)                        │
                                               ├─ local secret sanitization
                                               ├─ deterministic detectors
                                               ├─ versioned policy (final authority)
                                               ├─ signed event ledger + active view
                                               └─ selected semantic provider
                                                         │
                       fixture ──────────────────────────┤
                       direct Responses API, no tools ──┤
                       Codex subscription child ────────┘
                              │ fixed argv + stdin; no shell
                              ▼
                       private empty temporary cwd
                       `codex exec --ephemeral ...`
                              │ JSONL event audit + strict output file
                              ▼
                       schema/identity/digest checks
                       tool event => explicit failure

Control Room reads only content-safe daemon APIs and shows the provider's
identity and isolation class beside actual and would-have actions.
```

### Subscription provider boundary

`CodexSubscriptionCandidateExtractor` and
`CodexSubscriptionSemanticAdjudicator` implement the existing async protocols.
They share strict structured-output schemas and bounded validation helpers with
the direct OpenAI provider but do not reuse its `no tools` instructions or
security label.

The launcher resolves `codex` to a regular executable under the normative
owner/ancestor rules below and invokes it with
`asyncio.create_subprocess_exec`.
The exact supported controls are recorded in
`contracts/codex-subscription-provider.md`; the minimum invocation is:

```text
codex
  --ask-for-approval untrusted
  exec
  --ephemeral
  --ignore-user-config
  --ignore-rules
  --strict-config
  --skip-git-repo-check
  --sandbox read-only
  --disable plugins
  --disable remote_plugin
  --disable apps
  --disable hooks
  --disable memories
  --disable shell_tool
  --disable browser_use
  --disable browser_use_external
  --disable computer_use
  --disable in_app_browser
  --disable multi_agent
  --disable goals
  --config web_search="disabled"
  --config shell_environment_policy.inherit="none"
  --model <configured-model>
  --cd <private-empty-directory>
  --output-schema <private-schema-path>
  --output-last-message <private-output-path>
  --color never
  --json
  -
```

An executable or search-path component is trusted only when it is absolute,
owned by the effective user or root, and not group- or world-writable; every
existing ancestor through the filesystem root must meet the same owner/write
rule. Relative/empty PATH entries and current-directory lookup are rejected.
An explicit executable must be absolute. A discovered symlink may be resolved
once only when both the link's parent chain and resolved regular target satisfy
the rule. The target must be executable and its identity/digest are pinned and
rechecked before launch.

`HOME` and `CODEX_HOME` are the only authentication-location inputs. Each must
be an absolute, existing, current-user-owned directory, must not itself be a
symlink, and must not be group- or world-writable. Every existing ancestor
through the filesystem root must be owned by the effective user or root and
must not be group- or world-writable. `CODEX_HOME` defaults to the validated
`HOME/.codex`; identity and ancestor state are rechecked before launch so a
replacement or permission drift fails closed. No other parent environment or
credential variable is forwarded.

The disabled feature names above were present in the researched Codex 0.144.4
runtime and are compatibility-tested before use. `mcp_servers={}` is not used
as a supposed clearing control: Codex configuration deep-merges that empty
table and retains configured servers. The primary user/project MCP isolation is
`--ignore-user-config` plus the empty non-repository cwd. Because no documented
global MCP-disable switch exists, tool-event rejection and the lower-isolation
claim remain mandatory.

The prompt is written to stdin, never the process list. The provider sets
`VERITY_SEMANTIC_CHILD=1`; the installed hook adapter checks the same marker and
returns before reading or forwarding hook content. `--ignore-user-config`, the
private empty working directory, disabled agentic features, and no inherited
environment are the primary isolation controls. The marker is defense in
depth, not the sole recursion control.

The provider first executes the supported bounded `codex login status` command
with the same trusted binary and content-safe capture. Only an authenticated
ChatGPT login is accepted for this explicit provider. API-key login, ambiguous
status, missing CLI, unsupported CLI behavior, or any credential-bearing output
fails readiness. Verity never opens Codex authentication storage.

The child emits JSONL. The parent rejects duplicate keys, non-finite numbers,
unrecognized oversize records, and every event indicating command, shell,
filesystem, web, MCP, or other tool activity. A model response is accepted only
from the restrictive private output file after schema validation, exact
candidate or evidence identity and SHA-256 binding, provider/schema/prompt
version validation, size bounds, and a second local sanitization pass.

On timeout or cancellation, the parent terminates the child process group,
waits a short bounded interval, escalates to kill, and fails if descendants
cannot be accounted for. Private directories are mode `0700`; created schema,
prompt-output, and diagnostic files are mode `0600`, are never symlinks, and are
removed after a bounded read. Routine logs contain only error classes, timing,
IDs, and digest prefixes.

### Provider identity and replay compatibility

`live_codex_subscription` is added to provider-state enums, candidate extractor
labels, API contracts, filters, statistics, evaluation output, and UI types.
Historical values remain unchanged. Isolation class is a derived presentation
attribute rather than a rewrite of historical signed payloads:

| Provider state | Isolation class | Claim |
|---|---|---|
| `live_openai` | `tool_free_api` | Direct Responses API request with no tools and `store=False` |
| `live_codex_subscription` | `agentic_sandboxed` | Ephemeral read-only Codex child; tool activity invalidates output |
| `recorded_fixture` | `recorded_fixture` | Deterministic offline structured fixture |
| `deterministic_only` / `not_required` | `local_deterministic` | No semantic call used |
| `failed` | `failed` | No semantic recommendation accepted |

The event envelope, canonicalization algorithm, signature construction, and
existing schema version remain unchanged. Enum expansion is additive: replay
must accept all old values and new events bind the new label in their original
signed payload. No migration mutates prior rows.

### Desktop demo installation

Normal `verity install-codex` remains responsible only for the reviewed Verity
plugin and native-memory controls. `verity demo desktop-setup` is a separate
explicit operation:

1. Resolve and validate the selected Codex config, Python runtime, and fixture
   source without mutating state.
2. Show the exact MCP entry, staging destination, artifact digests, existing
   value, and teardown plan.
3. Require `--yes` to stage the reviewed fixture and update only the dedicated
   `mcp_servers.verity_cordon_poisoned_docs` entry.
4. Atomically create a restrictive receipt containing original entry state,
   applied value, canonical hashes, runtime identity, and receipt version.
5. Refuse setup or teardown on symlinks, unsafe ownership/modes, digest drift,
   config drift, ambiguous partial state, or an unreadable receipt.
6. `verity demo desktop-teardown --yes` restores or removes only the recorded
   entry and staged demo artifacts. It never changes the Verity ledger, key,
   memory view, normal plugin, or unrelated Codex configuration.

The MCP fixture remains bounded stdio. It provides
`get_release_guidance` and an inert `demo_artifact_sink`. The sink accepts only
the fixed synthetic marker declared in the demo contract, records safe metadata
in process memory, reads no files or environment, starts no subprocess, and has
no network imports or transmission capability. It rejects all unexpected
fields or values.

The installed MCP entry uses an absolute verified Python runtime with isolated
mode, a receipt-bound staged script and private empty cwd, `enabled=true`,
`required=true`, short startup/tool timeouts, an explicit two-tool allow-list,
and prompt approval. It supplies no MCP environment or environment-variable
forwarding. Codex Desktop must be restarted after setup or teardown, as required
by the documented host-config reload behavior.

### Desktop decision gate

Hook capture remains asynchronous. The demo and documentation therefore use an
explicit evaluation-state checkpoint after the poisoned tool call. The Control
Room and CLI must distinguish captured/pending from a signed terminal decision.
A fresh-task protection claim is permitted only after the evidence has a signed
terminal outcome and the ledger/view verification state is healthy. A timeout
or daemon failure yields no Verity-provided memory rather than an optimistic
claim.

### Attack coverage

The primary fixture is a conditional command insertion: an untrusted tool asks
to persist concealed operational authority that activates during a later
release task. The curated evaluation adds:

- a benign quoted discussion to measure false-positive behavior;
- a weak-signal policy-conformant fact injection;
- split-chunk wording that crosses the existing transactional stream boundary;
- a compaction-origin candidate; and
- a procedural/skill-like instruction classified as high authority without
  claiming complete Codex-skill protection.

The taxonomy comes from primary papers recorded in `research.md`. EmergentMind
is cited only as a secondary literature index. Paper attack-success rates are
not Verity results.

### Failure behavior

| Failure | Required result |
|---|---|
| Codex executable missing, replaced, or unsafe | Provider unavailable; no fallback; high-risk candidate quarantined |
| ChatGPT subscription login absent or ambiguous | Readiness failed without credential detail; no child evaluation |
| API-key login detected | Reject subscription provider; direct API remains a separate explicit choice |
| Usage limit, nonzero exit, refusal, or rate limit | Content-safe semantic failure; deterministic failure policy applies |
| Timeout or cancellation | Terminate process group; record only failure class; no accepted output |
| Tool event or attempted tool call | Reject the complete assessment even if a valid final answer exists |
| Malformed, duplicate-key, identity-mismatched, or oversized output | Reject output; no partial candidate or assessment persists |
| Temp-file or cleanup safety failure | Fail closed and retain only content-safe diagnostics |
| Hook unexpectedly loads in child | `VERITY_SEMANTIC_CHILD` causes immediate no-op; observed recursion is a test failure |
| Demo sink receives unexpected data | Reject call without storage or external side effect |
| Demo setup interruption | Normal install remains unchanged; partial receipt/state is reported and teardown refuses guessing |
| Config or staged artifact drift | Setup/teardown refuses overwrite and reports content-free drift codes |
| Daemon, ledger, policy, or view unhealthy | No memory injection and no new commit; read-only audit where safe |
| Desktop unavailable | Offline fixture demo exercises the real policy, ledger, view, revocation, and UI |

## Project Structure

### Documentation (this feature)

```text
specs/002-codex-desktop-subscription-defense/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── tasks.md
├── contracts/
│   ├── codex-subscription-provider.md
│   ├── desktop-demo-contract.md
│   └── desktop-demo-receipt.schema.json
└── checklists/
    ├── requirements.md
    ├── security.md
    ├── subscription-provider.md
    └── demo-readiness.md
```

### Source Code (repository root)

```text
src/verity_cordon/
├── semantic/
│   ├── structured.py              # shared strict schemas and validation
│   ├── openai_provider.py         # existing direct API provider
│   └── codex_subscription.py      # bounded subscription child provider
├── codex/
│   ├── hooks.py                   # child recursion guard
│   ├── installer.py               # existing normal plugin install
│   └── demo_installer.py          # separate demo MCP setup/teardown
├── core/{config.py,models.py}
├── daemon/app.py
├── ledger/queries.py
└── cli/main.py

examples/poisoned-docs-mcp/
├── src/poisoned_docs_mcp/server.py
├── README.md
└── tests/test_server.py

apps/control-room/src/
├── api/types.ts
├── routes/{OverviewPage.tsx,CandidateDetailPage.tsx,MemoryInventoryPage.tsx}
└── test/

tests/
├── unit/
├── contract/
├── integration/
├── adversarial/
└── end_to_end/

evals/datasets/
scripts/demo-desktop.sh
docs/{decisions,hackathon,security}/
```

**Structure Decision**: Extend the existing single-install repository and
loopback Control Room. The subscription provider and demo installer are narrow
modules behind existing protocols; no new production service, package, or agent
framework is introduced. The example MCP stays independently testable but is
staged only by the explicit demo command.

## Verification Strategy

Implementation follows test-first slices:

1. Add replay-compatible provider labels and shared strict schemas; prove old
   fixture and API events still parse, verify, and replay.
2. Falsify unsafe child behavior with fake executables covering argv/env,
   auth, tool events, malformed and oversized JSONL, timeout, cancellation,
   process descendants, temp permissions, cleanup, and recursion.
3. Add the original delayed-trigger and false-positive fixtures; prove selective
   enforcement through the real hook queue, policy, ledger, view, and injection
   contract.
4. Add preview/apply/teardown fixture-config tests against temporary Codex homes
   including interruption and drift cases.
5. Add Control Room provider labels and warning tests, then build and inspect the
   actual local UI with browser smoke checks.
6. Run the tracked critical suite in a clean checkout so unrelated untracked
   duplicate files in the operator workspace cannot contaminate test discovery.
7. Exercise a real subscription child only when explicitly selected; record
   the exact Codex version, authentication class, model, command outcome, and
   that the evidence was synthetic. Record Desktop UI observations separately
   as manual smoke evidence.

Security-critical gates include exact subprocess argument and environment
assertions, no raw synthetic marker in routine logs/telemetry, no secret input
on argv, tool-event rejection, explicit no-fallback behavior, old signed-event
replay, fresh-task approved-only injection, one-memory revocation, and ledger
verification after rebuild.

## Complexity Tracking

No constitution violation or speculative subsystem is introduced. A separate
demo installer is intentionally retained instead of extending normal plugin
installation because the attack fixture must never appear in ordinary product
setup. A child-process provider is required because supported ChatGPT
subscription authentication is exposed through Codex rather than the OpenAI
API SDK; its reduced isolation is explicit and opt-in.
