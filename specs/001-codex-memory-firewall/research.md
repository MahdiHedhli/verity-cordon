# Research: Codex Memory Firewall

**Feature**: `001-codex-memory-firewall`

**Verified**: 2026-07-15 (America/New_York)

This document records primary-source findings that materially constrain the
architecture. The linked pages were current when inspected; runtime checks and
the repository lockfiles remain the final evidence for the implemented build.

## OpenAI Build Week

**Sources**:

- [Hackathon overview](https://openai.devpost.com/)
- [Official rules](https://openai.devpost.com/rules)

**Decision**: Enter the Developer Tools track and optimize a working local
vertical slice against the four equally weighted judging criteria.

**Verified facts**:

- Submission period: 2026-07-13 09:00 PT through 2026-07-21 17:00 PT.
- Judging period: 2026-07-22 10:00 PT through 2026-08-05 17:00 PT.
- The demo video must be publicly visible on YouTube, have audio, and be less
  than three minutes; judges need not watch beyond three minutes.
- A repository URL, setup and test path, Codex/GPT-5.6 explanation, and real
  `/feedback` Session ID are required. Developer tools also need supported
  platforms and a path that does not require reconstructing the product.
- Existing open-source work may be used with license compliance, but new work
  during the submission period must be distinguished and materially enhance the
  baseline.
- The judging criteria are Technological Implementation, Design, Potential
  Impact, and Quality of the Idea, equally weighted.

**Implication**: Keep dated Git history from baseline commit `ef2c80d`, ship an
offline product path with synthetic data, preserve free judge access through
the judging period, and never fabricate the video or Session ID.

## GitHub Spec Kit

**Sources**:

- [Official repository](https://github.com/github/spec-kit)
- [v0.12.15 release](https://github.com/github/spec-kit/releases/tag/v0.12.15)
- [Installation](https://github.github.io/spec-kit/installation.html)
- [Codex integration](https://github.github.io/spec-kit/reference/integrations.html)

**Decision**: Pin official Spec Kit `v0.12.15` and use its native Codex skills.

**Evidence**:

- Release commit: `7b91c1eda46e1107a53831cd3f14f608b4b7bad0`.
- Inspected `main`: `ad601e5d52251f9131220c621d1cbbb7d61bebee`.
- Installed with `uv tool install specify-cli --from
  git+https://github.com/github/spec-kit.git@v0.12.15`.
- Initialized with `specify init --here --force --integration codex --script sh`
  after an empty-workspace preflight and manual Git baseline.
- Codex commands are skills under `.agents/skills` and use `$speckit-*` names.

**Alternatives considered**: Unpinned main and a hand-authored parallel planning
system. Rejected because they would make the source of truth non-reproducible.

## Codex Local Memories

**Sources**:

- [Memories](https://learn.chatgpt.com/docs/customization/memories)
- [Configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Developer commands](https://learn.chatgpt.com/docs/developer-commands?surface=cli)

**Decision**: Use a controlled replacement memory plane; disable native local
memory use and generation for the Verity demo environment.

**Verified behavior**:

- ChatGPT web memory and local Codex memory are separate.
- Local Codex memories are documented as experimental and off by default, but
  effective state must be checked because this host reports the feature present.
- Generated files under the Codex home directory are not a supported primary
  control surface and have no documented stable interception contract.
- Supported controls include `[features] memories = false`,
  `memories.generate_memories = false`, `memories.use_memories = false`, task
  controls through `/memories`, and one-run `codex --disable memories`.
- `memories.disable_on_external_context = true` excludes some externally
  augmented tasks from generation but is defense in depth, not a complete
  disable.

**Required integration configuration**:

```toml
[features]
hooks = true
memories = false

[memories]
generate_memories = false
use_memories = false
disable_on_external_context = true
```

**Bounded claim**: Verity controls only memory captured and injected through its
documented integration. It does not intercept undocumented native internals or
ChatGPT web memory.

## Codex Lifecycle Hooks

**Source**: [Hooks](https://learn.chatgpt.com/docs/hooks)

**Decision**: Package thin command hooks for supported evidence events and use
`SessionStart` to inject approved, typed context.

**Published events**: `SessionStart`, `SubagentStart`, `PreToolUse`,
`PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`,
`UserPromptSubmit`, `SubagentStop`, and `Stop`.

**Integration mapping**:

| Verity purpose | Codex event | Material constraint |
|---|---|---|
| Approved-memory injection | `SessionStart` | JSON `hookSpecificOutput.additionalContext` becomes developer context. |
| User evidence capture | `UserPromptSubmit` | Prompt is available; matcher is ignored. |
| Tool evidence capture | `PostToolUse` | Supported Bash, `apply_patch`, and MCP output; it cannot undo side effects. |
| Compaction marker | `PreCompact`, `PostCompact` | Trigger is `manual` or `auto`; transcript format is not stable. |
| Turn evidence capture | `Stop` | Latest assistant message is available; successful output must be JSON. |

**Runtime constraints**:

- Matching command hooks run concurrently across active config layers; ordering
  is not guaranteed and Verity must not depend on it.
- Non-managed hooks require review and trust of their current definition hash.
- Only command handlers run; `async: true`, prompt handlers, and agent handlers
  are currently skipped.
- Default hook timeout is 600 seconds, so Verity sets explicit short deadlines.
- Tool hooks do not cover every shell mechanism, WebSearch, or every Codex tool
  path. Claims remain limited to documented captured surfaces.
- `transcript_path` is convenient but its format is explicitly unstable; core
  behavior must rely on event fields rather than parsing it.

**Session-start output**:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": "VERITY_CORDON_APPROVED_MEMORY_START\n...\nVERITY_CORDON_APPROVED_MEMORY_END"
  }
}
```

**Failure decision**: If the daemon, policy, ledger, or view is unhealthy, the
adapter exits successfully with no injected memory and a content-free local
warning. It never falls back to raw evidence.

## Codex Distribution Surface

**Sources**:

- [Build plugins](https://learn.chatgpt.com/docs/build-plugins)
- [Build skills](https://learn.chatgpt.com/docs/build-skills)

**Decision**: Provide a Codex plugin because lifecycle hooks, not model-followed
skill guidance alone, are required. The manifest lives at
`.codex-plugin/plugin.json`; bundled hook paths remain inside the plugin root.

**Implication**: Installation is explicit, project trust is verified by
`verity doctor`, and the operator is told to review hooks and start a new Codex
session. A skill is not described as an enforcement boundary.

## GPT-5.6 and Structured Outputs

**Sources**:

- [GPT-5.6 guidance](https://developers.openai.com/api/docs/guides/latest-model)
- [GPT-5.6 Sol](https://developers.openai.com/api/docs/models/gpt-5.6-sol)
- [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [Python SDK](https://github.com/openai/openai-python/releases/tag/v2.45.0)

**Decision**: Configure live semantic calls with the `gpt-5.6` alias, record the
requested alias and returned model, and use `AsyncOpenAI.responses.parse` with
strict Pydantic schemas and `store=False`.

**Verified facts**:

- `gpt-5.6` routes to `gpt-5.6-sol`; no dated immutable Sol snapshot was listed.
- GPT-5.6 supports the Responses API and Structured Outputs.
- `responses.parse(..., text_format=PydanticModel)` produces schema-constrained
  parsed output. Refusal, incomplete output, or missing parsed content still
  needs explicit handling.
- Responses are stored by default; `store=False` disables response application
  state storage but is not a Zero Data Retention claim.
- The official SDK defaults are too permissive for this hook-driven path;
  Verity uses a short timeout and one bounded retry.

**Semantic isolation**:

- No tools, conversation, previous response, or durable memory.
- Evidence is sanitized locally first and supplied as untrusted data.
- Input and output are bounded and schema validated.
- Cache key binds the sanitized-content digest, source class, namespace, kind,
  session/task scope, persistence request, authority/secrecy signals, model,
  prompt, and schema versions. Text-identical content from a user and an
  untrusted tool cannot share an assessment accidentally.
- Deterministic policy remains the final authority.

**Alternatives considered**: Treating the model as the policy engine or silently
using fixtures after a live failure. Rejected because both make trust decisions
ambiguous and the latter misrepresents the runtime contribution.

## Donor Baseline: OWASP Agent Memory Guard

**Repository**: [OWASP/www-project-agent-memory-guard](https://github.com/OWASP/www-project-agent-memory-guard)

**Inspected branch and commit**: `main` at
`93bc011d54ae3495718ab5d59aef0aaa05e70264`

**License**: Apache-2.0

**Release state**: Latest published core release `v0.3.0` at
`32e607e7774f315b05658fd5dade8e9fc0b068ba`, published 2026-06-10.

**Verified baseline**:

- Synchronous `MemoryGuard.write/read` over a process-local `InMemoryStore`.
- Dataclass/YAML policy with permissive, strict, and tiered behavior.
- Default regex/heuristic detectors cover injection, secrets/PII, size, churn,
  protected keys, cross-task contamination, and self-reinforcement. Tool abuse,
  privilege escalation, excessive autonomy, and optional local ML exist outside
  the default pipeline.
- Recovery is bounded in-memory whole-store snapshots and destructive rollback,
  not event-specific revocation.
- Current-main streaming is a synchronous sliding window, is absent from the
  `0.3.0` wheel, is excluded from coverage, is not transactional, and calls a
  detector method that does not exist in the shipped detector protocol.
- Events and quarantine are process-local and unsigned. Clean allows may emit no
  event. There is no persistent sequence, signature chain, deletion/reordering
  verification, or Codex integration.
- The default REST server binds broadly, exposes permissive CORS and reset
  behavior without authentication, and can return detector metadata containing
  matched content. Verity does not inherit these defaults.
- Core tests at the inspected commit: 96 passed and 10 expected failures. The
  expected failures document split, encoded, correlated, homoglyph,
  multilingual, and read/write attacks not covered by the donor.

**Decision**: Implement Verity cleanly. Reuse research concepts, not donor code,
unless later provenance is explicitly documented in `THIRD_PARTY_NOTICES.md`.

## Runtime and Dependency Baseline

Versions were queried from the official package registries on 2026-07-15.
Lockfiles, not this table, define the tested installation.

| Component | Verified current version | Selection |
|---|---:|---|
| Python | local 3.14.6; project target 3.12+ | Support 3.12-3.14; CI tests 3.12 and 3.14 where practical. |
| FastAPI | 0.139.0 | Local daemon and UI API. |
| Pydantic | 2.13.4 | Domain and policy validation plus schema generation. |
| aiosqlite | 0.22.1 | Non-blocking SQLite access without an ORM. |
| openai | 2.45.0 | Async Responses Structured Outputs. |
| cryptography | 49.0.0 | Ed25519 signing and verification. |
| OpenTelemetry API | 1.43.0 | Privacy-safe span API only; exporter ecosystem deferred. |
| Typer | 0.26.8 | Synchronous CLI boundary over async services. |
| Uvicorn | 0.51.0 | Loopback ASGI server. |
| pytest / pytest-asyncio | 9.1.1 / 1.4.0 | Automated backend tests. |
| Ruff / mypy | 0.15.21 / 2.3.0 | Formatting, lint, and strict static checks. |
| React / React DOM | 19.2.7 | Local Control Room. |
| Vite | 8.1.4 | Lightweight frontend build. |
| TypeScript | 7.0.2 | Strict UI typing. |
| Vitest | 4.1.10 | UI unit tests. |

## Architecture Decisions

### Async boundaries

**Decision**: Define async protocols for event storage, memory views, detectors,
semantic adjudication, policy providers, event sinks, Codex adapters, clocks,
and key providers. SQLite and network I/O are awaited. Detector fan-out uses a
bounded `TaskGroup`, explicit deadlines, cancellation, stable sorting, and
failure results. CPU-heavy work moves through bounded threads only when needed.

### SQLite ordering and atomicity

**Decision**: Use one SQLite write transaction guarded by an async process lock
and `BEGIN IMMEDIATE`. Allocate the next global sequence, bind the previous
global hash, insert payload and event, and update derived view in the same
transaction. WAL mode improves readers; the ledger remains authoritative.

**Alternatives considered**: Large ORM, Redis, PostgreSQL, and per-stream chains.
Rejected for the local single-user vertical slice. A global chain makes
deletion and reordering checks straightforward; `stream_id` still groups domain
events.

### Canonical event representation

**Decision**: Canonicalize a documented JSON-compatible subset as UTF-8 with
lexicographically sorted object keys, compact separators, preserved array order,
lowercase JSON literals, normalized UTC timestamps, and finite numbers only.
Exclude `event_hash` and `signature` from the signed body; include
`previous_event_hash` and the exact payload SHA-256 digest. Hash canonical bytes
with SHA-256 and sign the 32 hash bytes with Ed25519.

This is a project-defined deterministic representation, not a claim of RFC 8785
compliance. Tests bind implementation and contract fixtures.

### Key handling

**Decision**: Generate one local Ed25519 installation key outside Git with mode
`0600`, derive the key ID as `vc-ed25519-` plus the full lowercase SHA-256 hex
digest of the raw public key, and support public-key export. The data directory
is configurable for isolated demos. Operating
system keychain support is deferred if it threatens the critical path.

### Policy format

**Decision**: Use YAML for readable local policy files, validate with Pydantic
v2, generate JSON Schema, compute a canonical content digest, and record every
activation. A malformed policy blocks new commits. No remote retrieval exists.

### UI integration

**Decision**: Build the React/TypeScript Control Room as a separate lightweight
app, then serve its committed production build from the loopback FastAPI daemon.
All views consume the same public local API used by tests. This avoids a second
production server and gives judges a single startup command.

### Offline semantics

**Decision**: Fixture semantic providers load recorded, schema-valid assessments
selected by deterministic fixture IDs. Offline mode is explicit in events and
UI. Live mode never silently falls back to fixtures.

### Detector plugins and telemetry

**Decision**: Discover only the `verity_cordon.detectors` entry-point group for
the hackathon, reject duplicate IDs, and isolate failures. Emit content-free
OpenTelemetry spans and local aggregate statistics. Semantic/event-sink plugin
groups and exporter configuration remain deferred.

## Remaining Bounded Uncertainties

- Codex does not document hook ordering, a stable transcript schema, or hooks
  for native memory operations.
- Codex tool hooks do not cover every tool path; the demonstrated poisoned MCP
  path is covered, but generalized interception is not claimed.
- GPT-5.6 currently has no dated immutable Sol snapshot in public docs, so live
  results are not bit-for-bit reproducible.
- The MVP threat boundary excludes a compromised host, user account, Codex
  binary, or signing key.
