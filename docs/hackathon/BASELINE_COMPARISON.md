# Donor Baseline Comparison

## Inspection Record

- **Project**: [OWASP Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard)
- **Repository branch**: `main`
- **Exact commit**: [`93bc011d54ae3495718ab5d59aef0aaa05e70264`](https://github.com/OWASP/www-project-agent-memory-guard/commit/93bc011d54ae3495718ab5d59aef0aaa05e70264)
- **Inspection date**: 2026-07-15
- **License**: Apache-2.0
- **Latest published core release**: `v0.3.0`, tag commit
  `32e607e7774f315b05658fd5dade8e9fc0b068ba`, published 2026-06-10

Verity Cordon is a separate project. The donor is prior art and a research
source; its branding and distinctive marketing language are not reused.

## Capability Comparison

| Capability | Verified donor baseline | Verity Cordon contribution |
|---|---|---|
| Core operation model | Synchronous `MemoryGuard.write/read` around a synchronous key/value protocol; default `InMemoryStore` is process-local. FastAPI endpoints call the synchronous core. | Async-first daemon and protocols, bounded concurrent detector execution, SQLite persistence, and explicit local IPC contracts. |
| Recovery | Bounded in-memory whole-store snapshots with destructive rollback. Snapshot digests are recorded but not checked during rollback. | Event-specific revocation, append-only history, and deterministic active-view replay that preserves unrelated memory. |
| Streaming | Current-main-only synchronous sliding character window for early alerts. It is absent from the published `0.3.0` wheel, non-transactional, excluded from tests, retains only a window, and currently calls a detector method that does not exist. | Transactional `begin/append/commit/abort`, bounded full buffer, complete final scan, isolated streams, audit outcomes, and no partial commit. |
| Policy validation | YAML `safe_load` into dataclasses; permissive, strict, and tiered presets; first matching rule per finding and strongest action. No schema, policy hash, activation history, or explicit failure contract. | Pydantic v2 validation and JSON Schema, version/digest binding, explicit failure policy, last-known-good behavior, and activation events. |
| Semantic detection | Optional local Hugging Face DeBERTa injection classifier, not in the default guard. Import/model/inference failures return unmatched. No OpenAI structured adjudication. | Selective sanitized GPT-5.6 structured extraction and assessment; fixture mode offline; deterministic policy retains authority. |
| Codex integration | No Codex lifecycle-hook or memory-plane integration. Generic recipes and framework-specific adapters exist. | Controlled Codex memory plane using documented memory controls and lifecycle hooks. |
| Audit integrity | Ephemeral in-memory event callbacks; clean allows may emit no event. Per-key hashes and snapshot digests exist, but no durable event chain, sequence verification, signatures, or key management. | SHA-256 payload/event binding, Ed25519 signatures, contiguous append-only sequence, public-key export, full chain and view verification. |
| Operator experience | Static scanner, `check`, FastAPI server, regex-based MCP server, Prometheus helper, and OTel example. No integrated security UI. | Verity Memory Control Room, coherent CLI, quarantine, revoke/replay, policy, and ledger workflows. |
| Shadow behavior | A permissive policy can detect and allow, but there is no explicit shadow mode or actual versus would-have action pair. | Explicit enforce/shadow modes with both actions, policy version, provider state, and a confirmed one-memory current-policy rescan that can atomically revoke and replay an unsafe shadow admission. Automatic policy-wide rescanning is not implemented. |
| Storage backends | Only `InMemoryStore` is implemented; callers may provide a custom synchronous protocol implementation. | SQLite authoritative event ledger plus rebuildable materialized views for the MVP. |

## Existing Donor Detectors

The default guard includes regex/heuristic prompt injection, secrets/PII, size
anomaly, rapid-change churn, protected keys, cross-task contamination, and agent
self-reinforcement. Tool abuse, privilege escalation, excessive autonomy, and an
optional ML detector are shipped but not enabled in the default pipeline.

## Existing Surfaces

- FastAPI routes include scan, write, read, events, stats, health, file scan,
  and reset.
- A separate stateless MCP server exposes entry and batch scanning plus
  pre-store and pre-recall checks, using its own regex logic.
- Integrations include LangChain chat history, CrewAI, LlamaIndex, separate
  LangChain middleware, and an AutoGen source package.
- Optional Prometheus helpers and an OpenTelemetry callback example exist; they
  are not a durable native audit system.

## Tests and Limitations Observed

- Core configured suite: **96 passed, 10 expected failures**.
- The coverage result omits streaming, ML, REST, CLI, integrations, metrics,
  middleware, scan API, RAG, and tools.
- Expected failures cover split credentials, time bombs, multi-write
  correlation, Base64, chained fragments, homoglyphs, read/write taint,
  non-English injection, and fake-error injection.
- The current stream scanner raises an attribute error because it calls
  `detector.detect()` while detector implementations expose `inspect()`.
- Detector exceptions and ML failures can be treated as clean, a pattern Verity
  explicitly rejects.
- Events, quarantine, baselines, and snapshots are process-local and non-durable.
- The default REST bind/CORS/reset posture and raw matched metadata are not
  carried into Verity Cordon.

## Code Provenance

The initial Verity Cordon implementation is clean-room and does not copy donor
source. `THIRD_PARTY_NOTICES.md` records the donor as research prior art. If a
future file is copied, adapted, or substantially derived, that file must retain
applicable Apache-2.0 notices, identify this exact source commit, and be marked
as modified before release.
