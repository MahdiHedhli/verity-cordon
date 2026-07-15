# Devpost Submission Draft

## Title

Verity Cordon

## One-Line Pitch

A tamper-evident memory firewall for Codex: verifiable memory, revocable trust.

## Project Description

Codex can carry useful knowledge between tasks, but durable memory creates a new
security boundary: untrusted content from tools, documentation, imported files,
or model output can be cleaned up into a persistent instruction and regain
influence in a later session.

Verity Cordon makes durable memory explicit, attributable, policy-governed, and
revocable. Candidate memories are traced to evidence, screened for secrets,
evaluated by deterministic detectors and a structured GPT-5.6 semantic
assessment, and resolved by a versioned deterministic policy. Only eligible
memory is supplied to future Codex sessions through documented lifecycle hooks.

Every decision enters a signed, hash-chained local event ledger. If a previously
trusted memory is later identified as malicious, an operator can revoke that
exact memory and reconstruct the active view without erasing unrelated
knowledge.

## Problem

Prompt-injection defenses often focus on the current context window. Durable
memory changes the time horizon: an external tool can ask an agent to preserve a
hidden operational rule, and a later session may receive that rule without the
original warning signs or source context. Developers need a controlled memory
plane with attribution, explicit trust decisions, safe evaluation, and
retroactive correction.

## Solution

Verity Cordon provides:

- A documented Codex controlled memory plane
- Atomic candidate extraction and provenance
- Local secret sanitization before model calls
- Deterministic persistence, authority, cross-task, and size detectors
- Isolated GPT-5.6 structured semantic assessment
- Pydantic-validated versioned policy with enforce and shadow modes
- A signed append-only event chain and deterministic active view
- Quarantine, manual review, selective revocation, and replay
- Transactional streamed memory writes
- A calm, local Memory Control Room
- Offline synthetic judging and an explicit live GPT-5.6 path

## How It Works

Supported Codex hooks send bounded evidence to a loopback async daemon. Verity
screens secrets, extracts atomic candidates, fans out deterministic detectors,
and optionally asks GPT-5.6 for schema-constrained semantic risk evidence. A
deterministic policy chooses allow, redact, quarantine, or block.

The outcome, provenance, versions, digests, and signatures are appended to
SQLite as an ordered event chain. Eligible events materialize an active memory
view. At documented `SessionStart`, a thin hook returns only typed, delimited,
budgeted approved memory as developer context. Daemon or ledger failure results
in no injected memory.

## Built With

- Codex and GitHub Spec Kit
- GPT-5.6 through the OpenAI Responses API and Structured Outputs
- Python, asyncio, Pydantic, FastAPI, aiosqlite, cryptography, Typer
- React, TypeScript, Vite, Vitest
- SQLite, SHA-256, Ed25519
- pytest, Ruff, mypy, OpenTelemetry API

## How Codex Was Used

Codex drove the work end to end in the primary project thread: live rules and
API research, donor inspection, Spec Kit source of truth, architecture,
implementation, adversarial tests, UI, documentation, browser verification,
and repository publication. The operator set the product identity, security
constitution, claims, scope cuts, and release decisions. Bounded subagents were
used for research, contracts, and isolated review—not the core build.

## How GPT-5.6 Is Used at Runtime

GPT-5.6 performs two distinct schema-constrained tasks after local secret
sanitization: extracting atomic candidate memories and assessing semantic risk
such as persistence intent, authority claims, exfiltration, tool hijack, and
cross-task contamination. The call has no tools, durable memory, conversation,
or previous response. The model recommends risk; deterministic policy retains
final authority. Offline mode uses visibly labeled recorded fixtures and never
pretends they are live.

## Challenges

- Designing a supported Codex integration without claiming undocumented native
  memory interception
- Making tamper evidence independently verifiable rather than decorative
- Preserving explainability while keeping raw secrets out of model calls,
  telemetry, and operator list views
- Combining shadow evaluation, enforcement, revocation, and replay into a demo
  under three minutes
- Separating donor prior art from clean hackathon contributions

## Accomplishments

- A complete local memory-security lifecycle rather than a scanner-only proof
  of concept
- Event-specific revocation that preserves unrelated knowledge
- Transactional streamed writes that cannot partially commit
- Honest actual versus would-have shadow actions
- One-command offline path using the real policy, ledger, view, API, and UI
- Test-backed claim boundaries and a detailed threat model

## What We Learned

Durable memory is not just another content field. It is a trust transition
across time. Provenance, policy, audit integrity, and recovery need to be
designed together. Semantic models are useful at ambiguous classification, but
they should supply evidence rather than become the final trust authority.

## What Is Next

The immediate roadmap is deeper evaluation and hardened local operations. Other
storage backends, agent adapters, remote policy, enterprise identity, packaged
local models, HSM-backed keys, exporter ecosystems, and managed services are
intentionally deferred behind separate numbered Spec Kit features.

## Testing Instructions

```bash
./scripts/bootstrap.sh
./scripts/demo-offline.sh
```

Open the printed loopback URL. Reproduce shadow admission, enforcement,
cross-session injection, selective revocation, rebuild, and ledger verification.
Run the full critical suite with `./scripts/verify.sh`. Live GPT-5.6 instructions
are in the README and require a local `OPENAI_API_KEY` that is never printed.

## Required Final Links

- **Repository**: `REPLACE_WITH_PUBLIC_REPOSITORY_URL`
- **Public YouTube demo**: `REPLACE_WITH_PUBLIC_YOUTUBE_URL`
- **Codex `/feedback` Session ID**: `REPLACE_WITH_REAL_SESSION_ID`
