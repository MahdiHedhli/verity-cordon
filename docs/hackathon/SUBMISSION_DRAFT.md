# Devpost Submission Draft

## Title

Verity Cordon

## One-Line Pitch

A tamper-evident memory firewall for Codex: verifiable memory, revocable trust.

## Project Description

Codex can carry useful knowledge between tasks, but durable memory creates a new
security boundary: untrusted content from tools, documentation, imported files,
or model output can be cleaned up into a persistent instruction and regain
influence in a later session. The primary demonstration invokes a reviewed,
local Trojan Hippo-inspired poisoned-docs fixture from a terminal while the
running Control Room shows shadow admission, deterministic enforcement of the
identical payload, quarantine, signed event history, and ledger verification.
It does not claim Codex Desktop origin, fresh-session injection footage,
revocation footage, or live-model attestation.

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
- A reversible, confirmation-gated Codex Desktop demonstration fixture
- Atomic candidate extraction and provenance
- Local secret sanitization before model calls
- Deterministic persistence, authority, cross-task, and size detectors
- Direct-API and explicitly lower-isolation Codex subscription paths for
  GPT-5.6 structured semantic evidence
- Pydantic-validated versioned policy with enforce and shadow modes
- A signed append-only event chain and deterministic active view
- Quarantine, manual review, targeted current-policy rescan, selective
  revocation, and replay
- Transactional streamed memory writes
- A calm, local Memory Control Room
- Offline synthetic judging and an explicit live GPT-5.6 path
- A clean-room Trojan Hippo-inspired delayed-trigger scenario using only fixed
  synthetic values and an inert local sink

## How It Works

Supported Codex hooks send bounded evidence to a loopback async daemon. Verity
screens recognized secrets, atomically records signed capture plus a bounded
sanitized queue row, then acknowledges the hook before background extraction or
semantic work. The worker extracts atomic candidates, fans out deterministic
detectors, and optionally asks GPT-5.6 for schema-constrained semantic risk
evidence. A deterministic policy chooses allow, redact, quarantine, or block.

The direct OpenAI path uses the Responses API with no tools. The optional Codex
subscription path instead invokes one bounded, read-only Codex child using the
operator's supported ChatGPT sign-in. It does not read Codex credential files,
does not require an OpenAI API key, forwards only an allow-listed environment,
rejects tool events or malformed output, and never silently switches provider.
Because this path runs an agentic Codex process, the UI labels it
`agentic_sandboxed` rather than making a tool-free isolation claim.

The outcome, provenance, versions, digests, and signatures are appended to
SQLite as an ordered event chain. Eligible events materialize an active memory
view. At documented `SessionStart`, a thin hook returns only typed, delimited,
budgeted approved memory as developer context. Daemon or ledger failure results
in no injected memory.

## Built With

- Codex Desktop, Codex CLI, and GitHub Spec Kit
- An OpenAI Responses API provider configured to request `gpt-5.6`, plus an
  exercised Codex ChatGPT-subscription path that requested `gpt-5.6-luna`; the
  current Codex event stream does not attest the returned remote model
- Python, asyncio, Pydantic, FastAPI, aiosqlite, cryptography, Typer
- React, TypeScript, Vite, Vitest
- SQLite, SHA-256, Ed25519
- pytest, Ruff, mypy, OpenTelemetry API

## How Codex Was Used

Codex drove the work end to end in the primary project thread: current rules and
API research, donor inspection, Spec Kit source of truth, architecture,
implementation, adversarial tests, UI, documentation, browser verification,
and repository publication preparation. In Sprint 002, Codex also implemented
and adversarially tested the subscription subprocess boundary, reversible
Desktop fixture setup, delayed-attack matrix, and Control Room timeline. The
operator set the product identity, security constitution, claims, scope cuts,
Desktop-first direction, subscription-access goal, attack-model reference, and
release decisions. Bounded subagents were used for research, contracts,
isolated review, Codex plugin/hook integration, and secondary test and
documentation work. The primary thread reviewed and integrated that work and
retained the majority of the core build.

## How GPT-5.6 Is Configured at Runtime

Verity's explicit live providers request GPT-5.6-family identifiers for two
schema-constrained tasks after local secret sanitization: extracting atomic
candidate memories and assessing semantic risk such as persistence intent,
authority claims, exfiltration, tool hijack, and cross-task contamination. The
model output recommends risk; deterministic policy retains final authority.
Offline mode uses visibly labeled recorded fixtures and never pretends they are
live.

The direct Responses API provider has no tools, durable memory, conversation,
or previous response. The separate subscription provider is deliberately
labeled `agentic_sandboxed`: it runs a bounded Codex child, rejects any observed
tool activity, and makes no claim that tools are absent inside the Codex binary.
On 2026-07-16, the final hardened no-key pipeline completed through supported
ChatGPT sign-in. It requested `gpt-5.6-luna`, recorded
`live_codex_subscription` with `agentic_sandboxed` isolation, and exercised
both live candidate extraction and live semantic assessment. The run processed
45 synthetic candidates: deterministic policy allowed 31 and quarantined 14.
Selective recovery revoked 8 memories. Verification reported 562 signed
events, a complete anchored chain, and a consistent materialized view. One
final rendered `SessionStart` context contained 6 approved memory records, and
the fixed synthetic attack markers were absent from that context. Earlier
unavailable-model, strict-schema, and rate-limit attempts remained fail closed
and led to regression coverage before the final run. This proves bounded
execution on one host and date, not universal plan entitlement, stable latency,
remote-model attestation, a credentialed direct-API run, or a manually observed
Desktop app task. In particular, `requested_model=gpt-5.6-luna` is local
configuration evidence; `returned_model` remains null for subscription
assessments.

## Challenges

- Designing a supported Codex integration without claiming undocumented native
  memory interception
- Making tamper evidence independently verifiable rather than decorative
- Preserving explainability while keeping raw secrets out of model calls,
  telemetry, and operator list views
- Combining shadow evaluation, enforcement, revocation, and replay into a demo
  under three minutes
- Separating donor prior art from clean hackathon contributions
- Using the Trojan Hippo threat model without copying, running, or claiming to
  reproduce its benchmark
- Using supported ChatGPT subscription execution while preserving explicit
  provider identity, process bounds, and honest lower-isolation claims

## Accomplishments

- A complete local memory-security lifecycle rather than a scanner-only proof
  of concept
- Event-specific revocation that preserves unrelated knowledge
- Transactional streamed writes that cannot partially commit
- Honest actual versus would-have shadow actions
- One-command offline path using the real policy, ledger, view, API, and UI
- A Codex Desktop-first setup that is previewable, confirmation-gated,
  receipt-bound, drift-aware, and reversible without changing unrelated config
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

The guaranteed no-key judge path is:

```bash
./scripts/bootstrap.sh
export VERITY_DATA_DIR=.verity-demo
./scripts/demo-offline.sh
```

It exercises the real policy, signed ledger, materialized view, local API, and
Control Room with visibly labeled recorded semantic fixtures.

For the optional subscription-backed Desktop path:

Before any confirmed Codex configuration change, close every ChatGPT Desktop
task, exit Codex CLI TUI and IDE Codex sessions, and fully quit the ChatGPT
desktop app. Keep clients closed while each user-wide mutation runs. The first
installer call below is a read-only preview; apply `--yes` only after reviewing
that preview and the exact hook definitions.

```bash
./scripts/bootstrap.sh
./scripts/verify.sh
export VERITY_DATA_DIR="$PWD/.verity-desktop-demo"
export VERITY_SEMANTIC_PROVIDER=codex_subscription
export VERITY_CODEX_MODEL=gpt-5.6-luna
uv run verity ledger init-key
uv run verity install-codex --source-root .
export VERITY_CODEX_INSTALL_DIGEST="<copy preview.preview_digest after reviewing hooks, artifacts, and hook runtime>"
uv run verity install-codex --source-root . \
  --expected-preview-digest "$VERITY_CODEX_INSTALL_DIGEST" --yes
```

The install preview digest is verified before any mutation, but it does not
grant Codex hook trust. After installation, use Codex CLI `/hooks` to inspect
and trust the exact installed Verity command hook hash, then continue:

```bash
export VERITY_CONFIRM_HOOK_TRUST=1
./scripts/demo-desktop.sh
```

After digest-confirmed setup, start `uv run verity serve` in terminal A. In
terminal B, run `uv run verity doctor --confirm-hook-trust` and then the printed
`verity demo desktop-status` command before reopening Desktop.

The Desktop helper previews the dedicated setup and prints the explicit setup,
status, startup, and teardown commands; it does not automate or scrape the
Desktop UI. Follow
`specs/002-codex-desktop-subscription-defense/quickstart.md`, restart Desktop
after confirmed setup, keep the loopback Control Room visible, and use new tasks
for the plant and trigger steps. The exercised MCP entry is user-wide in
`$CODEX_HOME/config.toml`; the dedicated workspace is not project-local
isolation. Close unrelated tasks and quit Desktop around each mutation. Wait
for a signed terminal outcome before claiming protection, then immediately
quit Desktop and apply a separately digest-confirmed teardown. Teardown removes
only receipt-bound demo artifacts and preserves the normal plugin, unrelated
Codex config, ledger, key, and memory history.

Subscription semantic mode uses supported ChatGPT sign-in and requires no
`OPENAI_API_KEY`. Availability depends on the operator's plan, workspace,
model access, and usage limits; an unavailable live provider fails explicitly
without substituting fixtures or the direct API.

Open the printed loopback URL for either applicable path. In offline mode,
inspect shadow admission, enforcement, selective
rescan/revocation, simulated SessionStart rendering, rebuild, and ledger
verification. Run the full critical suite with `./scripts/verify.sh`.

The final recorded gate passed 785 backend tests plus 13 isolated
example/plugin tests at 81% backend coverage, all 11 Control Room tests,
frontend type checking, lint, and production build, and both configured
dependency audits. The 20-sample synthetic evaluation reported 0
fixture-scoped false positives and 0 fixture-scoped false negatives; these are
dataset results, not universal accuracy claims.

For stage reliability, the one-command offline path invokes the reviewed fixture
over bounded stdio under a minimal environment, validates its inert safety flag,
and supplies the returned synthetic response directly to the same memory
service. It does not claim to launch Codex.

## Attribution and Limitations

The delayed-trigger scenario is inspired by the
[Trojan Hippo paper](https://arxiv.org/abs/2605.01970) and
[benchmark repository](https://github.com/debesheedas/trojan-hippo-benchmark).
Verity does not vendor, execute, reproduce, or compare itself against that
benchmark. The fixture, fixed synthetic markers, inert local sink, and tests are
original clean-room materials; paper-reported attack rates are not Verity
results.

Verity provides tamper-evident local history, not tamper-proof storage. It does
not verify arbitrary factual truth, completely prevent prompt injection,
intercept undocumented Codex internals, control all outbound information flow,
or protect a compromised host, user account, signing key, operating system, or
Codex binary. “Codex Desktop” means the Codex experience in the supported
ChatGPT desktop app and is the primary demo surface on macOS; CLI is the
deterministic harness, Linux is an intended secondary target, and Windows is
unverified. Automated tests cover the integration contract, but Desktop-only
observations are reported separately as manual smoke evidence.

## Required Final Links

- **Devpost project**: https://devpost.com/software/verity-cordon
  (submission `1095381`; accepted 2026-07-17 at 20:20:22 EDT)
- **Repository**: https://github.com/MahdiHedhli/verity-cordon
- **Superseded Unlisted review video**: https://youtu.be/c-a7sLusXv4
  (1:24; retained only as review evidence and not suitable for submission
  because its voiceover omitted the required Codex/GPT-5.6 explanation)
- **Public YouTube demo**: https://youtu.be/tREkD6WbolI
  (1:50; published Public on 2026-07-17; assigned to the
  `OpenAI Hack-a-thon` playlist; YouTube Copyright and Community Guidelines
  checks passed)
- **Codex task/session ID**: `019f6486-18b4-74b2-b195-3d513f4dc454`
  (verified through Codex task status; not represented as `/feedback` output)
