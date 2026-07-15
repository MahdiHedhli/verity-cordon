# Research: Codex Desktop Subscription Defense

**Feature**: `002-codex-desktop-subscription-defense`

**Verified**: 2026-07-15 (America/New_York)

This document records the sources and runtime observations that constrain the
Desktop-first sprint. Primary sources govern architecture and claims. The
linked pages were current when inspected; the installed Codex executable,
generated contracts, and repository tests remain the evidence for the shipped
build.

## Decision Summary

- Codex Desktop is the primary interactive demo surface. A CLI harness remains
  the deterministic fallback and exercises the same Verity policy, ledger,
  materialized view, and integration contracts.
- Add an explicit `codex_subscription` semantic provider that invokes supported
  local Codex non-interactive execution under a ChatGPT subscription sign-in.
  It does not require an `OPENAI_API_KEY`.
- Treat subscription-backed evaluation as a lower-isolation, agentic semantic
  provider. Verity requests no tool use and rejects observed tool activity, but
  it does not claim that the Codex runtime is tool-free.
- Keep provider selection explicit. Authentication, capacity, timeout, tool
  activity, malformed output, or process failure must not trigger a silent
  fallback to direct API or recorded-fixture evaluation.
- Demonstrate a clean-room, synthetic, Trojan Hippo-inspired delayed poisoning
  scenario. It is not a reproduction of the benchmark and does not inherit the
  benchmark's reported attack rates.

## Codex Authentication and Subscription Use

**Official sources**:

- [Codex authentication](https://learn.chatgpt.com/docs/auth)
- [Codex pricing and plan access](https://learn.chatgpt.com/docs/pricing)
- [Codex non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode)
- [Codex app server](https://learn.chatgpt.com/docs/app-server)

**Local verification**:

- Inspected Codex CLI: `codex-cli 0.144.4`.
- `codex login status` returned `Logged in using ChatGPT` on the inspected host.
- `codex exec` exposes supported non-interactive controls for ephemeral runs,
  isolated configuration, read-only sandboxing, JSONL events, a strict output
  schema, and writing the final response to a designated file.

**Decision**: The MVP subscription provider uses `codex exec`, not credential
file access and not an undocumented Desktop transport. The provider first calls
the supported login-status command, requires a successful ChatGPT sign-in, and
records only a boolean readiness state and a bounded error class. It must not
read, copy, parse, print, or persist Codex credential files or bearer tokens.

The provider launches an absolute, previously verified Codex executable without
a shell. Sanitized evidence is passed through standard input, never the command
line. The child runs in a private empty working directory with a minimal
environment and uses the supported equivalents of:

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
  --output-schema <private-schema-file>
  --output-last-message <private-output-file>
  --color never
  --json
  -
```

`--ignore-user-config` plus the private empty working directory prevents the
normal user and project plugin/MCP configuration from entering the semantic
run. A defense-in-depth child marker also makes the Verity hook adapter ignore
the run if hooks are unexpectedly loaded. The exact argument vector is covered
by a contract test because supported CLI syntax can change.

The inspected runtime exposes the listed feature names, but does not expose a
documented global MCP-disable feature. An empty `mcp_servers={}` override was
tested and does not clear configured servers because configuration is
deep-merged. The provider therefore relies on `--ignore-user-config` and the
empty non-repository cwd to exclude user/project MCP configuration, disables
the verified high-risk agentic feature surfaces listed above, rejects any
observed tool event, and retains the lower-isolation claim. These controls do
not prove that future managed or built-in extension surfaces are absent.

The configured executable is accepted only when its absolute search/link and
resolved-target ancestors are owned by the effective user or root and are not
group- or world-writable. Relative or empty PATH entries are ignored. Validated
`HOME` and `CODEX_HOME` must be absolute, existing, current-user-owned,
non-symlink directories that are not group- or world-writable. Every existing
ancestor through the filesystem root must be effective-user/root-owned and not
group- or world-writable, and the identity/mode chain is rechecked before
launch. This keeps subscription auth available to Codex without treating an
attacker-replaceable parent or arbitrary parent environment as trusted.

`gpt-5.6` is the sprint's requested default model value, not a promise that
every subscription or workspace exposes it. The current CLI exposes no model
listing command used by this integration. Model availability is established
only by an explicit live invocation; unavailable access fails content-safely
with no provider fallback.

**Output boundary**: JSONL progress and the final structured file are both
untrusted. Verity applies byte and line limits, rejects duplicate JSON keys,
rejects any command, file, web, MCP, or other tool event, validates the final
object against the same strict identity/digest schema as the direct provider,
and terminates the process group on timeout or cancellation. Private temporary
directories and files use restrictive permissions and are removed after the
result is classified.

**Isolation claim**: These controls reduce inherited context and fail safely on
observable tool activity. They do not prove that the Codex runtime contains no
tools, and they do not inherit the direct Responses API provider's tool-free or
request-storage claims. The Control Room must label this provider
`live_codex_subscription` and display its lower-isolation status.

## Codex Desktop Integration Surface

**Official sources**:

- [Build Codex plugins](https://learn.chatgpt.com/docs/build-plugins)
- [Codex hooks](https://learn.chatgpt.com/docs/hooks)
- [Codex memories](https://learn.chatgpt.com/docs/customization/memories)
- [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)

**Decision**: Continue using the documented Verity plugin, command hooks,
memory controls, and MCP configuration shared by supported Codex surfaces.
Desktop is a presentation and operator-workflow choice, not a license to patch
Desktop internals. The existing thin hook-to-daemon contract remains the
security boundary.

The demo-only poisoned-documentation MCP entry is installed separately from the
normal Verity plugin. Setup must show a preview, require confirmation, record a
digest-bound receipt, preserve unrelated Codex configuration, detect drift,
and support safe teardown. Teardown removes demo integration state but preserves
the Verity ledger, signing key, and memory history.

A Desktop demonstration is not considered protected until the captured evidence
has a terminal signed decision. If evaluation is pending or unhealthy, the UI
must say so and the operator must not start the claimed clean follow-up task.
When Desktop is unavailable, the CLI fallback uses the same fixture and product
pipeline rather than substituting a mocked security decision.

## Persistent-Memory Poisoning Literature

The following primary sources informed the attack model and evaluation cases.
They are research inputs, not evidence that Verity defeats every technique they
describe.

| Primary source | Relevant contribution | Verity use |
|---|---|---|
| [Trojan Hippo](https://arxiv.org/abs/2605.01970) | Delayed-trigger poisoning planted through untrusted content and activated in a later task after memory persistence. | Clean-room synthetic dormant-instruction scenario and cross-task acceptance test. |
| [MPBench](https://arxiv.org/html/2606.04329) | A broader benchmark and taxonomy of poisoning paths through explicit, inferred, compacted, and procedural memory. | Coverage taxonomy for deterministic and adversarial fixtures. |
| [MemoryGraft](https://arxiv.org/abs/2512.16962) | Persistent poisoning and behavioral transfer through long-term agent memory. | Cross-session contamination and provenance cases. |
| [Hidden in Memory](https://arxiv.org/abs/2605.15338) | Memory-resident attack behavior that can remain latent until later interaction. | Dormancy and later-trigger abuse case. |
| [MemPoison](https://arxiv.org/abs/2605.29960) | Poisoning techniques and evaluation of memory-mediated agent behavior. | Indirect and persistence-focused adversarial fixtures. |
| [MemMorph](https://arxiv.org/abs/2605.26154) | Adaptive or transformed memory poisoning that challenges surface-pattern matching. | Obfuscation and semantic-review cases without universal-protection claims. |

[EmergentMind's persistent-memory-poisoning topic page](https://www.emergentmind.com/topics/persistent-memory-poisoning)
was inspected only as a secondary literature index. It is useful for discovering
related work, but its rendered equations and numeric summaries were not reliable
enough to serve as implementation or claim evidence. No prose, diagrams, or
datasets are copied from it.

### Coverage Taxonomy

The primary literature motivates four memory-write channels that Verity should
represent in research and tests:

1. Explicit instructions to store attacker content.
2. System- or agent-inferred memory writes derived from observed content.
3. Compaction-inferred memory writes that elevate salient attacker content.
4. Experience-to-procedure writes that turn prior behavior into a reusable
   skill or operating rule.

The active sprint uses six attack categories for evaluation-fixture labeling:

- explicit command insertion;
- conditional command insertion;
- salience-driven compaction poisoning;
- policy-conformant fact injection;
- false precedent insertion; and
- skill or procedure insertion.

The demo emphasizes conditional command insertion because it provides a clear
write-now, trigger-later narrative. The remaining categories inform tests and
future evaluation expansion; their presence in this taxonomy does not create
new active product scope.

## Trojan Hippo Benchmark Inspection

**Repository**:
[debesheedas/trojan-hippo-benchmark](https://github.com/debesheedas/trojan-hippo-benchmark)

**Inspected branch and commit**: `main` at
`a67d3261338120c606fcf6afda2547f622809922`

**Inspection date**: 2026-07-15

**Repository license**: Apache-2.0

**Paper license**: CC BY 4.0 as stated by the paper distribution.

**Relevant findings**:

- The benchmark models a one-time poisoning opportunity through untrusted
  content, followed by a later topic-related trigger that can activate a
  persistent instruction.
- Its example attack uses simulated email/tool behavior and evaluates delayed
  activation after varying numbers of intervening sessions.
- The repository is large and contains vendored components and benchmark
  infrastructure. Some execution paths make external model calls, and the
  included Mem0-derived code can emit PostHog telemetry unless separately
  disabled. Debug paths may retain raw content.
- The benchmark's simulated email tool is not a production exfiltration system,
  but running the repository is not required for the Verity demo and would add
  unnecessary network, data-retention, attribution, and dependency risk.

**Decision**: Do not vendor, import, or execute the benchmark in the judge path.
Use an original, compact local fixture that returns useful synthetic release
guidance plus a disguised instruction to preserve a permanent validation rule.
The later trigger may attempt to send an allow-listed synthetic manifest marker
to a local inert `demo_artifact_sink`. The sink never reads process environment,
files, email, credentials, or personal data; it rejects any non-synthetic value
and cannot transmit externally.

The repository and paper are credited as attack-model inspiration. The demo is
described as **Trojan Hippo-inspired**, not as a benchmark reproduction,
compatible implementation, or comparative score. Paper-reported attack success
rates and persistence after many sessions are not Verity evaluation results.

## Semantic Provider Alternatives

### Direct OpenAI API provider only

Retains the strongest request-level isolation and structured-output contract,
but requires separate API credentials and does not meet the subscription-access
goal. It remains supported and is not replaced.

### Codex app server

Offers a structured programmatic protocol and may be appropriate for a future
integration. It adds a longer-lived service and more surface area than needed
for this bounded provider. The MVP chooses one-shot `codex exec`, which is
easier to time-bound and clean up.

### Driving the Desktop UI for semantic calls

Rejected. UI automation is brittle, harder to isolate, and unnecessary because
supported non-interactive Codex execution can use the same local ChatGPT sign-in.
Desktop remains the human-facing demo and task surface.

### Silent fallback to fixtures or the API

Rejected. It would make provider identity, cost, isolation, and judge-facing
claims ambiguous. Provider failure remains explicit policy input; high-risk
memory is quarantined by the deterministic policy.

## Risks and Required Verification

- Codex CLI arguments and JSONL event names can evolve. Contract tests must
  validate the supported argument vector and conservative tool-event rejection.
- ChatGPT subscription availability and rate limits are external state. The
  offline fixture path remains the no-key judge fallback, but is always labeled
  recorded-fixture evaluation.
- Built-in agent tools may exist even after configuration isolation. Any
  observed tool activity invalidates the result; the product makes no stronger
  claim.
- Desktop setup is a local configuration mutation. Preview, confirmation,
  receipts, expected-head checks, drift refusal, and reversible teardown are
  mandatory.
- Literature examples can become accidental marketing overclaims. Documentation
  and UI metrics must report only behavior measured by repository fixtures and
  tests.
