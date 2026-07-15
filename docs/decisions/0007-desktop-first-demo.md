# ADR 0007: Desktop-First Delayed-Poisoning Demo

**Status**: Accepted

**Date**: 2026-07-15

## Context

The original judge path emphasized the command line and Control Room. Codex
Desktop now provides the clearest primary demonstration: an operator can see an
untrusted tool response in one task, inspect Verity's decision, and open a fresh
task to verify that only approved memory crosses the boundary.

The Trojan Hippo research provides a compelling delayed-trigger threat model,
but importing or running the benchmark would add a large dependency tree,
external model calls, possible telemetry, and attribution complexity. A demo
must also never read real email, environment data, files, credentials, or send
anything externally.

## Decision

Use Codex Desktop as the primary human-facing demo and retain the CLI as a
secondary deterministic harness over the same product pipeline.

Create an original clean-room synthetic fixture inspired by the Trojan Hippo
attack model:

1. A local documentation tool returns useful synthetic release guidance mixed
   with a disguised instruction to preserve a permanent validation rule.
2. In shadow mode, Verity records admission as the actual action and quarantine
   or block as the would-have action. The UI explicitly says this is not active
   protection.
3. A later synthetic release task may demonstrate the dormant trigger only
   against a local inert `demo_artifact_sink` that accepts fixed allow-listed
   markers and has no external transmission capability.
4. In enforcement mode, the same operational instruction is quarantined or
   blocked while the useful fact remains eligible for approved memory.
5. The operator revokes the earlier shadow-admitted memory, rebuilds the active
   view, preserves unrelated memory, and verifies the signed event chain.

Demo-only MCP configuration is separate from normal Verity installation. Setup
must be previewable, confirmation-gated, digest-receipted, expected-state and
drift aware, and reversible without changing unrelated Codex configuration.
Teardown removes demo integration state but does not delete the ledger, signing
key, or memory history.

The Desktop script requires a terminal signed evaluation before claiming that a
fresh task is protected. The CLI fallback remains available when Desktop cannot
be configured and exercises the real policy, ledger, materialization,
revocation, and Control Room paths with recorded semantic fixtures.

The project credits the benchmark repository at inspected commit
`a67d3261338120c606fcf6afda2547f622809922` and the primary paper. It describes
the scenario as **Trojan Hippo-inspired**, not as a benchmark reproduction or a
measurement of benchmark attack-success rates.

## Consequences

- The primary narrative matches the product boundary: memory moves between
  Codex tasks only after an attributable Verity decision.
- The Desktop sequence contains a manual UI step and must be rehearsed and
  honestly labeled; browser or CLI tests do not prove Desktop UI behavior.
- Judge setup mutates local Codex configuration only after preview and explicit
  confirmation, and teardown must preserve unrelated settings.
- The fixture remains safe to publish because every value is visibly synthetic,
  the sink rejects unexpected data, and neither component reads host state or
  uses external networking.
- Reported results are limited to repository tests and included evaluation
  fixtures. Research-paper persistence and attack-rate numbers are contextual,
  not Verity performance claims.

## References

- [Trojan Hippo paper](https://arxiv.org/abs/2605.01970)
- [Inspected Trojan Hippo benchmark](https://github.com/debesheedas/trojan-hippo-benchmark)
- [Build Codex plugins](https://learn.chatgpt.com/docs/build-plugins)
- [Codex hooks](https://learn.chatgpt.com/docs/hooks)
- [Codex memories](https://learn.chatgpt.com/docs/customization/memories)
