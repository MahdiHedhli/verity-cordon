# ADR 0003: Controlled Codex Memory Plane

**Status**: Accepted

**Date**: 2026-07-15

## Context

Current public Codex documentation provides local memory controls and lifecycle
hooks but no native memory read/write interception hook. Codex also describes
its local memory files as generated state that should not be manually edited as
the primary control surface.

## Decision

Disable native local memory generation and use for the controlled Verity
environment. Capture selected evidence through documented command hooks, send
it to a bounded local daemon, and inject only eligible typed memory through
documented `SessionStart` developer context.

## Consequences

- The integration is supportable and claim-bounded.
- Hook ordering, transcript file shape, and unhooked tool paths are not assumed.
- Daemon or ledger failure produces no Verity memory injection.
- The product does not claim transparent protection for ChatGPT web memory,
  Codex cloud, or undocumented internals.
