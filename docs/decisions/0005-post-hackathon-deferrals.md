# ADR 0005: Post-Hackathon Deferrals

**Status**: Accepted

**Date**: 2026-07-15

## Context

The broader memory-security roadmap includes storage, agent, policy, telemetry,
enterprise, cryptographic, governance, and managed-platform work. Pulling these
items into the Build Week feature would create untested scaffolding and weaken
the Codex demonstration.

## Decision

Preserve the enterprise memory-mesh roadmap but keep it outside the active
hackathon task graph.

“Verity Cordon will expose stable internal boundaries for storage, detection,
semantic review, policy retrieval, event publishing, and agent integration
during the hackathon. Only implementations required for the Codex vertical
slice will be built. Additional backends, agent integrations, remote
control-plane capabilities, enterprise identity, packaged local models, and
exporter ecosystems are intentionally deferred. This is a product and delivery
decision, not an accidental omission.”

The complete `VC-FUT-001` through `VC-FUT-030` register lives in
`docs/product/post-hackathon-roadmap.md`.

## Promotion Rule

A deferred item may become active only after it receives:

1. Its own numbered Spec Kit feature
2. Prioritized user stories
3. Independent acceptance tests
4. A constitution-compliant plan
5. A generated task graph
6. A milestone
7. An explicit scope decision

## Consequences

- `specs/001-codex-memory-firewall/tasks.md` contains no deferred implementation.
- Interfaces exist only where the active Codex slice consumes them.
- Public copy distinguishes future direction from tested support.
- Promotion requires explicit governance rather than opportunistic scope growth.
