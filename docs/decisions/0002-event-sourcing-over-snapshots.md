# ADR 0002: Event Sourcing over Snapshot Rollback

**Status**: Accepted

**Date**: 2026-07-15

## Context

Whole-store snapshot rollback can remove unrelated knowledge and rewrites state
without preserving the complete reason for a correction. Verity Cordon must
revoke one memory and independently verify its decision history.

## Decision

Use signed append-only events, event-specific revocation, and deterministic
materialization as the primary recovery model. SQLite projections are derived
and rebuildable; they are not the audit authority.

## Consequences

- One memory can be revoked without erasing unrelated memories.
- Verification can detect payload alteration, deletion, and reordering.
- Append and projection updates need careful atomic transaction boundaries.
- Snapshot checkpoints may be considered later only as replay optimizations,
  never as destructive history replacement.
