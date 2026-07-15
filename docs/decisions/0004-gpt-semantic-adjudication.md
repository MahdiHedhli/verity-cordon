# ADR 0004: GPT-5.6 Semantic Adjudication

**Status**: Accepted

**Date**: 2026-07-15

## Context

Regex and structural rules are necessary but cannot reliably distinguish a
benign discussion from an indirect persistence or authority claim. A semantic
model can add useful risk evidence, but allowing it to grant trust would make
policy non-deterministic and difficult to audit.

## Decision

Use the current `gpt-5.6` alias for schema-constrained candidate extraction and
semantic risk assessment after local secret sanitization. Calls have no tools,
memory, conversation, or prior response, use bounded input and timeout, and set
`store=False`. Deterministic versioned policy retains final authority.

## Consequences

- GPT-5.6 contributes meaningfully to runtime behavior without becoming the
  trust root.
- Model, prompt, schema, provider state, and sanitized digest are recorded.
- Offline mode uses visibly labeled recorded fixtures; live failure never
  silently falls back to them.
- Because no dated immutable Sol snapshot is documented, live results are not
  claimed to be bit-for-bit reproducible.
