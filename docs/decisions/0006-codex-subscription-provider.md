# ADR 0006: Codex Subscription Semantic Provider

**Status**: Accepted

**Date**: 2026-07-15

## Context

Verity Cordon's live GPT-5.6 semantic provider uses the OpenAI API and therefore
requires API credentials. Codex subscribers may already have a supported local
ChatGPT sign-in through Codex Desktop and CLI. The sprint needs a live semantic
path that can use that subscription without accessing credential files or
misrepresenting the security properties of an agentic Codex run.

`codex exec` is a documented non-interactive surface and accepts strict output
schemas, ephemeral execution, sandbox controls, isolated configuration, and
bounded machine-readable output. Unlike the direct Responses API call, however,
the Codex runtime can expose agent tools. Configuration flags can reduce that
surface, but they do not prove a tool-free execution environment.

## Decision

Add an explicit `codex_subscription` semantic provider that invokes a verified
local Codex executable under a supported ChatGPT subscription sign-in.

The provider:

- checks authentication through `codex login status` and records no credential
  material;
- invokes an absolute executable with a fixed argument vector and no shell;
- sends locally sanitized, bounded evidence through standard input;
- uses ephemeral execution, ignored user and project configuration, a private
  empty working directory, read-only sandboxing, disabled web search, disabled
  Verity hooks and memories, and a minimal inherited environment;
- requests strict structured output and captures bounded JSONL and final-output
  files in a restrictive private temporary directory;
- rejects tool activity, duplicate JSON keys, oversized output, schema or
  identity mismatch, timeout, cancellation, and abnormal process termination;
- marks the child process so the Verity hook adapter ignores it as a
  defense-in-depth recursion guard; and
- supplies a valid result only as advisory semantic evidence to deterministic,
  versioned policy.

Provider selection is explicit. The system must not silently fall back among
`codex_subscription`, the direct OpenAI API provider, and recorded fixtures.
High-risk semantic failure remains an explicit finding and defaults to
quarantine under policy.

Subscription-backed results use the distinct provider state
`live_codex_subscription`. Operator surfaces label them as a lower-isolation
agentic provider. Verity requests that the child use no tools and fails on
observed tool use, but it does not claim that the runtime is tool-free. It also
does not inherit the direct API provider's request-storage claim.

## Consequences

- Codex subscribers can exercise live semantic review without configuring a
  separate `OPENAI_API_KEY`.
- Subscription availability, model access, and rate limits remain external
  dependencies and can make the provider unavailable.
- Child stdout, stderr, JSONL, and final output are untrusted inputs and require
  the same sanitization, schema, identity, digest, and privacy handling as other
  evidence.
- The direct API provider remains the higher-isolation live option; the fixture
  provider remains the deterministic offline option.
- CLI syntax, authentication state, executable integrity, child termination,
  tool-event detection, recursion prevention, and replay compatibility require
  dedicated contract and adversarial tests.
- Future migration to the Codex app server requires a separate decision and
  must preserve explicit provider identity and failure behavior.

## References

- [Codex authentication](https://learn.chatgpt.com/docs/auth)
- [Codex non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode)
- [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- [ADR 0004: GPT-5.6 Semantic Adjudication](./0004-gpt-semantic-adjudication.md)
