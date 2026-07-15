# Verity Cordon Positioning

## Public Identity

**Verity Cordon**

A tamper-evident memory firewall for Codex.

**Verifiable memory. Revocable trust.**

## Core Statement

Codex can carry useful knowledge between tasks, but durable memory can also turn
yesterday's untrusted content into tomorrow's execution context.

Verity Cordon replaces implicit memory reuse with a verifiable memory lifecycle.
Every candidate memory is traced to its source, evaluated under a versioned
policy, and allowed, redacted, quarantined, or rejected before it becomes active
context.

Every security decision is recorded in a cryptographically chained event
ledger. When a threat is discovered later, Verity Cordon can revoke the exact
memory event and reconstruct a clean memory view without erasing unrelated
knowledge.

## Short Description

Verity Cordon protects Codex from persistent memory poisoning by making durable
memory explicit, attributable, policy-governed, and revocable.

It captures candidate memories from user, tool, and agent activity, evaluates
them through deterministic detectors and an optional GPT-5.6 semantic
adjudicator, and records every decision in a signed event ledger. Semantic
review can use the direct API or an explicitly selected, lower-isolation Codex
subscription child; in both cases, deterministic versioned policy makes the
final action decision.

In enforcement mode, only eligible memories from the verified active view are
injected into future Codex sessions. Shadow mode deliberately applies its
configured shadow action, records the stricter would-have action, and is never
presented as active protection.

## Desktop and Subscription Demonstration Boundary

Codex Desktop is the primary demonstration surface. A separate,
confirmation-gated installer adds one private receipt-bound synthetic
poisoned-docs MCP fixture. Its delayed attack is Trojan Hippo-inspired: a useful
tool result carries a concealed persistent instruction that can reappear in a
later task. The demo is not a reproduction of the benchmark, a real
exfiltration exercise, or a universal attack-success measurement.

The exercised Codex `0.144.4` integration registers that fixture user-wide in
`$CODEX_HOME/config.toml`. A dedicated demo workspace minimizes accidental use
but is not project-local scoping or a security boundary. The supported operator
flow closes other Desktop tasks, quits Desktop around each mutation, requires a
separately reviewed SHA-256 preview digest and explicit hook-trust assertion,
and removes the fixture immediately after rehearsal.

The fixture's `demo_artifact_sink` is local stdio only. It accepts exactly two
fixed synthetic markers, retains no arbitrary body, and performs no external
transmission. That boundary makes the demonstration safe; it is not a general
outbound information-flow-control feature.

The Codex subscription provider reuses supported local ChatGPT sign-in without
Verity reading credential files. It is explicitly labeled
`live_codex_subscription` and `agentic_sandboxed`. Verity requests restricted
ephemeral execution and rejects observed tool activity, but does not claim the
child was tool-free or that an attempted side effect was prevented. Accepted
semantic output remains advisory.

## Meaning of the Name

“Verity” refers to verifiable provenance, integrity, and decision history. It
does not mean that the system proves the factual truth of arbitrary claims.

“Cordon” refers to the controlled trust boundary around durable agent memory.
It does not mean that the perimeter is impenetrable.

## Approved Claims

Verity Cordon may claim only demonstrated, test-backed support for:

- Tamper-evident memory history
- Verifiable provenance
- Versioned policy enforcement
- Explicit memory trust decisions
- Selective revocation
- Memory-view reconstruction
- Shadow-mode evaluation
- Cross-session protection against demonstrated memory-poisoning patterns
- A controlled memory plane for Codex using documented integration surfaces
- Explicitly labeled Codex-subscription semantic advice with schema, request
  identity, sanitized-content digest, and observed-tool-activity acceptance
  gates
- A reversible, receipt-bound local Desktop demo fixture with tested drift
  refusal, interrupted-operation recovery, and an inert fixed-marker sink

## Prohibited Claims

Public documentation, UI, video, and submission copy must not claim:

- Impenetrability or tamper-proof storage
- Factual truth verification
- Complete prevention of prompt injection
- Transparent interception of undocumented Codex internals
- Protection against a fully compromised host, user account, signing key, or
  malicious Codex binary
- Enterprise readiness beyond demonstrated implementation
- Support for unimplemented or untested agent frameworks
- That a signature proves a memory statement is factually correct
- That the Codex subscription child is tool-free or provides outbound
  information-flow control
- That rejecting an observed child tool event undoes or proves prevention of an
  attempted side effect
- That a request digest identifies or attests the remote model that produced a
  subscription response
- That the Desktop demo receipt is signed ledger evidence, a supply-chain
  attestation, or tamper-proof state
- That selecting a dedicated workspace or MCP `cwd` scopes the exercised
  Desktop fixture to one project
- That the fixed sink digest or its self-reported status cryptographically
  proves the absence of external transmission
- That the Trojan Hippo-inspired fixture reproduces the benchmark or measures
  universal attack or defense rates

## Audience and Problem

The primary audience is developers using Codex for multi-session work and
security operators evaluating durable agent context. The product addresses the
specific risk that untrusted tool, document, file, user, or model content can be
cleaned up into a durable instruction and regain influence in a later session.

Verity Cordon does not promise to make every current-session tool result safe.
It governs the durable reuse path exposed through its documented controlled
memory plane. Its demonstrated Desktop attack, subscription provider, and local
installer support that narrow story without expanding the claim to arbitrary
MCP safety, current-session rollback, or host-level containment.
