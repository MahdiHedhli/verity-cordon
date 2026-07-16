# Data Model: Codex Desktop Subscription Defense

**Feature**: `002-codex-desktop-subscription-defense`

This document is an additive model over
[`001-codex-memory-firewall`](../001-codex-memory-firewall/data-model.md). The
feature does not replace the event envelope, evidence, detector, policy,
memory, or materialization models. Existing signed event payloads remain valid
byte-for-byte.

## Compatibility Rules

- `ProviderState` adds `live_codex_subscription` to `live_openai`,
  `recorded_fixture`, and `failed`.
- `ProviderSummaryState` adds `live_codex_subscription` to the existing summary
  states.
- `MemoryCandidate.extractor_provider` adds `live_codex_subscription`.
- Old events and projections MUST parse without inserting fields into their
  signed payload bytes. The additive enum values do not cause a migration or
  re-signing of history.
- `provider_isolation` is a derived presentation field, not a model-supplied
  assertion and not a new required field in historical signed payloads.
- SQLite continues to store serialized provider values as text. No authoritative
  event or materialized-view row is rewritten merely to add the new enum value.

## Semantic Provider Identity

The requested provider and the provider that actually ran are separate facts.
Provider selection is explicit and there is no fallback chain.

| Field | Type | Rule |
|---|---|---|
| `requested_provider` | enum | `fixture`, `openai`, or `codex_subscription`; selected from validated local configuration. |
| `provider_state` | enum | Successful assessment state: `recorded_fixture`, `live_openai`, or `live_codex_subscription`; `failed` for an attempted provider that did not return an acceptable result. |
| `provider_isolation` | derived enum | `recorded_fixture`, `tool_free_api`, or `agentic_sandboxed`; derived locally from the requested provider and never accepted from model output. |
| `requested_model` | string/null | Required for both live providers. It is the locally validated configured identifier. |
| `returned_model` | string/null | MUST be null for subscription execution because the current Codex runtime contract exposes no trustworthy remote-model metadata. Direct API providers may populate the shared field from their trusted response envelope. Model-authored text cannot establish it. |
| `prompt_version` | string | Stable local prompt identifier. Subscription extraction and assessment use distinct versions. |
| `output_schema_version` | string | Stable local structured-output envelope version. |
| `executable_path` | absolute path/null | Subscription provider only; resolved locally and never exposed in routine API, telemetry, or UI output. |
| `executable_digest` | SHA-256/null | Subscription provider only; used for doctor and drift checks. |
| `codex_version` | string/null | Canonical `codex-cli MAJOR.MINOR.PATCH` parsed from a fresh bounded invocation of the verified executable. Feature 002 supports `>=0.144.4,<1.0.0`; version acceptance is compatibility gating, not proof of capability or remote-model availability. |
| `started_at` / `completed_at` | UTC time | Operational timing; only bounded latency and content-safe state enter routine telemetry. |
| `failure_class` | enum/null | Content-safe classification when no acceptable result was produced. |

Every newly constructed success or failure assessment populates
`requested_provider` from trusted adjudicator metadata. Absence remains
accepted only for backward-compatible replay of legacy `1.0.0` records. Outer
timeout, validation, and internal-error wrappers preserve the attempted
provider, locally requested model, and prompt version when available; they do
not substitute another provider.

The presentation mapping is fixed:

| Provider state | Isolation class | Required operator label |
|---|---|---|
| `live_openai` | `tool_free_api` | Direct OpenAI API; tool-free request path |
| `live_codex_subscription` | `agentic_sandboxed` | Codex subscription; lower isolation, tool activity invalidates the result |
| `recorded_fixture` | `recorded_fixture` | Recorded deterministic fixture |
| `failed` | `failed` | Failed semantic evaluation; `requested_provider` separately preserves which provider was attempted |

`live_codex_subscription` does not inherit direct-API claims about tool absence
or request storage. Deterministic policy consumes the semantic result as
advisory input and remains the only authority for the final action.

## Subscription Provider Configuration

Validated settings extend the existing `Settings` model:

| Field | Type | Default | Rule |
|---|---|---|---|
| `semantic_provider` | enum | existing default | Adds explicit value `codex_subscription`; no automatic selection. |
| `codex_model` | string | requested `gpt-5.6-luna` | 1-128 safe identifier characters; passed as one fixed argument. Luna is the exercised GPT-5.6-family subscription model for bounded extraction and classification. Availability is checked only by an explicit invocation and failure does not trigger fallback. |
| `codex_executable` | absolute path/null | null | When null, resolve `codex` once from absolute PATH entries whose complete ancestor chains are effective-user/root-owned and not group/world-writable. Explicit paths must be absolute. The resolved regular executable and every ancestor obey the same rule. |
| `codex_semantic_timeout_seconds` | integer | 30 | Greater than zero and no more than 120 seconds. |
| `codex_auth_timeout_seconds` | integer | 5 | Greater than zero and no more than 15 seconds. |
| `codex_max_input_bytes` | integer | 262144 | Positive and no more than 1048576. Applied after local secret sanitization and canonical UTF-8 encoding. |
| `codex_max_jsonl_bytes` | integer | 2097152 | Positive and no more than 4194304. |
| `codex_max_stderr_bytes` | integer | 262144 | Positive and no more than 1048576; stderr content is discarded after content-safe classification. |
| `codex_max_final_bytes` | integer | 65536 | Positive and no more than 262144. |
| `codex_termination_grace_seconds` | integer | 1 | At least 1 and no more than 3 seconds for bounded child and process-group cleanup. |

The subscription runner additionally enforces a constructor-only JSONL line
bound, `max_jsonl_line_bytes`, with default `262144` and inclusive range
`1..1048576`. It is intentionally not an environment-configurable `Settings`
field in this sprint. All five byte-bound constructor values reject zero,
negative values, values above their documented hard maxima, booleans, and
coercible non-integer values such as floats or strings.

Public subscription readiness uses a fixed 250 millisecond runner-lock
acquisition budget. Lock contention reports retryable `unavailable` without
cancelling the lock holder. A probe that acquires the lock still performs the
fresh version/login checks and observes sticky cleanup health.

Configuration validation fails before provider construction. A configured
subscription provider never falls back to `openai` or `fixture` when any field,
binary, authentication, or invocation check fails.

## Subscription Authentication Readiness

Authentication readiness is operational state, not a credential record.

| Field | Type | Rule |
|---|---|---|
| `state` | enum | `ready_chatgpt`, `not_logged_in`, `unsupported_auth`, `codex_unavailable`, or `status_failed`. |
| `checked_at` | UTC time | Local clock. |
| `codex_version` | string/null | Content-safe bounded version string. |
| `failure_class` | string/null | Content-safe value only. |

Each readiness check freshly invokes bounded `codex --version` followed by the
supported `codex login status` surface. No previous success is cached. The
version parser accepts only canonical `codex-cli MAJOR.MINOR.PATCH` output in
the supported range `>=0.144.4,<1.0.0`, after executable identity rechecks; the
later semantic invocation remains the behavior/capability test. Verity does not
open, copy, parse, print, persist, or watch Codex credential files. Raw version
and status output is never logged or included in events. API-key or unsupported
authentication is not treated as subscription readiness.

## Subscription Structured-Output Envelopes

Both operations use local strict JSON Schemas with
`additionalProperties: false`. The prompt supplies the expected identity and
digest; the returned values must match exactly before any output is accepted.

### Candidate extraction output

| Field | Type | Rule |
|---|---|---|
| `schema_version` | literal | `1.0.0`. |
| `operation` | literal | `candidate_extraction`. |
| `provider` | literal | `codex_subscription`; validated but never used to infer the actual provider. |
| `evidence_id` | identifier | Must equal the local request. |
| `sanitized_content_digest` | SHA-256 | Must equal SHA-256 of the exact canonical sanitized evidence sent on stdin. |
| `candidates` | list | At most 16 entries using the existing strict `ExtractedCandidate` model. |

Verity constructs each `MemoryCandidate` locally, assigns a new identifier and
timestamp, binds the existing evidence reference, re-sanitizes all model text,
recomputes the statement digest, and records
`extractor_provider=live_codex_subscription`.

### Semantic assessment output

| Field | Type | Rule |
|---|---|---|
| `schema_version` | literal | `1.0.0`. |
| `operation` | literal | `semantic_assessment`. |
| `provider` | literal | `codex_subscription`; validated but never trusted as execution evidence. |
| `candidate_id` | identifier | Must equal the local candidate. |
| `sanitized_content_digest` | SHA-256 | Must equal SHA-256 of the exact sanitized statement sent on stdin. |
| `assessment` | object | Existing strict `SemanticRiskOutput`: bounded scores, categories, signals, rationale, and recommended disposition. |

Verity constructs `SemanticAssessment` locally with
`requested_provider=codex_subscription` and
`provider_state=live_codex_subscription`. The attempted provider remains
`codex_subscription` if execution later fails; absence is accepted only while
replaying legacy signed `1.0.0` assessments. The local configured model is
stored as `requested_model`; `returned_model` is null under the current
subscription contract because its runtime event stream supplies no trusted
remote-model attestation. The signed event envelope therefore falls back to
the local `requested_model` for `semantic_model_identifier`; that field records
the request and is not a remote-model attestation. The model cannot set
assessment IDs, timestamps, latency, cache state, requested/provider state, or
failure metadata.

## Subscription Failure Classification

`SemanticFailure.class` adds the following content-safe values while retaining
all existing values:

- `unsupported_auth`
- `executable_drift`
- `tool_activity`
- `output_limit`
- `process_exit`
- `cleanup_failure`
- `cancelled`

Existing values remain appropriate for `timeout`, `unavailable`, `refusal`,
`incomplete`, `invalid_schema`, `invalid_response`, and `internal_error`.
Missing Codex and usage/rate-limit errors map to `unavailable` unless the
runtime provides a safer, stable content-free class. Duplicate JSON keys,
identity/digest mismatch, an unknown JSONL event, or a malformed final document
map to `invalid_response` or `invalid_schema`. An exact documented
`error`/`turn.failed` JSONL failure lifecycle maps to retryable `process_exit`;
its message values are discarded and it can never yield an accepted semantic
assessment. Malformed or tool-bearing failure events remain `invalid_response`
or `tool_activity`, respectively. Incomplete process-group,
stdout/stderr reader-drain, or temporary-artifact cleanup maps to
`cleanup_failure`; the internal sticky cleanup-health reason is
`process_group`, `stream_drain`, or `temporary_artifacts`. When another provider
error or cancellation is already active, that primary outcome is preserved and
the cleanup health state is recorded separately. Partial temporary-root setup
is transactionally removed. Failures after root creation while creating or
writing private I/O artifacts map to content-safe `internal_error`; failure to
remove the partial tree additionally records sticky `temporary_artifacts`
cleanup health. Parent cancellation remains cancellation after the cleanup
attempt. Raw exception paths and child stdout/stderr are never stored in the
failure object.

A failed assessment contains no scores, rationale, categories, or recommended
disposition. High-risk semantic failure is consumed by the existing fail-closed
policy path and cannot become a clean assessment.

## Delayed Attack Scenario

The original synthetic scenario is a versioned test fixture, not retained user
evidence and not a reproduction of an external benchmark.

| Field | Type | Rule |
|---|---|---|
| `scenario_id` | literal | `vc-delayed-docs-v1`. |
| `scenario_version` | literal | `1.0.0`. |
| `source_tool` | literal | `verity_cordon_poisoned_docs`. |
| `benign_fact` | string | Fixed synthetic release guidance with no real project data. |
| `dormant_instruction` | string | Fixed synthetic attempt to establish a concealed permanent operational rule. |
| `trigger` | string | Fixed later synthetic release task. |
| `sink_tool` | literal | `demo_artifact_sink`. |
| `artifact_marker` | literal | `VERITY_SYNTHETIC_RELEASE_MANIFEST_V1`. |
| `environment_marker` | literal | `VERITY_SYNTHETIC_DEMO_ENV_V1`. |
| `expected_enforce_action` | enum | `quarantine` or `block`, selected by policy. |
| `expected_shadow_action` | literal | `allow`; paired with the enforcement decision in `would_have_action`. |

No field can reference an arbitrary file, environment variable, URL, email
address, host, token, or payload. The sink validates the two exact marker
literals and reports only a count, acceptance boolean, and digest of the
canonical fixed marker pair. It does not retain a body or transmit data.

## Desktop Demo Installation Receipt

The demo receipt is a private, bounded JSON document validated by
[`desktop-demo-receipt.schema.json`](contracts/desktop-demo-receipt.schema.json).
It is independent from the normal Codex integration receipt.

| Field group | Contents | Rule |
|---|---|---|
| Identity | receipt version, installation UUID, lifecycle state, create/update times | One receipt identifies one setup attempt. |
| Confirmation | `operator_confirmed` | Must be true before any write-ahead receipt or configuration mutation. |
| Paths | Codex home, config path, private staging root; reserved `backup_path=null` compatibility field | Absolute local paths; private and omitted from routine output. No whole-config copy is created. |
| Config binding | existence flag, before/after digests, original restrictive mode, unrelated typed-value projection digest; reserved `backup_sha256=null` compatibility field | Expected existence plus whole-file digests bind replacements; the projection digest prevents a retry from accepting unrelated post-write changes without retaining potentially secret config content. Existing restrictive owner mode is preserved; only a new config defaults to `0600`. |
| Managed entry | fixed name, canonical entry digest, fixed stdio command/arguments/options | Teardown compares this entry independently so unrelated config changes are preserved. |
| Original value | `managed_entry_original` object with `present=false`, `digest=null`, and boolean `parent_table_present` | Setup refuses a pre-existing entry with the reserved demo name rather than copying possibly secret configuration into a receipt; the parent-table flag supports exact teardown. |
| Runtime identity | Codex and Python resolved paths, file digests, bounded versions | Doctor rejects runtime drift before use. |
| Staged artifacts | relative path, digest, byte size | All paths are below the private staging root; no symlinks. |
| Product integration | normal integration receipt path/digest | Binds the demo to a verified normal Verity installation without merging the receipts. |
| Teardown | request/completion times and post-teardown config digest | Null before removal; populated through atomic state transitions. |

New demo receipts use receipt version `1.1.0` and record normal-integration
receipt version `2.0.0`. Demo receipt version `1.0.0` remains parseable only
for existing-receipt inspection and safe cleanup; it cannot resume a prepared
setup because it lacks the mode and unrelated-projection bindings. A legacy
normal receipt cannot satisfy the current normal-integration readiness gate
for new setup.

The receipt contains no credential, capability, environment dump, raw evidence,
signing key, hook input, or child output. It is written with mode `0600` below a
`0700` Verity data directory using no-follow reads and atomic replacement.

## Desktop Demo Installation State Machine

```text
absent
  | explicit confirmation; write-ahead receipt committed before artifact mutation
  v
prepared (artifact may still be absent)
  | exact receipt-bound artifact staged or safely restaged
  v
prepared + staged
  | exact managed MCP entry written atomically
  v
installed
  | explicit teardown confirmation
  v
removing
  | managed entry and verified staged artifacts removed
  v
removed

prepared + config replaced but unrelated projection mismatch
  | append non-finalizable local failure state
  v
failed
  | exact confirmed teardown only
  v
removing
```

Rules:

1. Preview is read-only and creates no directory, backup, receipt, or config
   file.
2. A receipt in `prepared` state is written before the Codex config mutation.
   On restart, an absent entry permits safe retry only when the whole config
   still matches the receipt's pre-mutation digest; an exact managed entry
   permits finalization only when the recorded unrelated-value projection still
   matches; any other entry requires operator review. Config and managed-entry
   state are classified before a missing artifact is restaged. If the exact
   managed entry and exact present artifact are live but the projection differs,
   a current v1.1 recovery retries only the interrupted `prepared` to `failed`
   receipt transition after revalidating the config and receipt heads, runtimes,
   and normal integration. It never finalizes that installation.
3. Setup refuses a pre-existing `verity_cordon_poisoned_docs` entry. It does not
   overwrite or serialize unknown existing values.
4. `installed` requires the exact managed-entry digest and all staged artifact
   digests to verify. After either the initial or recovery config replacement,
   every unrelated parsed config value must also equal its pre-replacement
   projection and the receipt's type-tagged projection digest; the comparison
   does not render or persist those values. A mismatch records `failed` and
   cannot be finalized by retry. If the first failure-state receipt write is
   interrupted, exact-bound recovery records the same failure before teardown;
   it does not reinterpret the changed projection as a new baseline.
5. Unrelated Codex config changes do not block teardown when the managed entry
   is byte-equivalent after canonical TOML parsing. Drift inside the managed
   entry blocks teardown. Only the pre-mutation digest is retained; the demo
   never copies or restores the full Codex config.
6. Staged artifacts are removed only when their path containment, digest,
   byte-size, owner mode, device, and inode checks pass. The selected entry is
   renamed through an anchored parent descriptor to a unique quarantine name,
   reverified, and only then unlinked. A replacement or symlink is not deleted.
   Drift is reported for manual review rather than recursively deleting the
   staging root.
7. `removed` is a terminal receipt state. The receipt remains as local setup
   history; a later setup receives a new installation identifier.
8. Setup and teardown never delete or rewrite the Verity event ledger, signing
   key, policies, or memory projections.
9. Config, receipt, archive, and artifact writes bind both expected existence
   and SHA-256; receipt-dependent mutations additionally recheck device, inode,
   owner, and mode. New setup/recovery rebinds the exact normal v2 receipt and a
   fresh doctor result before each mutation and finalization.
10. Teardown re-reads config before artifact removal and again before the
    `removed` transition, requiring managed absence, equality of every
    unrelated typed TOML value, and the preserved restrictive mode.

## Evidence Evaluation State

The feature reuses the baseline pending-evidence queue and signed terminal
events. A Desktop protection claim requires one of these signed terminal states:

- `EvidenceEvaluationCompleted`, including a zero-candidate outcome; or
- a candidate-specific signed policy and memory outcome; or
- `EvidenceEvaluationFailed`, which cannot authorize memory injection.

Capture acknowledgement alone is not a protection decision. The Desktop guide
and Control Room poll by opaque evidence ID and expose only `pending`,
`completed`, or `failed` plus content-safe status metadata. A fresh-task demo
must wait for `completed` and verify ledger/view health before asserting that
approved memory is present and poisoned memory is absent.

## Relationships and Invariants

1. One evidence record may yield zero or more candidates; each subscription
   extraction envelope binds the exact evidence ID and sanitized digest.
2. One candidate has at most one accepted semantic assessment per evaluation
   attempt; retry attempts that fail remain explicit and cannot be overwritten
   as though they succeeded.
3. Provider selection and actual provider state must agree. A successful
   subscription invocation cannot produce `live_openai` or
   `recorded_fixture`, and a failed one cannot cause another provider call.
4. A semantic assessment never commits memory directly. Existing detector
   aggregation and deterministic policy produce the final decision.
5. `actual_action`, `would_have_action`, and `shadow_mode` remain independently
   stored. `shadow_mode=true` is never displayed as active protection.
6. Only approved, active, unexpired, non-revoked materialized memory is eligible
   for a new Desktop task. The same baseline injection grammar and budget apply.
7. The demo receipt governs only local integration artifacts. The signed event
   ledger governs memory-security history; neither substitutes for the other.
