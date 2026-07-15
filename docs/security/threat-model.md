# Verity Cordon Threat Model

**Feature**: `001-codex-memory-firewall`
**Review date**: 2026-07-15
**Status**: Security design baseline; protection claims require the linked
adversarial and end-to-end tests to pass

## Scope and Security Objective

Verity Cordon is a controlled memory plane for local Codex clients. Its primary
security objective is to prevent unadjudicated content captured through the
documented integration surfaces from becoming Verity-provided durable context.
It also makes memory decisions attributable, selectively revocable, and
tamper-evident.

This is not a claim that arbitrary content is factually true, that every prompt
injection is detected, or that every Codex action is intercepted. A malicious
tool response can still affect the current session before or independently of
the durable-memory path. The demonstrated claim is narrower: for the captured
surfaces and tested attack patterns, Verity Cordon governs whether candidate
memory becomes active and is supplied to a later session.

## Protected Assets

- Integrity of the active-memory view and session-start injection.
- Provenance and decision history for each candidate memory.
- Ordering, payload binding, and signature validity of the event ledger.
- Integrity and availability of the active policy and its version history.
- Confidentiality of raw evidence, credentials, API keys, and signing material.
- Integrity of manual approval, block, revocation, and rebuild actions.
- Separation between concurrent transactional memory streams.
- Honest operator visibility into degraded, shadow, fixture, and live states.

Availability of Codex itself is not a protected guarantee. When Verity Cordon
is unhealthy, Codex may continue the current task without Verity-provided
memory, but Verity Cordon must fail closed for new memory trust and injection.

## Security Invariants

1. Observed content is untrusted until the full candidate lifecycle completes.
2. No stream chunk is active memory before a successful final commit.
3. Semantic output is advisory; versioned deterministic policy has final
   authority.
4. A failed component is a failure finding, never an implicit clean result.
5. A ledger or materialized-view integrity failure disables injection and new
   commits.
6. A correction is a new event; historical security events are not rewritten.
7. Detected secret material does not enter model-bound content, routine
   telemetry, list views, fixtures, or screenshots.
8. Shadow admission is labeled as shadow admission and is not active protection.
9. Facts and tool observations do not gain instruction authority merely because
   they were approved as memory.
10. Native Codex memory use and generation remain disabled for the controlled
    demo plane; installer and doctor checks verify effective configuration.

## System and Adversary Model

The MVP is a single-user local service on macOS or Linux. Codex, the thin hook
adapter, the Verity daemon, SQLite, the Control Room, detector plugins, and the
local demo MCP server share a host but cross distinct application trust
boundaries. Live semantic assessment crosses the host boundary to the OpenAI
API only after local secret screening and sanitization.

The in-scope adversary may control imported text, documentation, a tool or MCP
response, model-authored content proposed as memory, stream chunk boundaries,
or a detector plugin's returned value and failure behavior. The adversary may
also cause ordinary local corruption, deletion, reordering, timeouts, process
failure, or storage interruption. The adversary does not have root access or
control of the operator account, operating system, Codex binary, Verity daemon,
or installation signing key.

The operator is trusted to review hook definitions, protect the host and key,
understand shadow mode, and confirm trust-changing actions. Operator mistakes
remain possible and are mitigated through confirmation, reasons, provenance,
and append-only review history rather than treated as impossible.

## In-Scope Threats

- Prompt injection in tool output, documentation, or imported files.
- Model-authored or summarized content that reinforces its own authority.
- Cross-task contamination and untrusted content seeking durable instruction
  status.
- Credentials or other secret material proposed for memory.
- Poisoning intended to survive a context reset or new session.
- Retroactively discovered poisoned memory.
- Encoded, indirect, quoted, oversized, or cross-chunk persistence attempts.
- Accidental event or payload modification, deletion, omission, or reordering.
- Materialized-view drift from the authoritative event history.
- Detector timeout, exception, malformed output, duplicate ID, or plugin crash.
- Semantic-provider timeout, refusal, malformed output, or unavailability.
- Malformed, missing, or failed policy activation.
- Daemon, hook, signing-key, database, or local IPC failure.
- Unsafe trust-changing UI requests and stale UI state.

## Out-of-Scope Threats and Non-Claims

- Root, administrator, or malicious operating-system compromise.
- Full compromise of the user account, Verity daemon, or installation signing
  key.
- A malicious or compromised Codex binary.
- Hardware attacks and side-channel resistance.
- Nation-state endpoint compromise.
- Remote multi-tenant attacks, distributed consensus, and cross-host
  federation.
- Production supply-chain attestation, HSM-backed key lifecycle, and enterprise
  identity or RBAC.
- Perfect factual truth determination or complete prompt-injection prevention.
- Transparent interception of undocumented Codex internals.
- Current-session rollback of side effects already performed by a tool.
- Tool and activity paths not exposed by the documented Codex hooks used by the
  implementation.
- Confidentiality against another process running with the fully compromised
  operator account.

## Integration Coverage Constraints

As verified from the published Codex documentation on 2026-07-15, command
hooks include `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`,
`PreCompact`, `PostCompact`, and `Stop`, among other lifecycle events.
`SessionStart` can add developer context. No documented hook intercepts native
memory reads, writes, generation, or commits. Verity Cordon therefore disables
native local memory generation and use and supplies its own approved view at
`SessionStart`.

Hook coverage is not universal. In particular, documented tool hooks cover the
supported tool paths rather than every possible Codex activity; matching hooks
may run concurrently without a documented ordering guarantee; `PostToolUse`
cannot undo a tool's side effects; asynchronous command hooks are not
supported; and the transcript file format is explicitly unstable. The adapter
must use event input fields, not parse the transcript as a security contract,
and must not depend on ordering among separate hooks.

## Abuse Cases

Each abuse case specifies the expected control and the residual risk that must
remain visible in product claims.

### TM-01: Tool output requests persistent exfiltration

**Scenario**: An external documentation tool returns useful release guidance
plus an instruction to preserve a synthetic exfiltration workflow for future
sessions.

**Expected control**: Capture the tool source and evidence digest; split useful
facts from operational instructions; run secret, persistence, authority,
concealment, and exfiltration-related checks; use sanitized semantic review
when policy requires it; and let deterministic policy quarantine or block the
instruction in enforcement mode. The candidate must not enter the active view
or session-start injection. Shadow mode records both the applied admission and
the stricter would-have action. The demo never performs real exfiltration.

**Residual risk**: A novel paraphrase may evade both deterministic and semantic
detection. The original tool response may already influence the current
session. The control governs durable reuse, not every immediate effect.

### TM-02: A model launders the malicious instruction into cleaner language

**Scenario**: A model summary removes obvious attack phrases while preserving
the instruction's intent.

**Expected control**: Preserve the evidence chain and `agent_output` source
class; never upgrade authority because text was model-authored; detect
self-reinforcement, persistence intent, and kind/content mismatch; and require
stronger policy for operational instructions. Semantic assessment receives the
sanitized candidate and provenance, while deterministic policy retains the
decision.

**Residual risk**: Meaning can be laundered subtly enough to appear benign.
Model provenance and policy reduce authority but do not prove intent.

### TM-03: An attack is split across stream chunks

**Scenario**: Individually benign fragments combine into a persistent malicious
instruction only across chunk boundaries.

**Expected control**: Keep every chunk in an isolated uncommitted stream;
perform bounded incremental scanning with overlap; evaluate the complete
canonical buffer again at commit; and atomically commit or abort. A blocked,
cancelled, oversized, or aborted stream can never partially commit or commit a
second time.

**Residual risk**: Buffer and scanning limits can be abused for denial of
service. Resource limits may abort benign very large content rather than fully
classify it.

### TM-04: Encoded or indirect wording hides persistence intent

**Scenario**: The candidate uses encoding, euphemism, indirection, or an
authority-by-reference pattern instead of explicit attack language.

**Expected control**: Apply structural validation and bounded normalization,
flag anomalous encoding and authority claims, preserve the original evidence
digest, and route ambiguity to semantic review or quarantine according to
policy. Decoders must be allow-listed and bounded; recursive or executable
decoding is prohibited.

**Residual risk**: Unknown encodings, steganography, and novel indirect language
can remain undetected. Quarantining ambiguity trades availability for safety.

### TM-05: Benign documentation says "ignore previous" in an explanation

**Scenario**: Security documentation quotes or discusses an attack phrase but
does not ask Codex to follow it.

**Expected control**: A regex match is evidence, not proof. Detectors record safe
offsets and context; candidate extraction distinguishes quotation from a
durability request; contextual semantic assessment can classify benign
discussion; and false-positive fixtures must exercise the same policy path.

**Residual risk**: Context classification can still be wrong. Manual review may
be needed for ambiguous operational documentation.

### TM-06: The semantic provider is unavailable

**Scenario**: The live API times out, refuses, rate-limits, returns invalid
structured output, or cannot be reached.

**Expected control**: Record an explicit semantic failure state. Never silently
substitute fixtures in live mode. High-risk or ambiguous candidates default to
quarantine; lower-risk fallback is allowed only by an explicit versioned rule.
No unverified memory is injected as a consequence of the failure.

**Residual risk**: Safe content may be delayed or quarantined, and explicit
lower-risk fallback can admit a detector false negative.

### TM-07: A detector raises an exception

**Scenario**: A built-in or discovered detector times out, crashes, is
cancelled, or returns malformed output.

**Expected control**: Run detectors with per-detector deadlines, cancellation,
error isolation, deterministic result ordering, schema validation, and an
explicit failure finding. A failed detector is not a clean verdict. High-risk
ambiguity defaults to quarantine, and duplicate detector IDs are rejected.

**Residual risk**: Lower-risk fallback explicitly permitted by policy may
proceed with reduced coverage. Repeated failures can cause denial of service.

### TM-08: Database append fails after evaluation

**Scenario**: Policy calculates an allow decision, but SQLite fails before the
event, payload, and materialized view are durably updated.

**Expected control**: Treat ledger append and materialized-view update as one
transactional commit boundary. Roll back the whole operation, return failure,
and expose no new active memory. Retry must be idempotent by event or request
ID. Injection may use only the previously verified view, subject to health
policy.

**Residual risk**: When storage is unavailable, the failed attempt itself may
not be durably auditable; a content-free local health warning is the remaining
signal. Availability is reduced.

### TM-09: An attacker modifies a historical payload

**Scenario**: Stored event payload JSON is changed without changing the event
envelope.

**Expected control**: Re-canonicalize the stored payload, recompute its SHA-256
digest, compare it to `payload_digest`, then verify the event hash, Ed25519
signature, and chain. On the first mismatch, disable injection and new commits,
show the exact failing event, and retain safe read-only audit access.

**Residual risk**: An attacker who also controls the signing key and writable
history can construct a new apparently valid history. That host/key compromise
is outside the MVP boundary.

### TM-10: An attacker reorders two events

**Scenario**: Two valid database rows are swapped or their sequence metadata is
altered.

**Expected control**: Verify contiguous sequence numbers, each event's
`previous_event_hash`, recomputed event hashes, signatures, and stream-specific
ordering rules. Reordering must fail at the first broken sequence or link and
disable injection and commits.

**Residual risk**: A signing-key compromise permits complete history
reconstruction. External transparency anchoring is deferred.

### TM-11: A new policy rejects memory admitted by an old policy

**Scenario**: Shadow mode or an older enforcement rule admitted a candidate that
a newly activated policy identifies as malicious.

**Expected control**: Preserve original policy ID, version, mode, actual action,
and would-have action; append `PolicyActivated`; rescan affected active memory;
append a reasoned `MemoryRevoked` event; replay the active view; and verify that
unrelated memory remains.

**Residual risk**: Revocation depends on a rescan trigger, suitable new
detection, and operator or policy action. Previously injected content cannot be
removed retroactively from sessions that already received it.

### TM-12: A malicious detector plugin tries to crash the pipeline

**Scenario**: A discovered plugin hangs, raises, returns oversized or malformed
data, or conflicts with an existing detector ID.

**Expected control**: Require explicit installation trust; validate identity and
version at discovery; reject duplicate IDs; bound execution time and result
size; isolate failure from other detector tasks; and convert failure to a
detector failure finding. Policy determines the safe fallback.

**Residual risk**: A Python plugin loaded into the daemon process is code, not
untrusted data. Without process isolation it can access the daemon's user-level
capabilities or terminate the process. The reference plugin is not a sandbox,
and operators must install only trusted code.

### TM-13: Injected memory contains an instruction inside a fact field

**Scenario**: A candidate is labeled as a fact or tool observation but its
statement contains an operational instruction.

**Expected control**: Detect kind/content and namespace mismatches before
commit; require stronger policy for instruction-like text; preserve the type in
the active view; and inject memories inside a strict delimiter with developer
context stating that facts and tool observations are data, not higher-priority
authority. Blocked or quarantined content is never injected.

**Residual risk**: Delimiters and developer instructions reduce but do not
eliminate model susceptibility to embedded instructions. Candidate screening
remains essential.

### TM-14: A direct user preference contains a secret

**Scenario**: A user asks to remember a preference that includes a token,
password, private key, or synthetic credential.

**Expected control**: Screen locally before candidate extraction or semantic
review; replace detected material with a typed placeholder; apply block,
redact, or quarantine policy; minimize separately protected raw-evidence
retention; and keep the value out of telemetry, routine UI, and screenshots.
Direct user origin does not bypass screening.

**Residual risk**: Pattern and entropy checks can miss unfamiliar secret
formats. Any locally retained evidence depends on host and file protections and
is not encrypted against a compromised operator account by default.

### TM-15: A revoked memory remains in a stale materialized view

**Scenario**: A revocation event is valid, but the cached active view still
contains the revoked statement.

**Expected control**: Verify view consistency against deterministic replay at
startup, before injection, after revocation, and on explicit ledger verification.
Any mismatch disables injection. `memory rebuild` replaces the derived view
transactionally, then verification confirms the target is gone and unrelated
memory remains.

**Residual risk**: Previously injected sessions retain their existing context.
A bug shared by both materialization and verification could evade detection, so
independent fixture-based replay tests are required.

## Additional Threat Coverage

The named abuse cases above are the required demonstration set. These related
in-scope conditions retain their own controls and residual risk:

| Condition | Expected control | Residual risk |
|---|---|---|
| Cross-task or cross-project contamination | Preserve session, task, project route, source class, and namespace; reject or quarantine a candidate outside its allowed scope; enforce scope again at injection | Incorrect provenance or overly broad namespace configuration can admit contamination |
| Injection in imported files or documentation | Treat file content as untrusted evidence and run the same extraction, detector, semantic, and policy path as tool output | Content read through an uncaptured Codex path is outside the demonstrated enforcement surface |
| Oversized or empty candidates | Apply pre-extraction size/structure limits, per-stream buffer caps, and an anomalous-size detector; abort without partial commit | Limits can reject benign large content and can be exercised for local denial of service |
| Malformed or missing active policy | Validate with the versioned Pydantic model; reject invalid activation; use only an intact last-known-good policy; otherwise fail closed for commits | Recovery requires operator action and reduces availability |
| Native Codex memory is accidentally re-enabled | Installer writes the controlled configuration; `doctor` verifies effective use/generation state and hook trust; Control Room reports configuration drift | Configuration can change after a check; native-memory behavior is outside Verity's ledger if re-enabled |
| Event deletion or omission | Verify contiguous sequence, prior-hash links, signatures, expected ledger head where available, and view replay | A consistently truncated tail cannot be proven from a self-contained ledger alone; see [the cryptographic limitation](./cryptographic-claims.md#what-omission-verification-can-and-cannot-prove) |
| Forged or replayed Control Room mutation | Loopback peer restriction, strict Host/Origin, bearer capability for non-browser clients, minimum-length passphrase challenge, single-use 60-second nonce, constant-time proof check, bounded challenge issuance, failed-proof cooldown, 15-minute idle HttpOnly session and CSRF for the UI, JSON-only request, confirmation, reason, actor, and idempotency key | A weak operator-selected passphrase remains guessable; same-user malware that steals a capability, verifier, passphrase, or live browser session can act with local authority |
| Intentional retention expiry of raw evidence | Record retention outcome and retain the signed digest/provenance event; never represent deleted evidence as still fully verifiable | Once content is deliberately expired, its digest cannot prove what unavailable bytes contained to a new verifier |

## Failure-Behavior Matrix

"Continue without memory" is fail-open only for current Codex task
availability. It is fail-closed for the Verity memory trust boundary.

| Failure | Memory commit | Session injection | Required signal and recovery |
|---|---|---|---|
| Daemon or local IPC unavailable | Refuse; never queue an unverified implicit commit | Return no Verity context; Codex may continue | Content-free health warning; recover daemon and rerun health checks |
| Hook times out, exits nonzero, or emits invalid output | No commit from that hook invocation | No context from a failed `SessionStart` hook | Codex hook status; daemon records a failure only if reachable; doctor checks trust and effective config |
| Ledger cannot open or append | Roll back and refuse | Use no view whose integrity cannot be established | Critical storage state; safe read-only audit if possible; repair before writes |
| Ledger chain, payload, signature, key ID, or order fails verification | Disable all new commits | Disable all injection | Critical Control Room state, first invalid event, explicit operator repair path |
| Materialized view differs from replay | Disable commits that depend on the inconsistent view | Disable injection | Rebuild transactionally, then re-verify before re-enabling |
| Active policy is malformed or unavailable and no valid last-known-good policy exists | Fail closed | Disable Verity injection when eligibility cannot be established | Validation error and policy hash/version; install or restore a valid policy |
| Proposed policy activation is invalid while a validated active policy remains intact | Reject activation; retain validated active policy | Continue only under the still-verified active policy and view | Append `PolicyActivationRejected` with safe issue codes where storage permits; show last-known-good status |
| Detector timeout, exception, cancellation, or malformed result | Record failure; high-risk ambiguity quarantines; lower fallback only by explicit rule | Never inject quarantined result | Detector ID/version/error class only; no raw content |
| Semantic timeout, refusal, API error, or invalid schema | Never silently use a fixture; high-risk ambiguity quarantines | Never inject quarantined result | Provider state, error class, prompt/model version; retry only within bounded policy |
| Secret screening fails or finds prohibited material | Do not send content to semantic provider; block or quarantine | No raw secret injection | Safe category and placeholder metadata only |
| Signing key missing, unreadable, or has unsafe permissions | Refuse new signed events and commits | Disable injection; otherwise a due TTL could remain active because `MemoryExpired` cannot be signed | Critical key health state; repair permissions or restore key through documented procedure |
| Detector plugin has duplicate ID or fails discovery | Reject duplicate/plugin; do not treat it as having passed | Only results from a complete policy-required detector set may inject | Plugin identity/version failure; operator removes or repairs plugin |
| Stream is oversized, cancelled, blocked, or abandoned | Abort; no partial commit and no later commit | None from the stream | Append abort outcome when ledger is available; otherwise health warning |
| Live OpenAI credentials are absent | Live semantic-required candidate cannot pass that stage | No fixture substitution and no ambiguous high-risk injection | `doctor` reports presence only, never the key; offline mode remains explicitly separate |
| Control Room loses API connectivity during a trust-changing action | Server transaction is authoritative; client must not assume success | Unchanged until a verified server result exists | Show unknown/pending state, refetch event outcome, require a fresh confirmation before retry |
| Memory exceeds injection budget | No change to stored trust decision | Deterministically select eligible entries by documented budget/order; never truncate inside a memory record | Report omitted count and budget metadata without raw content |

## Residual-Risk Summary

Verity Cordon is detection- and policy-based software. False negatives, false
positives, semantic errors, implementation bugs, local denial of service, and
operator mistakes remain possible. Hash chaining and signatures reveal covered
modification under an uncompromised key; they do not prevent modification,
provide confidentiality, establish factual truth, or withstand a fully
compromised host. Shadow mode deliberately admits the configured shadow action
and therefore must not be represented as protection.

The release gate is evidence, not aspiration: adversarial fixtures must cover
every abuse case above, tamper tests must alter payloads, events, order,
omissions, and signatures, and end-to-end tests must prove that ineligible
memory is absent from later session context.

## Review Triggers

Review this model when a Codex hook contract changes; a new capture surface,
detector plugin mechanism, storage backend, policy action, key mechanism, or
agent integration is added; live provider data handling changes; or a test
finds a new bypass. Deferred multi-tenant, remote-policy, HSM, federation, and
other-agent work requires a separate numbered feature and threat model update.
