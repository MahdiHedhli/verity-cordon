# Verity Cordon Threat Model

**Features**: `001-codex-memory-firewall`,
`002-codex-desktop-subscription-defense`
**Review date**: 2026-07-15
**Status**: Implemented local MVP; protection claims remain limited to the
linked tests and final publication verification

## Scope and Security Objective

Verity Cordon is a controlled memory plane for local Codex clients, with Codex
Desktop as the primary demonstration surface. Its primary security objective is
to prevent unadjudicated content captured through the documented integration
surfaces from becoming Verity-provided durable context. It also makes memory
decisions attributable, selectively revocable, and tamper-evident.

This is not a claim that arbitrary content is factually true, that every prompt
injection is detected, or that every Codex action is intercepted. A malicious
tool response can still affect the current session before or independently of
the durable-memory path. The demonstrated claim is narrower: for the captured
surfaces and tested attack patterns, Verity Cordon governs whether candidate
memory becomes active and is supplied to a later session.

The optional Codex subscription provider is a lower-isolation
`agentic_sandboxed` semantic adviser. Verity minimizes and sanitizes its input,
requests a restricted ephemeral child, rejects observed tool activity, and
validates the returned schema, request identity, and content digest. Those
controls are acceptance gates, not outbound information-flow control and not
proof that the child had no tools or made no attempted side effect before an
event was observed. Deterministic policy remains the final authority.

## Protected Assets

- Integrity of the active-memory view and session-start injection.
- Provenance and decision history for each candidate memory.
- Ordering, payload binding, and signature validity of the event ledger.
- Integrity and availability of the active policy and its version history.
- Exclusion of original evidence bytes, recognized credentials, API keys, and
  signing material from routine output and remote calls.
- Integrity of manual approval, block, revocation, and rebuild actions.
- Separation between concurrent transactional memory streams.
- Honest operator visibility into degraded, shadow, fixture, and live states.
- Integrity of the receipt-bound Desktop demo entry, staged synthetic fixture,
  and verified Codex and Python runtime identities used to operate it.

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
7. Recognized secret material is replaced before model-bound content and is
   excluded from routine telemetry, list views, fixtures, and screenshots.
   Sanitizer false negatives remain a documented residual risk.
8. Shadow admission is labeled as shadow admission and is not active protection.
9. Facts and tool observations do not gain instruction authority merely because
   they were approved as memory.
10. Native Codex memory use and generation remain disabled for the controlled
    demo plane; installer and doctor checks verify effective configuration.
11. A subscription child is never treated as tool-free. Any observed tool or
    unknown event invalidates the entire advisory result, with no fixture or API
    fallback.
12. The delayed-attack sink accepts only two fixed synthetic marker literals,
    is local stdio only, and provides no general payload or destination field.
    Its fixed digest identifies those markers; it is not evidence of network
    noninterference.
13. Desktop demo configuration changes require an explicit confirmed preview
    and a private write-ahead receipt. Drift or ambiguous partial state disables
    readiness and prevents automatic cleanup from guessing.
14. On the exercised Codex `0.144.4` surface, the demo MCP entry in
    `$CODEX_HOME/config.toml` is user-wide. A dedicated workspace or MCP `cwd`
    MUST NOT be described as project-local isolation.

## System and Adversary Model

The MVP is a single-user local service. macOS is the exercised platform; Linux
is an intended local target but is not yet recorded as exercised, and Windows
is unverified. Codex Desktop, the thin hook adapter, the Verity daemon, SQLite,
the Control Room, detector plugins, the receipt-bound demo installer, and the
local stdio demo fixture share a host but cross distinct application trust
boundaries. Direct live semantic assessment crosses the host boundary to the
OpenAI API only after local secret screening and sanitization. Subscription
assessment passes the same class of bounded sanitized input to an ephemeral
Codex child, which uses the operator's supported ChatGPT sign-in to reach the
service. Verity does not inspect or copy Codex credential files.

The verified fixture probe and subscription child use POSIX process sessions
and process-group termination on the exercised macOS host. Windows remains
unverified and does not have the same tested descendant process-group cleanup
guarantee in the current fallback.

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

For the Desktop fixture, the operator is also trusted to close every unrelated
Desktop task, quit Desktop around confirmed setup and teardown, reopen only the
dedicated synthetic rehearsal while the user-wide entry exists, and perform
fresh digest-confirmed teardown immediately afterward.

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
- Delayed poisoning that is admitted in shadow mode, reappears in a later task,
  and attempts to call a synthetic sink.
- Subscription-child tool activity, unknown event types, output spoofing,
  executable replacement, inherited-environment exposure, and incomplete
  descendant cleanup.
- Desktop demo receipt, managed-entry, artifact, runtime, preview, and teardown
  drift; reserved-name collision; unsafe filesystem paths; and interrupted
  setup.
- Unexpected or non-synthetic input sent to the local demo sink.

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
- Prevention of outbound activity by the Codex subscription child. The provider
  rejects observed tool activity as an invalid result but does not implement a
  network information-flow-control boundary.
- Proof that a Codex subscription execution was tool-free merely because its
  accepted event stream contained no tool event.
- Protection from a malicious replacement of the verified fixture, receipt,
  configuration, executable, and verifier by the same compromised operator or
  host.
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

Codex Desktop is the primary user-facing surface, but the memory boundary is
still the documented hook and local-daemon contract. The separately installed
`verity_cordon_poisoned_docs` MCP entry exists only for the synthetic demo and
is not part of the normal product installer. It exposes fixed release guidance
and an inert fixed-marker sink; it does not extend Verity's capture coverage or
prove that other MCP servers are safe. Codex `0.144.4` reads the managed table
from `$CODEX_HOME/config.toml`; the entry is user-wide even when the operator
opens a dedicated workspace and the server uses a private `cwd`.

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
self-reinforcement and persistence intent; and require stronger policy for
operational instructions. Semantic assessment receives the sanitized candidate
and provenance, while deterministic policy retains the decision. The MVP has no
dedicated kind/content-mismatch detector.

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

**Expected control**: Apply structural and size validation, preserve the
original evidence digest, run the implemented persistence and authority
detectors on visible text, and route candidates selected by policy to semantic
review. The MVP does not implement a general decoder, an anomalous-encoding
detector, or recursive normalization; it never executes encoded content.

**Residual risk**: Encoded instructions, steganography, and novel indirect
language can remain undetected, particularly if candidate extraction presents
them as benign or opaque. This abuse case is in scope for risk analysis but is
not a demonstrated comprehensive encoded-content defense.

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
show the exact failing event, and retain safe read-only audit access. A restart
must enter read-only mode before using stored policy: the status/policy/audit
surface remains content-safe, the displayed fallback policy is labeled invalid,
third-party detector plugins do not load, and `SessionStart` returns no context.

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
and would-have action; append `PolicyActivated`; identify the affected active
memory; and run a confirmed targeted rescan from its signed candidate event.
The rescan derives a fresh signed candidate that binds current sanitization and
the original candidate lineage, then applies current detector,
semantic-when-required, and policy inputs. It appends the new findings and
decision, and atomically appends a reasoned `MemoryRevoked` event when the
enforcement action is redact, quarantine, or block. Replay and verification
must preserve unrelated memory.

**Residual risk**: The operator must identify and rescan one active memory at a
time. Policy activation does not automatically discover or reevaluate every
prior memory, and previously injected content cannot be removed retroactively
from sessions that already received it.

### TM-12: A malicious detector plugin tries to crash the pipeline

**Scenario**: A discovered plugin hangs, raises, returns oversized or malformed
data, or conflicts with an existing detector ID.

**Expected control**: Require explicit installation trust; validate identity and
version at discovery; reject duplicate IDs; bound execution time and result
field counts, UTF-8 size, and total serialization; sanitize messages,
categories, and string metadata before policy or signed persistence; isolate
failure from other detector tasks; and convert failure to a detector failure
finding. Routine UI detail drops plugin metadata and reflects only fixed
messages plus an allow-listed taxonomy. Policy determines the safe fallback.

**Residual risk**: A Python plugin loaded into the daemon process is code, not
untrusted data. Without process isolation it can access the daemon's user-level
capabilities or terminate the process. The reference plugin is not a sandbox,
and operators must install only trusted code.

### TM-13: Injected memory contains an instruction inside a fact field

**Scenario**: A candidate is labeled as a fact or tool observation but its
statement contains an operational instruction.

**Expected control**: Apply persistence and authority detectors independently of
the declared kind, preserve the type in the active view, require stronger policy
for candidates classified as operational instructions, and inject memories
inside a strict delimiter with developer context stating that facts and tool
observations are data, not higher-priority authority. Blocked or quarantined
content is never injected. The MVP has no dedicated classifier that proves the
declared kind matches the statement.

**Residual risk**: A mislabeled instruction that evades the implemented
detectors can be admitted as a fact. Delimiters and developer instructions
reduce but do not eliminate model susceptibility to embedded instructions.

### TM-14: A direct user preference contains a secret

**Scenario**: A user asks to remember a preference that includes a token,
password, private key, or synthetic credential.

**Expected control**: Screen locally before candidate extraction or semantic
review; replace recognized material with a typed placeholder; apply block,
redact, or quarantine policy; retain no original evidence bytes; and keep the
recognized value out of telemetry, routine UI, and screenshots. Direct user
origin does not bypass screening. `EvidenceCaptured` still retains a bounded
pattern-sanitized excerpt and raw-content digest.

**Residual risk**: Pattern checks can miss unfamiliar secret formats. An
undetected value can remain in the signed excerpt and can reach the semantic
provider. The SQLite data depends on host and file protections and is not
encrypted against a compromised operator account by default.

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

### TM-16: A shadow-admitted instruction triggers in a later Desktop task

**Scenario**: A Trojan Hippo-inspired documentation response combines a useful
fact with a concealed permanent operational instruction. Shadow policy admits
the instruction, a fresh Desktop task receives it, and the later task proposes
the demo sink.

**Expected control**: Record the original source, evidence digest, candidate,
detector and semantic inputs, `actual_action=allow`, stricter
`would_have_action`, and `shadow_mode=true` in signed events. The Control Room
must state that this is not active protection. The demonstration sink accepts
only `VERITY_SYNTHETIC_RELEASE_MANIFEST_V1` and
`VERITY_SYNTHETIC_DEMO_ENV_V1` over local stdio, requires an operator prompt,
and performs no external action. After enforcement is activated, the same
malicious operational candidate is quarantined; a confirmed rescan appends a
revocation, deterministic rebuild removes it from later injection, unrelated
and false-positive-trap memories remain, and ledger verification must succeed.

**Residual risk**: Shadow mode intentionally permits durable reuse and a later
task can act on the admitted text before revocation. The inert fixed-marker sink
limits this repository demonstration only; it neither contains a real
exfiltration path nor shows that a production tool call could be undone.

### TM-17: The Codex subscription child attempts a tool or spoofs output

**Scenario**: An ephemeral subscription child tries a command, file, MCP, web,
browser, delegation, or unknown future activity, or returns a valid-looking
document for a different request or digest.

**Expected control**: Screen secrets before launch; pass bounded sanitized data
on stdin under a fixed non-shell argument vector; use a private empty read-only
working directory, allow-listed environment, ignored user configuration, and
disabled high-risk features; and parse bounded JSONL conservatively. Any tool or
unknown event, malformed stream, identity or digest mismatch, invalid schema,
timeout, output overflow, executable drift, or incomplete child outcome rejects
the entire result and triggers POSIX process-group cleanup (direct-child cleanup
only on unverified Windows). No fixture or direct-API provider is substituted.
A schema-valid accepted assessment is still advisory;
deterministic policy makes the action decision.

**Residual risk**: The child is an agentic process using a networked Codex
service, not a tool-free API call. A side-effect attempt can happen before its
event is observed and rejected. Disabled features, a read-only sandbox, and
event validation are defense in depth, not outbound information-flow control.
A sanitizer false negative in the minimal input can still cross to the Codex
service, and a compromised Codex executable or host is outside the boundary.

### TM-18: Desktop demo setup or sink state is tampered or ambiguous

**Scenario**: The reserved MCP name already exists, configuration changes after
preview, a non-cooperating Desktop/editor process races a config write, setup or
teardown is interrupted, a receipt or staged file is replaced, runtime identity
drifts, teardown sees a different managed entry, or the sink receives
non-synthetic content.

**Expected control**: Preview has zero mutation or process side effects. Apply
requires explicit hook-trust assertion and confirmation, an intact normal
integration, a matching preview digest, safe no-follow paths, strictly verified
runtimes and source, an atomic private `prepared` receipt before config
mutation, and an exact independently digest-bound managed entry. Confirmed
Verity operations serialize under a private lock and each replacement checks
the expected whole-config SHA-256 head. Readiness requires the installed
receipt, entry, artifacts, runtimes, safe fixture probe, and product health to
agree. `prepared` setup and `removing` teardown states resume only under exact
receipt-bound conditions; a later setup archives an exact prior `removed`
receipt without overwriting a conflict. Teardown removes only the exact
receipt-bound entry and digest-matching staged regular files, preserves
unrelated TOML changes, and refuses drift instead of restoring a stale
whole-file backup. A failed normal-integration doctor blocks setup/readiness but
does not block otherwise exact teardown, so the user-wide synthetic entry is
not stranded. The sink rejects any value other than its two fixed markers and
neither retains nor transmits an arbitrary body.

**Residual risk**: Receipt and artifact hashes detect tested drift but do not
authenticate code against a supply-chain authority, and the demo receipt is not
an Ed25519-signed ledger event. Same-user or host compromise can replace the
receipt, code, configuration, and verifier together. The operation lock does
not include Codex Desktop or arbitrary editors, so a non-cooperating writer can
race a point-in-time digest check; quitting Desktop and applying a fresh preview
immediately reduce but do not eliminate that risk. The fixture proves only this
reviewed local scenario.

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
| Forged or replayed Control Room mutation | Loopback peer restriction, strict Host/Origin, bearer capability for non-browser clients, minimum-length passphrase challenge, single-use 60-second nonce, constant-time proof check, bounded challenge issuance, failed-proof cooldown, 15-minute idle HttpOnly session and CSRF for the UI, JSON-only request, confirmation, reason, actor, and idempotency key | A weak operator-selected passphrase remains guessable; same-user malware that steals a capability, verifier, passphrase, or live browser session can act with local authority. The two-phase idempotency reservation can remain indeterminate after a process interruption; replay is refused and operator recovery may be required. |
| Sanitized evidence retention | Original submitted bytes are not retained; bind their digest, permanently retain a bounded sanitized excerpt, and transiently queue full sanitized text under item/byte/age limits | Pattern sanitization is not exhaustive. Undetected sensitive text can remain in the signed excerpt or transient queue; the digest cannot reveal unavailable original bytes to a new verifier. |
| Secret-bearing source label or stream-abort reason | Pattern-sanitize before signed persistence; reduce URL-like source labels to a host label and remove query/fragment data | Novel secret formats may evade pattern screening; retained safe metadata remains sensitive local data |
| Runtime data or database path is a symbolic link, unsafe file type, unexpected owner, or overly permissive database file | Reject before SQLite use; create the database leaf with exclusive, no-follow semantics where supported and validate it again before connections | Same-user or host compromise remains outside scope; platform filesystem guarantees vary |

## Failure-Behavior Matrix

"Continue without memory" is fail-open only for current Codex task
availability. It is fail-closed for the Verity memory trust boundary.

| Failure | Memory commit | Session injection | Required signal and recovery |
|---|---|---|---|
| Daemon or local IPC unavailable | Refuse; never queue an unverified implicit commit | Return no Verity context; Codex may continue | Content-free health warning; recover daemon and rerun health checks |
| Hook times out, exits nonzero, or emits invalid output | No commit from that hook invocation | No context from a failed `SessionStart` hook | Codex hook status; daemon records a failure only if reachable; doctor checks trust, effective config, staged files, and the current verified Python runtime rather than executing a receipt-selected interpreter |
| Evidence queue reaches its item or byte bound | Reject atomically before signed capture | Existing verified view only | Content-free resource-limit response; drain or repair the worker |
| Queued evaluation exceeds three attempts or one hour | Append `EvidenceEvaluationFailed` and purge the full queued text | No memory from the failed evidence | Terminal safe error code and failed-queue count |
| Queued sanitized text fails its signed digest check | Append an exact signed terminal failure when possible, purge text, and mark the ledger unhealthy; preserve the failure across restart | Disable injection | Sticky critical integrity state; investigate local storage before restoring service |
| Ledger cannot open or append | Roll back and refuse | Use no view whose integrity cannot be established | Critical storage state; safe read-only audit if possible; repair before writes |
| Ledger chain, payload, signature, key ID, order, or covered projection fails verification | Start or remain in read-only mode; disable signed writes and do not load detector plugins | Disable all injection | Content-safe Control Room status/policy/audit access, invalid policy-validation label, first invalid event where attributable, and explicit operator repair path |
| Materialized view differs from replay | Disable commits that depend on the inconsistent view | Disable injection | Rebuild transactionally, then re-verify before re-enabling |
| Active policy is malformed or unavailable and no valid last-known-good policy exists | Fail closed | Disable Verity injection when eligibility cannot be established | Validation error and policy hash/version; install or restore a valid policy |
| Stored policy or evidence projection differs from its signed source event | Treat verification as failed; refuse new commits | Disable injection | Report content-free `policy_projection_drift` or `evidence_projection_drift` and first attributable event when available |
| Proposed policy activation is invalid while a validated active policy remains intact | Reject activation; retain validated active policy | Continue only under the still-verified active policy and view | Append `PolicyActivationRejected` with safe issue codes where storage permits; show last-known-good status |
| Detector timeout, exception, cancellation, oversized output, or malformed result | Reject unusable output as a failure; high-risk ambiguity quarantines; lower fallback only by explicit rule | Never inject quarantined result | Detector ID/version/safe error class only; plugin free text and metadata are not reflected in routine detail |
| Semantic timeout, refusal, API error, or invalid schema | Never silently use a fixture; high-risk ambiguity quarantines | Never inject quarantined result | Provider state, error class, prompt/model version; retry only within bounded policy |
| Secret screening fails or finds prohibited material | Do not send content to semantic provider; block or quarantine | No raw secret injection | Safe category and placeholder metadata only |
| Signing key missing, unreadable, or has unsafe permissions | Refuse new signed events and commits | Disable injection; otherwise a due TTL could remain active because `MemoryExpired` cannot be signed | Critical key health state; repair permissions or restore key through documented procedure |
| Detector plugin has duplicate ID or fails discovery | Reject duplicate/plugin; do not treat it as having passed | Only results from a complete policy-required detector set may inject | Plugin identity/version failure; operator removes or repairs plugin |
| Stream is oversized, cancelled, blocked, or abandoned | Abort; no partial commit and no later commit | None from the stream | Append abort outcome when ledger is available; otherwise health warning |
| Live OpenAI credentials are absent | Live semantic-required candidate cannot pass that stage | No fixture substitution and no ambiguous high-risk injection | `doctor` reports presence only, never the key; offline mode remains explicitly separate |
| Codex subscription login, capacity, executable, schema, or child execution is unavailable | Record an explicit subscription failure; never substitute API or fixture output; action follows the versioned semantic-failure rule and high-risk ambiguity quarantines | No memory from a high-risk failed assessment | Content-safe provider/failure/isolation state only; repair sign-in/runtime or select another provider explicitly |
| Subscription child emits a tool or unknown event | Reject the entire advisory result even if its final file is otherwise valid; terminate and reap the POSIX process group, with direct-child-only fallback on unverified Windows | No memory based on the rejected assessment | `failed/tool_activity`; this is result rejection, not proof that an attempted side effect was prevented |
| Subscription child times out, is cancelled, exceeds an output bound, or cannot complete verified cleanup | Reject partial output, terminate POSIX descendants (direct child only on unverified Windows), and record the safe failure class; a cleanup-integrity failure also degrades provider health | No successful assessment and no implicit allow | Retry only within the configured bound after health recovery; raw child output and paths remain hidden |
| Desktop demo preview, receipt, managed entry, artifact, runtime, or normal integration does not verify | Refuse setup/reconciliation/readiness; do not guess, overwrite a collision, or run a drifted fixture. An unhealthy normal integration does not block separately digest-confirmed exact teardown. | Existing Verity memory behavior remains governed by the separate normal integration | Content-safe issue code and a fresh preview or bounded manual recovery path; close Desktop because its user-wide config writer does not cooperate with the Verity lock |
| Desktop teardown sees managed-entry or artifact drift | Refuse automatic removal and preserve current configuration and receipt state | No change to memory ledger or normal integration | Resolve drift manually, then rerun exact-state verification |
| Demo sink receives an unexpected value or field | Reject without retention, hashing the arbitrary body, or external transmission | No memory effect; sink is not a trust boundary | Fixed safe rejection only; never echo input |
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

The Codex subscription provider adds a deliberately lower-isolation agentic
boundary. Rejection of observed tool activity protects the acceptance decision;
it does not provide outbound information-flow control or prove that no activity
was attempted. The Desktop installer and fixed-marker sink reduce demo risk and
detect tested drift, but their receipts and SHA-256 values are local integrity
checks rather than signatures, supply-chain attestations, or network
noninterference proofs.

The release gate is evidence, not aspiration. Tests cover the demonstrated
critical claims, including payload/event/order/omission/signature tampering and
later-session exclusion. Some abuse cases above deliberately document residual
or unimplemented coverage—especially general encoded-content handling,
kind/content mismatch, and automatic policy-wide rescan—and must not be
presented as fixture-proven protection merely because they appear in this
model.

## Review Triggers

Review this model when a Codex hook contract changes; a new capture surface,
detector plugin mechanism, storage backend, policy action, key mechanism, or
agent integration is added; live provider data handling changes; or a test
finds a new bypass. Deferred multi-tenant, remote-policy, HSM, federation, and
other-agent work requires a separate numbered feature and threat model update.
