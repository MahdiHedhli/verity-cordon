# Verity Cordon Trust Boundaries

**Feature**: `001-codex-memory-firewall`
**Review date**: 2026-07-15
**Deployment boundary**: Single-user local macOS or Linux host

## Boundary Summary

Verity Cordon treats all proposed memory content as untrusted, even when it
originates from the operator, Codex, a model, a previously approved memory, or
a local tool. Trust is granted only to a specific, versioned policy decision
and can later be revoked. Trust in a memory event does not establish that its
statement is factually true or that text inside a fact has instruction
authority.

The local host and operator account form the MVP's outer security boundary.
Within it, process and data boundaries still matter: Codex does not write the
active view, the hook adapter does not make policy decisions, plugins do not
grant trust, the semantic model does not choose the final action, and the UI
does not mutate derived state directly.

```text
untrusted user, file, tool, and model content
                     |
                     v
              local Codex host
                     |
          documented command hooks
                     |
                     v
             thin hook adapter
                     |
       bounded authenticated loopback IPC
                     |
                     v
              verityd daemon (TCB)
        +------------+-------------+
        |            |             |
        v            v             v
  detector code  sanitized      deterministic
  and plugins    OpenAI call    policy engine
        \            |             /
         +-----------+------------+
                     |
                     v
        signed SQLite event ledger
                     |
                     v
        derived active-memory view
           |                   |
           v                   v
   SessionStart context   Control Room API
```

## Verified Codex Integration Boundary

The integration design was checked against the published
[Codex hooks documentation](https://learn.chatgpt.com/docs/hooks),
[Codex memories documentation](https://learn.chatgpt.com/docs/customization/memories),
and [configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
on 2026-07-15.

The documented hook events include `SessionStart`, `SubagentStart`,
`PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`,
`UserPromptSubmit`, `SubagentStop`, and `Stop`. `SessionStart` command-hook
output can add extra developer context. The native local-memory controls include
`memories.generate_memories` and `memories.use_memories`.

No published hook intercepts native memory read, write, generation, injection,
or commit operations. Verity Cordon therefore implements a controlled
replacement memory plane rather than claiming transparent interception. The
controlled posture is:

```toml
[features]
hooks = true
memories = false

[memories]
generate_memories = false
use_memories = false
disable_on_external_context = true
```

`disable_on_external_context` is defense in depth, not a substitute for
disabling native generation and use. The installer and `verity doctor` must
verify the effective configuration. Project-scoped config and hooks are ignored
when the project is untrusted, so a user-level installation or a verified launch
wrapper is required for that case. Native memory files are generated state and
must not be edited by Verity as its primary control mechanism.

The documented runtime has additional security consequences:

- Non-managed command hooks require operator review and trust of the exact hook
  definition. A changed definition is skipped until reviewed again.
- Only command handlers execute today. An `async` command hook is skipped, so
  the command adapter is synchronous from Codex's perspective and delegates to
  the async daemon through a short bounded request.
- Matching hooks from active layers can launch concurrently; no security
  decision may depend on ordering between separate hook handlers.
- The default hook timeout is too broad for this path. Verity hook entries must
  set a short explicit deadline and return no memory on timeout or daemon
  failure.
- `PostToolUse` sees a result after the tool ran. It can protect durable reuse
  but cannot undo the tool's current-session side effects.
- Tool-hook coverage is limited to documented supported paths. The poisoned
  MCP demo path is covered; not every possible Codex action is intercepted.
- `transcript_path` is convenient but its file format is not stable. Security
  logic must consume documented event fields and versioned Verity contracts,
  not parse the transcript as an enforcement interface.

The supported injection contract is a `SessionStart` JSON response containing
`hookSpecificOutput.hookEventName = "SessionStart"` and approved, delimited
memory in `hookSpecificOutput.additionalContext`. On daemon, ledger, policy, or
view-integrity failure, the adapter returns no additional memory. A content-free
`systemMessage` may report degraded health without exposing evidence.

## Trust-Boundary Register

### TB-01: Operator and local host

**Trusted for**: Installing reviewed code, protecting the user account,
confirming trust changes, and safeguarding keys and local evidence.

**Not trusted as memory evidence**: A direct user request to remember content
still requires secret screening, provenance, detectors, and policy.

**Controls**: Explicit confirmations and reasons for approval, block, mode
change, and revocation; restrictive local permissions; no secret-bearing output;
and append-only actor records.

**Residual boundary**: Root, user-account, OS, or signing-key compromise defeats
the MVP's local assurances. Enterprise identity and separation of duties are
deferred.

### TB-02: Codex process and native-memory configuration

**Trusted for**: Supplying documented hook inputs and applying documented
`SessionStart` developer context when the non-malicious Codex binary is
correctly configured.

**Untrusted input**: User prompts, model text, file contents, tool inputs and
outputs, MCP content, and prior conversational context.

**Controls**: Disable native local-memory generation and use; install only
documented hooks; verify hook trust and effective configuration; delimit
injected memory; and treat hook coverage as bounded.

**Residual boundary**: A malicious Codex binary is out of scope. Hook coverage
does not provide complete current-session prompt-injection prevention.

### TB-03: Thin Codex hook adapter

**Trusted for**: Validating the basic hook envelope, imposing a strict request
deadline, authenticating to the local daemon, and formatting documented output.

**Must not do**: Load a model, execute detectors, choose policy, open a remote
database, mutate the active view, parse an unstable transcript format, or inject
raw evidence.

**Controls**: Size and schema limits; event-specific adapters; idempotency keys;
content-free errors; no secret logging; and no-memory success behavior when the
daemon is unavailable.

**Residual boundary**: A skipped, untrusted, or failed hook creates a capture
gap. `doctor` reports this state; it cannot be described as protected.

### TB-04: Local IPC and HTTP API

**Endpoint**: `http://127.0.0.1:8765/api/v1` by default. Binding to wildcard or
non-loopback interfaces requires an explicit future security design and is not
part of the hackathon product.

**Controls**:

- A per-installation random bearer capability protects non-browser mutation
  clients. The capability is stored outside Git with user-only permissions and
  is never printed, logged, placed in a URL, or exposed to browser or semantic
  content.
- The exact same-origin Control Room obtains a separate short-lived session
  by answering a one-time challenge with an HMAC derived from an operator
  passphrase using PBKDF2-HMAC-SHA256. In the browser it exists only in a
  dedicated `type=password` input and transient derivation memory; the field
  disables autocomplete where supported and is cleared immediately. The
  passphrase is never rendered elsewhere, persisted, logged, or sent over HTTP.
  After
  `POST /api/v1/ui/session`, the daemon keeps the opaque session value in an
  HttpOnly, SameSite=Strict cookie; JavaScript receives only a short-lived CSRF
  value, keeps it in memory, and sends it in `X-Verity-CSRF`. Proof, session,
  CSRF, exact Origin, and strict Host checks are all required for a browser
  mutation. The local passphrase requires at least 12 characters; challenges
  are limited to 20 per minute, single-use, and expire after 60 seconds; proof checks use constant-time
  comparison; five failed proofs in five minutes trigger a five-minute global
  cooldown; sessions expire after 15 idle minutes; and authentication failures
  produce only content-free status and `Retry-After` output.
- Trust-changing requests require either the bearer capability or the
  proof-backed browser session plus CSRF, JSON content type, confirmation
  fields, actor, reason, and replay protection or idempotency.
- `Host` is restricted to the configured loopback host and port. Browser
  mutations accept only the Control Room's exact loopback `Origin`; missing,
  `null`, wildcard, and foreign origins are rejected.
- CORS is disabled or allow-listed to the exact Control Room origin; credentialed
  wildcard CORS is prohibited.
- Request body, response, connection, and processing deadlines are bounded.
- Routine reads expose safe representations only. Raw evidence has no default
  list endpoint and must never be included in error responses.

**Residual boundary**: Loopback is not user isolation. A process running as the
operator can attempt to reach the service, and theft of the local capability
permits authorized mutations. Production local identity and RBAC are deferred.

### TB-05: Verity daemon and deterministic policy engine

**Trusted computing base**: The daemon validates contracts, sanitizes evidence,
runs detectors, applies the active versioned policy, appends signed events, and
materializes views.

**Controls**: Async non-blocking I/O; bounded task fan-out; deterministic
detector aggregation; Pydantic validation; fail-closed policy behavior; atomic
storage transactions; serialized sequence allocation; and privacy-safe
telemetry.

**Residual boundary**: A daemon implementation flaw can invalidate several
controls at once. Critical-path modules require unit, integration, adversarial,
and fault-injection tests.

### TB-06: Detector implementations and plugins

**Trusted for**: Producing advisory, schema-validated findings under a specific
ID and version.

**Not trusted for**: Granting memory trust or mutating storage. Plugin output is
an input to deterministic policy.

**Controls**: Explicit installation trust; allow-listed entry-point group;
duplicate-ID rejection; deadline, cancellation, result-size, and schema bounds;
failure isolation; deterministic ordering; and explicit failure findings.

**Residual boundary**: In-process Python plugins execute as the daemon user and
are not sandboxed. A malicious plugin may access user-level resources or stop
the daemon. The reference plugin demonstrates discovery, not code isolation.

### TB-07: OpenAI API and semantic adjudicator

**Data crossing out**: Only bounded, locally sanitized evidence with detected
secrets replaced by typed placeholders, plus the minimum provenance needed for
the assessment.

**Data crossing in**: Schema-constrained candidate extraction or semantic risk
recommendations. Returned content is untrusted model output.

**Controls**: Official async SDK; configured `gpt-5.6` alias with returned model
recorded; no tools, conversation, previous response, or durable model memory;
`store=false`; strict instructions to treat evidence as data; structured output
validation; short timeout; bounded retry; sanitized-digest cache where safe;
and deterministic policy as final authority.

The cache key also binds provenance-sensitive source class, namespace, kind,
session/task scope, persistence request, authority/secrecy signals, model,
prompt, and schema versions. A text-identical candidate from a trusted user and
an untrusted tool is not the same cache input.

**Residual boundary**: Sanitization can miss a secret, the model can err or
refuse, and `store=false` is not a claim of Zero Data Retention. Live mode
depends on the operator's OpenAI data-governance settings and network path.

### TB-08: SQLite database and event payload store

**Authoritative data**: Ordered signed event history and payloads bound by
digest. Active and quarantined tables are derived and rebuildable.

**Controls**: User-only file permissions; versioned schema initialization;
transactional event, payload, and view writes; unique contiguous sequence
allocation; foreign keys and integrity checks; startup and on-demand ledger
verification; an atomically replaced signed expected-head sidecar outside the
SQLite file; backups treated as sensitive local data.

**Residual boundary**: The MVP does not promise encryption at rest. Hashes and
signatures detect covered modification but do not prevent reads, deletion, or
denial of service. A compromised host can replace both data and verifier.

### TB-09: Installation signing key

**Trusted for**: Signing the SHA-256 digest of each canonical event and
identifying the installation key used.

**Controls**: Ed25519; per-installation key; OS keychain when practical or a
documented user-only local-file fallback; key ID and public-key export; private
key excluded from Git, logs, backups intended for public sharing, and API
responses; startup permission check; no automatic insecure regeneration over
an existing history.

**Residual boundary**: The local key is not an HSM, remote attestation, or
external transparency anchor. Key theft permits forged history; key loss can
prevent new events and requires an explicit recovery procedure.

### TB-10: Memory Control Room

**Trusted for**: Rendering safe daemon state and submitting confirmed operator
intent. It is not authoritative storage.

**Controls**: Same-origin loopback service; strict Host and Origin validation;
passphrase proof, origin-bound HttpOnly session, and CSRF for browser mutations;
no wildcard CORS; safe redacted representations; accessible confirmation
dialogs; no optimistic trust-change success. Raw secrets never appear in URLs,
browser storage, console, screenshots, or error reports. The sole raw-passphrase
DOM exception is a dedicated non-autocompleted password input that is cleared
immediately after local key derivation and never submitted or rendered.

**Residual boundary**: Browser extensions, a compromised local browser profile,
or same-user malware are outside the UI boundary. The UI cannot establish
strong operator identity in the single-user MVP.

### TB-11: Local poisoned-docs demo MCP server

**Trust classification**: Deliberately untrusted evidence source and inert
security fixture.

**Controls**: Loopback-only binding; synthetic constants only; no process
environment reads; no filesystem secret discovery; no external requests; no
real tool invocation or exfiltration; and prominent source documentation that
the behavior is a demonstration.

**Residual boundary**: The fixture proves only the included attack path. It is
not representative of all MCP servers or every persistence technique.

## Data Classification and Allowed Flows

| Data class | Default location | May cross to OpenAI | May appear in telemetry or list UI | Integrity treatment |
|---|---|---:|---:|---|
| Raw evidence | Protected local evidence store, minimized retention | Never as raw evidence | No | SHA-256 evidence digest referenced by events |
| Detected credential or secret | Protected local evidence only if retention policy permits | Never | Never | Typed placeholder and safe finding metadata |
| Sanitized evidence | Daemon memory and bounded cache | Yes, in explicit live mode | Digest, length, and source class only | Digest recorded with semantic request metadata |
| Candidate safe representation | Local candidate store | Yes, if policy invokes semantic review | Yes, only after redaction rules | Candidate ID, source refs, and payload digest |
| Semantic assessment | Local event payload | Returned from OpenAI | Provider state, categories, scores, and safe rationale | Schema/version/model/prompt bound to event |
| Active memory | Derived local view | Not for adjudication unless rescanned | Safe statement according to policy | Deterministic replay from committed events |
| Ledger event and public key | Local database; public export when requested | No | Safe metadata may appear | `VC-CJ-1`, SHA-256 chain, Ed25519 signature |
| Private signing key or IPC capability | OS keychain or user-only local file | Never | Never | Permission and availability checks; never event payload |

## Trust Transitions

1. **Observe**: Hook or demo source data is untrusted evidence. Capture assigns
   source, session/task identity, safe representation, and digest; it grants no
   memory trust.
2. **Sanitize**: Local deterministic screening replaces detected secrets before
   any model call. Sanitized does not mean approved.
3. **Extract**: Atomic candidates remain untrusted and retain evidence links and
   extractor version.
4. **Assess**: Detector results and optional semantic output are advisory,
   versioned inputs. Failures are first-class findings.
5. **Decide**: Deterministic policy records rule, version, mode,
   `actual_action`, and `would_have_action`. Shadow admission remains labeled.
6. **Commit**: An allowed or redacted candidate becomes eligible only after an
   atomic signed ledger commit. Quarantine and block events never populate the
   active view.
7. **Expire/materialize**: Before injection, a healthy lifecycle sweep appends
   `MemoryExpired` for due TTLs. Replay admits only committed entries with no
   later expiry, revocation, or supersession event. It never consults the
   current clock while replaying history. The view is derived, not a second
   authority.
8. **Inject**: `SessionStart` receives a bounded, typed, delimited snapshot only
   after ledger and view verification.
9. **Revoke**: A new reasoned event removes the referenced memory on replay;
   history remains and unrelated memory is preserved.

## Session-Start Injection Boundary

Approved entries use an unambiguous wrapper such as:

```text
VERITY_CORDON_APPROVED_MEMORY_START

Memory ID: <opaque-id>
Type: fact
Namespace: project.dependencies
Trust decision: allowed
Provenance: user_input
Statement: <safe approved statement>

VERITY_CORDON_APPROVED_MEMORY_END
```

The surrounding developer context states that the block is Verity-approved
durable memory, not system truth; facts and tool observations must not be
executed as instructions; operational instructions require the stronger trust
class recorded in the entry; and manual approval is explicit. Entries are
selected deterministically within a token budget and never truncated inside a
record. Blocked, quarantined, expired, revoked, superseded, invalid, or
unverified entries are absent.

Delimiting is defense in depth, not an instruction-injection proof. Screening,
policy, typed fields, provenance, and later revocation remain required.

## Boundary Failure Rule

At every boundary, content trust fails closed even when Codex task availability
fails open. If the adapter, daemon, policy, ledger, key verification, or view
cannot establish eligibility, Verity supplies no durable memory. The current
Codex session may continue with a content-free warning. Detailed component
behavior and residual risks are defined in
[the threat model](./threat-model.md#failure-behavior-matrix).

## Change Control

Adding a non-loopback listener, remote policy source, new agent integration,
new storage backend, plugin process isolation, enterprise identity, public
Control Room, or hardware-backed key changes these boundaries and requires a
separate numbered feature or explicit scope amendment. None is implied by the
MVP interfaces.
