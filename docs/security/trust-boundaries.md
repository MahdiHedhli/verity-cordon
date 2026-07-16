# Verity Cordon Trust Boundaries

**Features**: `001-codex-memory-firewall`,
`002-codex-desktop-subscription-defense`
**Review date**: 2026-07-15
**Deployment boundary**: Single-user local host; macOS exercised, Linux intended
but not yet recorded as exercised, Windows unverified

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

The Codex subscription provider is a separate lower-isolation
`agentic_sandboxed` child boundary, not the direct API boundary. Verity rejects
its result when it observes tool or unknown activity, but that rejection is not
outbound information-flow control. The Desktop poisoned-docs MCP server is also
separate: it is an explicitly installed, receipt-bound, synthetic fixture with
one inert fixed-marker sink, not a product data destination.

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
       signed capture + bounded sanitized
             SQLite evidence queue
                     |
                     v
              verityd daemon (TCB)
        +------------+-----------------------+
        |            |                       |
        v            v                       v
  detector code  semantic router       deterministic
  and plugins      /       \           policy engine
                  v         v                /
          direct OpenAI   Codex subscription
          tool-free API   child (agentic,
                          lower isolation)
                  \         /
                   +-------+
                       |
         advisory schema-bound output only
                       |
         +-------------+--------------------+
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

The Desktop attack fixture is an additional evidence-source path:

```text
explicit demo setup + private write-ahead receipt
                     |
                     v
 Codex Desktop -> local stdio poisoned-docs MCP fixture
                     |                    |
                     |              fixed-marker inert sink
                     v
 documented hook capture -> normal Verity lifecycle above
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

Normal integration preview is read-only. Confirmed install and uninstall use
one private cooperating-process lock and expected-head SHA-256 checks for every
config replacement and receipt transition. Receipt version 2 records a
write-ahead `prepared` state before staged marketplace executables can change,
binding prior and target artifact digests, config heads, backup digest, preview
digest, the actual target interpreter path/digest/size/version, and fixed
active, staging, retired, and removal-tree paths. Recovery accounts for every
retained executable tree; random temporary or retired tree names are not used.
Every tree component and artifact is owner/mode/type checked with no symlink
traversal before digest use, rename, or removal. Successful Codex add/remove
steps are journaled so retries skip normal already-present/absent operations.
Artifact replacement preserves a receipt-verified marketplace registration and
uses an explicit `refresh_plugin` strategy with a separately journaled plugin
remove/add sequence; it does not reset registration progress and depend on an
already-present add succeeding.
Uninstall separately journals command removal, config restoration, tree
tombstoning/removal, and receipt deletion, including both config heads and its
backup digest. Recovery continues only from an exact receipt-bound phase.
Relative roots, symlinked or dangling security paths, and unsafe owner/mode
paths are rejected. Legacy receipts may be upgraded or removed but cannot
satisfy runtime readiness.

An external Codex command and the following local receipt transition are not
one transaction. A process interruption or receipt atomic-write,
synchronization, or replacement I/O failure after external success leaves a
narrow ambiguous state that requires Codex status reconciliation or operator
review; incomplete journal state never satisfies readiness.

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
- Tool-hook coverage is limited to documented supported paths. The adapter
  contract accepts supported MCP `PostToolUse` output. The one-command offline
  demo invokes the reviewed poisoned-docs fixture over bounded stdio, validates
  its response, and submits it directly to the core service; it does not claim
  that every possible Codex action is intercepted.
- `transcript_path` is convenient but its file format is not stable. Security
  logic must consume documented event fields and versioned Verity contracts,
  not parse the transcript as an enforcement interface.

The supported injection contract is a `SessionStart` JSON response containing
`hookSpecificOutput.hookEventName = "SessionStart"` and approved, delimited
memory in `hookSpecificOutput.additionalContext`. On daemon, ledger, policy, or
view-integrity failure, the adapter returns no additional memory. A content-free
`systemMessage` may report degraded health without exposing evidence.

The Desktop demo installer is deliberately separate from the normal Codex
installer. It manages only the reserved
`mcp_servers.verity_cordon_poisoned_docs` entry, a digest-verified staged script,
and a private write-ahead receipt. Preview has no side effects; apply and
teardown require explicit confirmation. Normal installation never stages or
enables the fixture. Under the exercised Codex `0.144.4` surface, the table is
stored in `$CODEX_HOME/config.toml` and is user-wide. A dedicated workspace and
the fixture `cwd` are not a project-scope enforcement boundary.

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
daemon is unavailable. The installer receipt binds the hook runtime to the
currently verified Python executable path, SHA-256, size, and
executable-reported version. `doctor` checks path, digest, and size before
executing it, rechecks the complete identity after the bounded cached-hook
probe, and never executes an arbitrary interpreter path supplied only by a
modified receipt.

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
  After `POST /api/v1/ui/session`, the daemon keeps the opaque session value in an
  HttpOnly, SameSite=Strict cookie; JavaScript receives only a short-lived CSRF
  value, keeps it in memory, and sends it in `X-Verity-CSRF`. Proof, session,
  CSRF, exact Origin, and strict Host checks are all required for a browser
  mutation. The local passphrase requires at least 12 characters; challenges
  are limited to 20 per minute, single-use, and expire after 60 seconds; proof
  checks use constant-time comparison; five failed proofs in five minutes
  trigger a five-minute global cooldown; sessions expire after 15 idle minutes;
  and authentication failures produce only content-free status and
  `Retry-After` output.
- Trust-changing requests require either the bearer capability or the
  proof-backed browser session plus CSRF, JSON content type, confirmation
  fields, actor, reason, and replay protection or idempotency.
- `Host` is restricted to the configured loopback host and port. Browser
  mutations accept only the Control Room's exact loopback `Origin`; missing,
  `null`, wildcard, and foreign origins are rejected.
- CORS is disabled or allow-listed to the exact Control Room origin; credentialed
  wildcard CORS is prohibited.
- Every API response carries `Cache-Control: no-store` and `Pragma: no-cache`.
- Request body, response, connection, and processing deadlines are bounded.
- Routine reads expose pattern-sanitized or content-hidden representations
  only. Original evidence bytes are not retained and must never be included in
  responses; a sanitized excerpt can still contain an undetected sensitive
  value.

**Residual boundary**: Loopback is not user isolation. A process running as the
operator can attempt to reach the service, and theft of the local capability
permits authorized mutations. The mutation idempotency mechanism reserves a key
before acting and records the response afterward; interruption between those
steps leaves an indeterminate reservation that is refused on retry and may need
local recovery. Production local identity and RBAC are deferred.

### TB-05: Verity daemon and deterministic policy engine

**Trusted computing base**: The daemon validates contracts, sanitizes evidence,
runs detectors, applies the active versioned policy, appends signed events, and
materializes views.

**Controls**: Async non-blocking I/O; bounded task fan-out; deterministic
detector aggregation; Pydantic validation; fail-closed policy behavior; atomic
storage transactions; serialized sequence allocation; signed capture before
hook acknowledgement; bounded SQLite queue item/byte/attempt/age limits; and
privacy-safe telemetry.

Startup verifies the ledger before using the stored active policy. If history
or a signed projection is invalid, the daemon builds only a read-only runtime:
the fallback configured or built-in policy is labeled invalid, does not
authorize injection or signed writes, and detector plugins are not loaded.
Content-safe Control Room status, policy, and audit reads remain available for
diagnosis.

**Residual boundary**: A daemon implementation flaw can invalidate several
controls at once. Critical-path modules require unit, integration, adversarial,
and fault-injection tests.

### TB-06: Detector implementations and plugins

**Trusted for**: Producing advisory, schema-validated findings under a specific
ID and version.

**Not trusted for**: Granting memory trust or mutating storage. Plugin output is
an input to deterministic policy.

**Controls**: Explicit installation trust; allow-listed entry-point group;
duplicate-ID rejection; deadline, cancellation, fixed field/count/UTF-8 and
serialized-result bounds; schema validation; secret sanitization of messages,
categories, and string metadata; failure isolation; deterministic ordering;
and explicit failure findings. Routine Control Room detail allow-lists category
labels, drops plugin metadata, and replaces plugin messages with fixed summaries.

**Residual boundary**: In-process Python plugins execute as the daemon user and
are not sandboxed. A malicious plugin may access user-level resources or stop
the daemon. The reference plugin demonstrates discovery, not code isolation.

### TB-07: Direct OpenAI API and semantic adjudicator

**Data crossing out**: Only bounded, locally sanitized evidence with detected
secrets replaced by typed placeholders, plus the minimum provenance needed for
the assessment.

**Data crossing in**: Schema-constrained candidate extraction or semantic risk
recommendations. Returned content is untrusted model output.

**Controls**: Official async SDK; configured `gpt-5.6` alias with returned model
recorded; no tools, conversation, previous response, or durable model memory;
`store=false`; strict instructions to treat evidence as data; structured output
validation; fixed character/UTF-8/count bounds; a second local sanitization pass
over model-originated statement and rationale text; short timeout; bounded
retry; no semantic-result reuse in the MVP; and deterministic policy as final
authority. Routine UI detail allow-lists semantic categories and hides model
free-text rationale. Semantic caching remains disabled because unsigned cached
advisory output could change a later policy decision.

**Residual boundary**: Sanitization can miss a secret, the model can err or
refuse, and `store=false` is not a claim of Zero Data Retention. Live mode
depends on the operator's OpenAI data-governance settings and network path.
The Codex subscription path does not inherit this boundary's tool-free or
`store=false` claims; it is defined separately in TB-12.

### TB-08: SQLite database and event payload store

**Authoritative data**: Ordered signed event history and payloads bound by
digest. Active and quarantined tables are derived and rebuildable.

**Controls**: User-only file permissions; versioned schema initialization;
transactional event, payload, and view writes; unique contiguous sequence
allocation; foreign keys and integrity checks; startup and on-demand ledger
verification; an atomically replaced signed expected-head sidecar outside the
SQLite file; signed-source comparison for evidence, policy, candidate,
detector, semantic, and decision projections; bounded pending evidence; digest
verification before queued evaluation; full queue-text deletion on success and
purge on terminal failure; exact signed-event verification of terminal queue
rows; sticky fail-closed queue-integrity state across restart; backups treated
as sensitive local data.

Configured data directories and database parents are required to be owned
private directories on platforms that expose ownership. The SQLite database
leaf is opened/validated as a restrictive current-user regular file and is
rejected when it is a symbolic link, unexpected type, unexpected owner, or has
group/other permission bits.

**Residual boundary**: The MVP does not promise encryption at rest. Hashes and
signatures detect covered modification but do not prevent reads, deletion, or
denial of service. `EvidenceCaptured` permanently retains a bounded
pattern-sanitized excerpt; sanitizer false negatives can leave sensitive text
in the ledger. A compromised host can replace both data and verifier.

### TB-09: Installation signing key

**Trusted for**: Signing the SHA-256 digest of each canonical event and
identifying the installation key used.

**Controls**: Ed25519; per-installation user-only local key file; key ID and
public-key export; private key excluded from Git, logs, backups intended for
public sharing, and API responses; startup permission check; no automatic
insecure regeneration over an existing history. OS-keychain support is
deferred.

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
Plugin metadata and model/plugin free-text explanations are not reflected into
candidate detail; fixed summaries and an allow-listed risk taxonomy are used.

**Residual boundary**: Browser extensions, a compromised local browser profile,
or same-user malware are outside the UI boundary. The UI cannot establish
strong operator identity in the single-user MVP.

### TB-11: Local poisoned-docs stdio fixture

**Trust classification**: Deliberately untrusted evidence source and inert
security fixture.

**Controls**: MCP-style JSON-RPC over stdin/stdout only with no network listener;
synthetic constants only; no process-environment reads; no filesystem secret
discovery; no external requests; and prominent source documentation that the
behavior is a demonstration. It exposes exactly `get_release_guidance` and
`demo_artifact_sink`. The sink accepts only the fixed manifest and environment
marker literals, rejects additional or changed content, keeps no body, and
returns a count, acceptance flag, fixed-pair digest, and
`external_transmission_performed=false`. The one-command offline demo starts
this reviewed process with a minimal environment, exchanges bounded stdio
messages, validates its identity and inert response, and then sends the returned
synthetic content to the core service.

**Residual boundary**: The fixture proves only the included attack path. It is
not representative of all MCP servers or every persistence technique. The sink
flag and fixed-pair digest describe this implementation and input; they are not
cryptographic proof that an arbitrary process performed no outbound action.

### TB-12: Codex subscription semantic child

**Trust classification**: Lower-isolation `agentic_sandboxed` semantic adviser.
It is not a tool-free API request and never grants memory trust.

**Data crossing out**: Only bounded locally sanitized evidence or a candidate
safe representation, the minimum provenance needed for the operation, the
locally supplied subject identity (`evidence_id` or `candidate_id`), and the
SHA-256 digest of the sanitized content text. Extraction hashes the sanitized
evidence; assessment hashes only the sanitized `candidate.statement`, not the
other candidate fields. The child uses the operator's supported ChatGPT sign-in
through Codex; Verity does not open, copy, parse, print, persist, or watch Codex
credential files.

**Controls**: Explicit provider selection; verified Codex executable and auth
directory identity; a fresh allow-listed environment with no API keys, bearer
values, proxy credentials, or arbitrary parent variables; fixed non-shell argv;
stdin-only untrusted content; ephemeral execution; ignored user configuration
and rules; private empty read-only working directory; disabled high-risk
feature surfaces; strict output schema; subject identity and content-text digest
matching;
bounded JSONL, stderr, and final file; conservative rejection of every tool or
unknown event; POSIX process-group termination and descendant reaping (with
direct-child-only fallback on unverified Windows); local re-sanitization;
explicit provider/isolation labels; and no fallback to the API or fixture.
Deterministic versioned policy consumes accepted output as advice and makes the
final action decision.

**Residual boundary**: The child must use a networked Codex service. A tool or
other side-effect attempt can occur before Verity observes and rejects its
event, and future activity may not be represented by the currently understood
event grammar. POSIX process-group cleanup was tested; the unverified Windows
fallback terminates the direct child and does not provide the same descendant
guarantee. These controls do not provide outbound information-flow control
or prove that no tool existed. Sanitization may miss a secret. Subscription
availability, service behavior, workspace policy, and rate limits are external
state. A malicious Codex binary or fully compromised host remains out of scope.

### TB-13: Desktop demo installer and private receipt

**Trusted for**: Previewing and managing one reserved local MCP table and one
reviewed staged fixture without changing the normal Verity integration, ledger,
memory view, or policy state.

**Controls**: Read-only zero-side-effect preview; explicit confirmation and
preview-digest match; an explicit operator hook-trust assertion; prerequisite
normal-integration doctor for setup/readiness; reserved-name collision refusal
without serializing the existing value; bounded no-follow paths; private modes;
resolved absolute regular executables with owner/ancestor mode checks plus
pinned source, staged artifact, Codex executable, and Python runtime SHA-256
identities and sizes; atomic writes; a schema-valid `prepared` receipt before
config mutation; an independently canonicalized managed-entry digest;
`prepared` and `removing` exact-state reconciliation; deterministic
installation-bound quarantine paths persisted before artifact rename;
repeatable archival of a digest-matching `removed` receipt by installation ID;
safe bounded fixture probe that never calls the sink; and teardown that removes
only the exact managed entry and digest-matching staged regular files while
preserving unrelated TOML changes. A non-empty staging directory prevents a
terminal removal receipt. Confirmed operations use a private Verity operation lock
and expected whole-config SHA-256 head. Teardown may proceed despite an
unhealthy normal integration when its own receipt, entry, artifacts, runtimes,
and separately reviewed teardown digest remain exact, so the user-wide fixture
is not stranded.

**Residual boundary**: The receipt is private local write-ahead state, not an
Ed25519-signed event and not a supply-chain attestation. File and entry hashes
detect tested drift under an uncompromised verifier; they do not prevent
modification. A coordinated same-user or host replacement of the receipt,
artifacts, configuration, runtimes, and verifier defeats this boundary. Status
is point-in-time, and ambiguous unreceipted state requires manual recovery. The
operation lock does not serialize Codex Desktop, editors, or arbitrary writers;
closing all other tasks and quitting Desktop around a fresh digest-confirmed
mutation is an operational mitigation for the remaining race. POSIX probe
cleanup uses a new process session and process-group termination. Windows is
unverified and lacks the same tested descendant process-group guarantee.

## Data Classification and Allowed Flows

| Data class | Default location | May cross to OpenAI | May appear in telemetry or list UI | Integrity treatment |
|---|---|---:|---:|---|
| Original evidence bytes | Not retained by the MVP | Never as original bytes | No | SHA-256 raw-content digest referenced by `EvidenceCaptured` |
| Recognized credential or secret | Not retained as raw content; replaced by a typed placeholder | Never as recognized raw content | Never | Redaction type/count and sanitized digest, without the value |
| Sanitized evidence | Permanent bounded `safe_excerpt` plus a transient bounded SQLite queue body | Yes, in explicit live mode | No queue body or capture excerpt in routine UI; telemetry uses digest/length/source | Queue body is checked against the sanitized digest bound in `EvidenceCaptured`; no semantic-result cache in the MVP |
| Subscription semantic input | Ephemeral Codex child stdin and private temporary files; no Verity session persistence | Yes, through Codex's supported ChatGPT subscription service when explicitly selected | Provider/isolation/failure state, latency, and IDs only; no prompt, status output, JSONL body, stderr, paths, or final free text | Locally supplied `evidence_id` or `candidate_id` and the sanitized content-text digest must match strict output; assessment covers `candidate.statement`, not the other candidate fields; this is not a signature from Codex or OpenAI and does not attest invocation freshness |
| Candidate safe representation | Local candidate store | Yes, if policy invokes semantic review | Yes, only after redaction rules | Candidate ID, source refs, and payload digest |
| Semantic assessment | Local event payload | Returned from direct OpenAI API or Codex subscription service | Provider state, isolation, categories, scores, and safe rationale | Schema/version/model-or-requested-model/prompt bound to event; subscription output also matches candidate subject identity and the digest of sanitized `candidate.statement` |
| Active memory | Derived local view | Not for adjudication unless rescanned | Safe statement according to policy | Deterministic replay from committed events |
| Ledger event and public key | Local database; public export when requested | No | Safe metadata may appear | `VC-CJ-1`, SHA-256 chain, Ed25519 signature |
| Private signing key or IPC capability | User-only local file; OS keychain support is deferred | Never | Never | Permission and availability checks; never event payload |
| Desktop demo receipt and staged fixture | Private local demo directory outside Git | No | Fixed state, issue codes, tool names, artifact sizes, and digest metadata only | Schema validation, private permissions, preview/entry/artifact/runtime digests, and exact-state checks; receipt is not ledger-signed |
| Demo sink arguments | Process memory in the reviewed local stdio fixture | No | Fixed marker names, count, acceptance, and canonical fixed-pair digest only | Exact equality to the two compiled synthetic literals; no arbitrary body is retained or hashed |

## Trust Transitions

1. **Observe/sanitize**: Hook or demo source data is untrusted evidence. Local
   pattern screening replaces recognized secrets. Source labels are sanitized;
   URL-like labels are reduced to the hostname and lose query/fragment data.
   Capture assigns source, session/task identity, a bounded sanitized excerpt,
   the raw-content and sanitized-content digests, and grants no memory trust.
2. **Queue**: The hook is acknowledged only after signed capture and a bounded
   full sanitized queue row commit atomically. Original submitted bytes are not
   retained. Sanitized does not mean non-sensitive or approved.
3. **Extract**: A background worker verifies the queue digest. Atomic candidates
   remain untrusted and retain evidence links and
   extractor version.
4. **Assess**: Detector results and optional semantic output are advisory,
   versioned inputs. The direct API and subscription child remain distinctly
   labeled; subscription is `agentic_sandboxed`, rejects observed tool activity,
   and never silently falls back. Failures are first-class findings.
5. **Decide**: Deterministic policy records rule, version, mode,
   `actual_action`, and `would_have_action`. Shadow admission remains labeled.
6. **Commit**: An allowed or redacted candidate becomes eligible only after an
   atomic signed ledger commit. Quarantine and block events never populate the
   active view. Outcome events—or `EvidenceEvaluationCompleted` for a
   zero-candidate drain—and deletion of the full queued text commit together;
   exhausted evaluation appends `EvidenceEvaluationFailed` and purges that text.
7. **Expire/materialize**: Before injection, a healthy lifecycle sweep appends
   `MemoryExpired` for due TTLs. Replay admits only committed entries with no
   later expiry, revocation, or supersession event. It never consults the
   current clock while replaying history. The view is derived, not a second
   authority.
8. **Inject**: `SessionStart` receives a bounded, typed, delimited snapshot only
   after ledger and view verification.
9. **Revoke**: A new reasoned event removes the referenced memory on replay;
   history remains and unrelated memory is preserved.
10. **Rescan**: A confirmed one-memory rescan verifies the original signed
    candidate and current signed policy, creates a fresh signed sanitized
    candidate, and records current findings and policy decision. Under
    enforcement, an unsafe result appends revocation and projection changes in
    the same transaction. No automatic policy-wide sweep is implied.

Desktop demo setup is outside this memory trust transition. It stages a local
evidence fixture and adds one receipt-bound MCP entry only after confirmation;
it does not approve memory, append ledger events, activate policy, or establish
that a Desktop task is protected. Protection requires candidate-specific signed
terminal memory events and a verified materialized view.

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
selected deterministically. The complete rendered UTF-8 byte length cannot
exceed the configured `injection_token_budget`, using byte count as a
conservative upper bound rather than an exact model tokenizer. Records that do
not fit are omitted and never partially truncated. Blocked, quarantined,
expired, revoked, superseded, invalid, or unverified entries are absent.

Delimiting is defense in depth, not an instruction-injection proof. Screening,
policy, typed fields, provenance, and later revocation remain required.

## Boundary Failure Rule

At every boundary, content trust fails closed even when Codex task availability
fails open. If the adapter, daemon, policy, ledger, key verification, or view
cannot establish eligibility, Verity supplies no durable memory. A failed
subscription child supplies no successful advisory assessment, records an
explicit failure for policy, and triggers no provider substitution. A failed or
drifted Desktop demo setup disables demo readiness and makes no
memory-protection claim. The current Codex session may continue with a
content-free warning. Detailed component behavior and residual risks are
defined in
[the threat model](./threat-model.md#failure-behavior-matrix).

## Change Control

Adding a non-loopback listener, remote policy source, new agent integration,
new storage backend, plugin process isolation, enterprise identity, public
Control Room, or hardware-backed key changes these boundaries and requires a
separate numbered feature or explicit scope amendment. None is implied by the
MVP interfaces. Changes to the supported Codex child invocation, JSONL event
grammar, subscription authentication marker, Desktop managed MCP entry, demo
receipt schema, or fixed sink contract also require review of TB-11 through
TB-13 and the related failure tests before publication.
