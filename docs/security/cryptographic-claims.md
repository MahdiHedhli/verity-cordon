# Verity Cordon Cryptographic Claims

**Feature**: `001-codex-memory-firewall`
**Cryptographic profile**: `VC-CJ-1` + SHA-256 + Ed25519
**Review date**: 2026-07-15

## Claim in One Sentence

Given an uncompromised installation public key and the expected ledger head,
Verity Cordon can verify whether the covered event content, payloads, ordering,
chain links, and signatures reproduce the recorded history.

This is a tamper-evidence claim, not a tamper-prevention claim. A valid
signature establishes that the event hash was signed by the corresponding
installation key. It does not establish factual truth, safe meaning, correct
policy, operator identity, confidentiality, or protection from a compromised
host or stolen signing key.

## Algorithm Suite

| Field | Required value | Purpose |
|---|---|---|
| `schema_version` | `1.0.0` | Selects the event-envelope contract |
| `canonicalization_algorithm` | `VC-CJ-1` | Selects the exact project JSON serialization profile below |
| `digest_algorithm` | `SHA-256` | Digests payloads and canonical event bodies |
| `signature_algorithm` | `Ed25519` | Signs the raw 32-byte event hash |
| `signing_key_id` | `vc-ed25519-` plus the full lowercase SHA-256 hex digest of the raw public key | Binds a stable lookup identifier to the public key |
| `signature` | Standard padded Base64 | Encodes the 64-byte Ed25519 signature |

SHA-256 and Ed25519 use their standard definitions. Verity Cordon does not
invent a custom digest or signature primitive. `VC-CJ-1` is a project-defined
serialization profile and is described fully because the same logical JSON can
otherwise have multiple byte representations.

## `VC-CJ-1` Canonical JSON Profile

`VC-CJ-1` is the byte representation produced by the Python 3.12 equivalent of:

```python
json.dumps(
    value,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    allow_nan=False,
).encode("utf-8")
```

Before calling the serializer, the implementation and verifier apply these
rules:

1. Input must be a value admitted by the versioned JSON Schema: object, array,
   string, finite JSON number, boolean, or null. Byte strings and arbitrary
   language objects are rejected.
2. A parser must reject duplicate object keys. Last-key-wins parsing is not
   acceptable for signed input.
3. Object keys are strings and are sorted recursively using Python's Unicode
   code-point string ordering. Array order is preserved.
4. Output uses UTF-8 without a byte-order mark and compact comma/colon
   separators with no insignificant whitespace.
5. Non-ASCII characters are emitted as UTF-8 rather than forced `\u` escapes.
   JSON-required escaping still applies to quotes, backslashes, and control
   characters.
6. Booleans and null use lowercase JSON literals. NaN, positive infinity, and
   negative infinity are rejected.
7. Finite numbers use the Python 3.12 JSON serializer's representation. Schema
   authors should prefer integers or normalized decimal strings for
   security-relevant values that need cross-language reproduction.
8. Timestamps are normalized before serialization to UTC RFC 3339 text ending
   in `Z`: `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`. Omit the fractional part when it is
   zero; otherwise emit one to six digits and remove trailing fractional zeroes.
9. No Unicode normalization is performed. Canonically composed and decomposed
   strings therefore produce different bytes and hashes. This intentionally
   binds the exact stored code points.
10. The serializer output ends immediately after the JSON value; no trailing
    newline is added.

`VC-CJ-1` is **not RFC 8785 JSON Canonicalization Scheme (JCS)**, and the
project must not describe it as RFC 8785 compliant. An independent verifier
must reproduce `VC-CJ-1` exactly or use the shipped verification library/CLI.
Moving to RFC 8785 would be a versioned cryptographic-profile migration, not a
silent implementation change.

## Key Identifier and Public-Key Fingerprint

An Ed25519 public key is exported in its standard 32-byte raw encoding. Its
identifier is derived without truncation:

```text
public_key_digest = SHA-256(raw_32_byte_ed25519_public_key)
signing_key_id = "vc-ed25519-" + lowercase_hex(public_key_digest)
fingerprint_sha256 = lowercase_hex(public_key_digest)
display_fingerprint = "SHA256:" + fingerprint_sha256
```

Machine contracts use `fingerprint_sha256`; the `SHA256:` prefix is display
formatting only. On verification, the verifier recomputes the digest from the
supplied public key and requires an exact `signing_key_id` match before
accepting a signature.
The public-key registry maps that ID to the raw public key and its lifecycle
metadata. A key ID is a lookup and integrity identifier, not proof of who owns
the installation.

## Payload Digest

The event `payload` is independently bound so a verifier can detect alteration
even if payload storage is separated from the envelope later.

```text
payload_bytes  = VC-CJ-1(event.payload)
payload_digest = lowercase_hex(SHA-256(payload_bytes))
```

The stored `payload_digest` is exactly 64 lowercase hexadecimal characters
with no `sha256:` prefix. Before verifying the event hash, the verifier must
recompute this digest from the stored payload and compare it in constant-time
where the library makes that practical. A missing payload, duplicate key,
non-finite number, schema-invalid value, or digest mismatch invalidates the
event.

`EvidenceCaptured` includes a bounded pattern-sanitized `safe_excerpt`, the
SHA-256 digest of the original submitted bytes, and the digest of the full
sanitized text. Original submitted bytes are not retained by the MVP. Event
`evidence_references` and the evidence projection must repeat the signed
raw-content digest exactly. Because those original bytes are unavailable after
capture, a later verifier can prove that the recorded digest was not changed;
it cannot independently recompute what the original bytes contained.

The transient SQLite queue stores the full sanitized text. Before evaluation,
the worker recomputes its digest and compares it with both the queue column and
the value signed by `EvidenceCaptured`. Successful outcome commit deletes the
row; a zero-candidate result appends `EvidenceEvaluationCompleted` in the same
transaction. Terminal `EvidenceEvaluationFailed` purges the text. This queue
check is an evaluation-time integrity control, not a long-term content-retention
claim.

## Event Hash Construction

The event body contains all schema-required envelope fields, including
`payload`, `payload_digest`, `previous_event_hash`, algorithm identifiers, and
`signing_key_id`. The producer then:

1. Validates and normalizes the complete event candidate.
2. Computes and inserts `payload_digest`.
3. Sets `previous_event_hash` to the prior verified event hash. Sequence 1 uses
   64 lowercase zeroes:

   ```text
   0000000000000000000000000000000000000000000000000000000000000000
   ```

4. Sets `canonicalization_algorithm`, `digest_algorithm`,
   `signature_algorithm`, and `signing_key_id`.
5. Creates the hash body by removing only `event_hash` and `signature`.
6. Serializes that body with `VC-CJ-1`.
7. Computes SHA-256 over those exact bytes.

```text
event_body  = event excluding fields {event_hash, signature}
event_bytes = VC-CJ-1(event_body)
event_hash  = lowercase_hex(SHA-256(event_bytes))
```

`event_hash` is exactly 64 lowercase hexadecimal characters with no prefix. The
hash body still includes `payload`, `payload_digest`, `previous_event_hash`,
`signing_key_id`, and both algorithm identifiers. Removing any of those fields
from the hash would weaken the claim and is prohibited without a new schema and
profile version.

## Signature Construction

Ed25519 signs the raw 32 digest bytes, not the 64 ASCII hexadecimal characters:

```text
message   = bytes_from_lowercase_hex(event_hash)  # exactly 32 bytes
signature = Ed25519.Sign(private_key, message)    # exactly 64 bytes
stored    = standard_base64_with_padding(signature)
```

The standard Base64 representation is 88 ASCII characters and ends with `==`.
URL-safe Base64, unpadded Base64, signature over the canonical event bytes, and
signature over the hex text are different formats and must be rejected for
this profile.

The private key is never part of an event, API response, log, fixture, or Git
object. The signature provides integrity and installation-key authenticity for
the recorded hash; it does not encrypt the event.

## Global Chain and Ordering

The SQLite ledger has one global sequence for the MVP:

- `sequence_number` starts at 1 and increases by exactly one.
- Event 1 uses the all-zero genesis `previous_event_hash`.
- Event N, for N greater than 1, stores event N-1's verified `event_hash`.
- Sequence allocation, event append, payload append, and derived-view update
  occur inside the protected transactional write boundary.
- Stream IDs group domain events but do not replace global sequence checks.

Global chaining detects reordering, insertion, and interior omission because at
least one expected sequence or previous-hash link no longer matches. It also
binds simultaneous event activity to one deterministic committed order.

## Verification Procedure

`verity ledger verify` must perform the following checks without repairing data
implicitly:

1. Open the ledger in a verification-safe mode and load the trusted or supplied
   public-key set and expected ledger head when available.
2. Parse every envelope with duplicate-key rejection and validate it against
   the selected schema. Reject unknown algorithms or schema versions.
3. Sort only by the stored global sequence for reading, then require contiguous
   sequence values beginning at 1. Database row order is not authoritative.
4. For event 1, require the all-zero genesis link. For each later event, require
   `previous_event_hash` to equal the immediately preceding event's verified
   hash.
5. Resolve every retained event payload and recompute each `payload_digest` with
   `VC-CJ-1` and SHA-256. Verify each evidence projection against its signed
   `EvidenceCaptured` payload and identity columns, including its bounded safe
   excerpt and metadata; recompute an evidence-content digest only when retained
   content actually exists.
6. Remove only `event_hash` and `signature`, canonicalize the remaining event
   body with `VC-CJ-1`, recompute SHA-256, and compare it to `event_hash`.
7. Resolve the public key named by `signing_key_id`, recompute the key ID from
   the raw key, decode the strictly padded standard Base64 signature, and run
   Ed25519 verification over the raw 32-byte event hash.
8. Confirm the final verified sequence and hash against the expected head or
   independently retained checkpoint when one is supplied.
9. Replay valid domain events into a fresh in-memory or temporary materialized
   view. Compare it with stored active, inventory, and quarantined views. Compare
   the active and historical policy projection with signed `PolicyActivated`
   events, and compare candidate, detector, semantic, and decision projections
   with their signed event payloads. Verify every terminal pending-evidence row
   against its exact signed capture and `EvidenceEvaluationFailed` events,
   including identity, error class, attempt count, failure time, purged-content
   state, and terminal-event link.
10. Return overall failure and the first attributable invalid sequence, event
    ID, check class, key ID, and safe reason. Never print raw payload content or
    key material.

Any failure disables Verity memory injection and new commits until an explicit
repair or recovery process succeeds and the entire verification passes.
On daemon restart, covered corruption produces an explicit read-only runtime:
content-safe status, policy, and audit reads remain available, the fallback
policy is labeled invalid and cannot authorize writes or injection, and detector
plugins are not loaded.

## What Omission Verification Can and Cannot Prove

An interior deletion is detectable from contiguous sequences and previous-hash
links. Deleting an event while leaving a materialized view derived from it is
also detectable through replay consistency. A terminal-suffix deletion is
detectable when the verifier has an independently retained expected head,
event count, or checkpoint.

A verifier given only a self-contained, consistently truncated ledger cannot
cryptographically distinguish that ledger from an older valid ledger. A
`LedgerCheckpointCreated` event inside the same ledger does not by itself solve
terminal truncation if the checkpoint can be deleted with the suffix. Public
key export is also not a head anchor.

For the hackathon, omission tests must cover interior deletion and terminal
deletion against the signed, restrictive `ledger-head.json` sidecar stored
outside the SQLite file. The sidecar records the expected sequence, hash, key
ID, and a signature over its canonical record and is replaced atomically after
each successful append. A caller may instead supply an exported signed
checkpoint. If neither anchor is available, the verifier returns
`tail_unproven` and does not report full verification. The
project must not claim complete deletion detection without an independent
freshness witness. External transparency anchoring, replicated witnesses,
monotonic hardware counters, and Merkle checkpoints are deferred.

The local sidecar proves completeness only relative to that retained anchor.
Coordinated rollback or deletion of both SQLite and the sidecar cannot be
distinguished from an older installation state without a separately retained
checkpoint or external freshness witness. Caller-supplied checkpoints have the
same relative-time limitation if the caller also rolls them back.

The head profile is exact: build an object containing `schema_version` =
`1.0.0`, non-negative `sequence_number`, lowercase-hex `event_hash`, and
`signing_key_id`; serialize it with `VC-CJ-1`; hash those bytes with SHA-256;
and sign the raw 32-byte digest with the same Ed25519 installation key. The
sidecar adds only the standard padded Base64 `signature`. An empty initialized
ledger uses sequence 0 and the 64-zero event hash. A head with an invalid
signature, key ID, sequence, or hash is not an anchor.

## Materialized-View Consistency

The active-memory view is not directly signed as an independent authority. It
is verified by deterministic replay of the signed event history:

1. Start with an empty view.
2. Apply eligible commit or approval events in global sequence.
3. Apply redaction, revocation, any schema-valid reserved supersession event,
   and explicit `MemoryExpired` events as defined by their versioned schemas.
   Replay never decides expiration from the verifier's current wall clock.
4. Exclude quarantined, blocked, invalid, expired, revoked, and superseded
   entries.
5. Compare canonical records and view metadata to the stored materialized
   tables.

A mismatch is an integrity failure even when every event signature is valid.
`verity memory rebuild` may create a replacement derived view transactionally,
but it never edits the historical events. Verification must run again after the
replacement and before injection resumes.

## Key Generation and Storage

- Generate one Ed25519 installation key with the operating system's secure
  random source.
- The current MVP stores the private key in a documented local file outside
  Git and the repository, with user-read/write-only permissions (`0600` on
  POSIX systems) in a user-only directory. Operating-system keychain support is
  deferred.
- Export only the raw public key or a standard public representation, key ID,
  fingerprint, algorithm, and creation metadata.
- Refuse new signed events if the private key is missing, unreadable, replaced,
  or has unsafe fallback-file permissions. Never silently generate a new key
  over an existing ledger.
- Verify that the selected private key derives the expected public key and ID
  before the first append of a process lifetime.
- Keep API keys, the local mutation capability, and the ledger-signing key as
  separate credentials with separate purposes.

Production rotation, recovery, enrollment, hardware-backed storage, and key
revocation are deferred. If a different key ever signs a later event, the
transition must be an explicit versioned key-rotation protocol with a trusted
link; accepting any key found in a row would be unsafe.

## Required Cryptographic Tests

| Test mutation | Required result |
|---|---|
| Change a payload value without updating its digest | Payload-digest failure at that event |
| Change an event field but retain the old event hash | Event-hash failure |
| Recompute the event hash without the private key | Signature failure |
| Reorder two events | Sequence or previous-link failure at the first affected event |
| Remove an interior event | Sequence or previous-link failure |
| Remove the final event while retaining expected-head/view state | Expected-head or view-consistency failure |
| Verify a truncated ledger without any independent expected head | Verifier reports that terminal completeness is unproven, not verified complete |
| Replace a signature with random bytes | Base64/length or Ed25519 verification failure |
| Verify with the wrong public key under the recorded ID | Key-ID or signature failure |
| Change `signing_key_id`, algorithm, or schema version | Event-hash, unsupported-profile, key-ID, or signature failure |
| Serialize an equivalent object with different whitespace or key order | Recanonicalization reproduces the original `VC-CJ-1` bytes and remains valid |
| Change Unicode code points through normalization | Payload or event digest failure |
| Insert a duplicate JSON key or non-finite number | Parse or schema failure before cryptographic acceptance |
| Modify the active view without changing events | Replay-consistency failure |
| Append concurrently | Unique contiguous sequences and a fully verifiable committed order |
| Force transaction rollback | No partial event, payload, or view state remains |

Tests must exercise actual stored bytes and the public verification path; mocks
that merely compare a precomputed string do not support the tamper-evidence
claim.

## Approved Cryptographic Claims

When the corresponding verification tests pass, Verity Cordon may say:

- The event ledger is append-only by application design and tamper-evident
  under an uncompromised installation key.
- Each event binds its exact canonical payload, previous event hash, algorithm
  identifiers, and signing key ID.
- The public key can verify Ed25519 signatures over recorded event hashes.
- Covered payload alteration, event alteration, reordering, interior omission,
  invalid signatures, and materialized-view drift are detected by the verified
  procedure.
- Revocation is a new signed event rather than a destructive historical edit.
  `MemorySuperseded` is a reserved contract event that replay can exclude, but
  the MVP exposes no supersession workflow.

## Prohibited or Unsupported Cryptographic Claims

Verity Cordon must not say that:

- The ledger is tamper-proof, immutable storage, or impossible to delete.
- A hash or signature proves a memory statement is factually correct, safe, or
  authorized by a human.
- Ed25519 provides confidentiality or protects raw evidence at rest.
- A signature proves trustworthy wall-clock time, legal non-repudiation, or
  operator identity.
- The system detects a consistently truncated tail without an independent
  expected head or freshness witness.
- The ledger withstands a compromised host, verifier, daemon, operator account,
  or signing key.
- The MVP provides production key rotation, HSM protection, distributed
  consensus, external transparency anchoring, or supply-chain attestation.
- Cryptographic integrity alone prevents prompt injection or memory poisoning.

These distinctions must remain consistent in the README, Control Room, demo,
submission copy, CLI output, and public verification instructions.
