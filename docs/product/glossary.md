# Glossary

**Active memory**: An eligible, committed memory in the current materialized
view. It has not been blocked, quarantined, revoked, superseded, or expired.

**Actual action**: The action applied to a candidate. In enforce mode it equals
the computed enforcement action. In shadow mode it is the configured shadow
action.

**Candidate memory**: Atomic, typed content proposed for durable reuse. It is
untrusted until the full lifecycle produces an eligible decision.

**Controlled memory plane**: The documented Codex-hook-based capture and
session-start injection path owned by Verity Cordon. It is not an interception
of undocumented Codex memory internals.

**Codex Desktop**: Project shorthand for the Codex experience in the supported
ChatGPT desktop app. It is a presentation surface, not a separate Verity
runtime or an undocumented integration boundary.

**Evidence**: Source observation and provenance from which candidates are
derived. The MVP does not retain the original submitted bytes; it permanently
binds their digest and a bounded pattern-sanitized excerpt, while full sanitized
queue text is transient. Routine operator surfaces use content-safe
representations and digests. Pattern sanitization is not exhaustive.

**Event ledger**: The append-only, ordered, payload-bound, signed security event
history from which active and quarantine views can be reconstructed.

**Fixture semantic provider**: A deterministic offline implementation that
returns recorded schema-valid extraction or risk results. It is labeled as a
fixture and never silently substitutes for live mode.

**Memory poisoning**: Untrusted content becoming durable context in a way that
can influence later agent work beyond the originating task.

**Policy authority**: The deterministic, versioned policy engine that makes the
final action decision. Semantic models provide evidence, not authority.

**Provenance**: Attributable origin and processing history. Provenance does not
establish factual truth.

**Quarantine**: An ineligible review state. Quarantined content is retained in
the audit view but never supplied as active memory unless a later approval event
and policy allow it.

**Revocation**: A new event that removes one earlier committed memory from the
active view without deleting its history or unrelated memories.

**Shadow mode**: An evaluation mode that records what enforcement would have
done while applying a configured shadow action. It is not active protection.

**Tamper-evident**: Alteration, omission, reordering, payload drift, or invalid
signature can be detected by verification under the stated key and host threat
boundary. It does not mean tamper-proof.

**Transactional stream**: A begin/append/commit/abort memory-write lifecycle in
which buffered chunks remain invisible until complete final evaluation.

**Would-have action**: The deterministic enforcement result recorded in both
enforce and shadow modes.
