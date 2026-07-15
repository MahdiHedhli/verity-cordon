# Security Policy

Verity Cordon is a hackathon-stage local security tool, not an enterprise or
host-compromise boundary. The demonstrated scope and residual risks are defined
in [the threat model](docs/security/threat-model.md).

## Supported Versions

During development, only the current verified feature commit is supported. Once
published, only the latest commit on the public default branch is supported for
OpenAI Build Week judging. The exercised local platform is macOS with Python
3.12 or newer. The source build requires Node.js `^20.19.0` or `>=22.13.0`.
Linux is an intended local target but is not yet recorded as exercised; Windows
remains unverified.

## Reporting a Vulnerability

Do not open a public issue containing exploit details, credentials, raw memory,
or private evidence. Use GitHub's private vulnerability-reporting feature once
enabled on the public repository. Until then, contact the repository owner
privately through the profile linked from the repository.

Include a minimal synthetic reproduction, affected commit, expected behavior,
and observed behavior. Never include real tokens or secrets.

## Local Security Boundary

- The daemon binds to `127.0.0.1` by default.
- Signing keys, browser passphrases, mutation capabilities, databases, and demo
  runtime state remain outside Git with user-only permissions.
- Configured data directories and the SQLite database leaf reject symbolic
  links, unexpected file types or owners, and unsafe database permissions.
- All local API responses are marked `no-store`/`no-cache`; this supplements,
  but does not replace, content-safe response design.
- The original submitted evidence bytes are not retained by the MVP. A signed
  `EvidenceCaptured` record permanently keeps a pattern-sanitized, bounded
  `safe_excerpt` plus the raw-content digest. Full sanitized queue text is
  transient and purged after success or terminal failure.
- Live semantic calls send only bounded, locally sanitized content with
  `store=False`; this is not a Zero Data Retention claim.
- A missing key, invalid policy without a last-known-good replacement, invalid
  ledger, stale view, or due expiry that cannot be signed disables injection.
- Ledger or signed-projection corruption detected at startup leaves the daemon
  in an explicit read-only state: content-safe status, policy, and audit reads
  remain available, policy validation is shown as invalid, trust-changing
  writes fail, `SessionStart` returns no context, and detector plugins are not
  loaded.
- A signed terminal queue-integrity failure purges the queued body and remains
  fail-closed after restart until the operator repairs the local state.
- Source labels and operator-provided stream-abort reasons are pattern-sanitized
  before signed persistence; URL-like source labels are reduced to a host label
  with query and fragment data removed.
- Root, OS, user-account, signing-key, malicious-Codex, and hardware compromise
  are outside the MVP threat model.

Pattern-based sanitization is not exhaustive. Undetected sensitive text may
remain in a signed excerpt or cross to the configured semantic provider. Treat
the local data directory and backups as sensitive even when a record says
`digest_only`; that state means the raw original is absent, not that no excerpt
exists.

See [cryptographic claims](docs/security/cryptographic-claims.md) before making
or evaluating any integrity claim.
