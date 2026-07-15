# Security Policy

Verity Cordon is a hackathon-stage local security tool, not an enterprise or
host-compromise boundary. The demonstrated scope and residual risks are defined
in [the threat model](docs/security/threat-model.md).

## Supported Versions

Only the latest commit on the public default branch is supported during OpenAI
Build Week judging. The verified local targets are macOS and Linux with Python
3.12 or newer and Node.js 22 LTS. Windows remains unverified until explicitly
tested.

## Reporting a Vulnerability

Do not open a public issue containing exploit details, credentials, raw memory,
or private evidence. Use GitHub's private vulnerability-reporting feature once
enabled on the public repository. Until then, contact the repository owner
privately through the profile linked from the repository.

Include a minimal synthetic reproduction, affected commit, expected behavior,
and observed behavior. Never include real tokens or secrets.

## Local Security Boundary

- The daemon binds to `127.0.0.1` by default.
- Signing keys, browser passphrases, mutation capabilities, databases, and raw
  evidence remain outside Git with user-only permissions.
- Live semantic calls send only bounded, locally sanitized content with
  `store=False`; this is not a Zero Data Retention claim.
- A missing key, invalid policy without a last-known-good replacement, invalid
  ledger, stale view, or due expiry that cannot be signed disables injection.
- Root, OS, user-account, signing-key, malicious-Codex, and hardware compromise
  are outside the MVP threat model.

See [cryptographic claims](docs/security/cryptographic-claims.md) before making
or evaluating any integrity claim.

