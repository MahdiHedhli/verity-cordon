# Codex Desktop Rehearsal Record

Use this blank record for the timed, operator-observed acceptance rehearsal.
Here, **Codex Desktop** means the Codex experience in the supported ChatGPT
desktop app. Do not mark an item observed unless a person saw it on the stated
surface. Keep automated state separate from manual app evidence.

Never paste raw authentication output, full Codex configuration, private
absolute paths, hook capabilities, Control Room passphrases, signing keys, raw
retained evidence, child-process output, real manifests, environment values, or
credentials into this file.

## Run Identity

- Observed at (UTC): `REPLACE`
- Observed at (local time and zone): `REPLACE`
- Branch: `codex/002-desktop-subscription-defense`
- Commit: `REPLACE_WITH_EXACT_COMMIT`
- Host platform: `macOS REPLACE / arm64` (do not record hostname)
- ChatGPT desktop app version/build: `REPLACE`
- App signature verification: `PASS/FAIL` (automated, content-safe)
- Codex CLI version: `REPLACE`
- ChatGPT subscription auth ready: `true/false` (automated boolean only)
- Verity data run label: `REPLACE_WITH_NON_PRIVATE_LABEL`

## Preflight and Trust

- [ ] Automated normal-install preview exited `2`, reported only the reviewed
      Boolean deltas, and reported `issues=[]`.
- [ ] Manual: all ChatGPT Desktop tasks, Codex CLI TUI sessions, and IDE Codex
      sessions were closed before each user-wide mutation.
- [ ] Manual: CLI `/hooks` showed the exact Verity command hook definitions and
      their current hashes were trusted.
- [ ] Automated: after the daemon started, `verity doctor
      --confirm-hook-trust` passed using the post-`/hooks` assertion.
- Demo setup preview digest prefix: `REPLACE_WITH_SAFE_PREFIX`
- [ ] Automated: digest-confirmed setup succeeded and the receipt was healthy.
- [ ] Manual: after restart, Desktop `/mcp` showed the expected
      `verity_cordon_poisoned_docs` demo server with exactly its two synthetic
      tools; unrelated operator-managed servers were not used.
- Hook canary terminal event ID: `REPLACE`
- [ ] Manual + automated: the benign Desktop canary produced a signed terminal
      event while ledger and materialized-view status were healthy.

## Provider and Policy

- Requested provider: `REPLACE`
- Requested model identifier: `REPLACE`
- Observed provider state: `REPLACE`
- Returned model from verified runtime metadata: `REPLACE_OR_NULL`
- Isolation label: `REPLACE`
- Failure class, if any: `REPLACE_OR_NONE`
- Assessment latency in milliseconds: `REPLACE`
- Active policy ID/version/digest prefix/mode: `REPLACE`

Do not label a fixture-backed or failed result as live. Do not imply live
candidate extraction if only live semantic risk assessment was observed.

## Timed Manual Sequence

- Timer start: `REPLACE`
- [ ] Shadow: Desktop planted the synthetic delayed instruction from the local
      documentation tool.
- Shadow candidate/memory/event IDs: `REPLACE`
- [ ] Control Room showed `actual_action=allow`,
      `would_have_action=quarantine|block`, and `shadow_mode=true`.
- [ ] Delayed task showed only a proposed call using the two fixed synthetic
      markers; no real data or network effect occurred.
- [ ] Enforcement: the same tool evidence reached a signed terminal quarantine
      or block decision.
- Enforcement terminal event ID/action: `REPLACE`
- [ ] Fresh Desktop task received eligible typed memory and the poisoned
      operational instruction was absent.
- [ ] Revocation appended `MemoryRevoked` for only the earlier shadow-admitted
      memory and preserved unrelated approved memory.
- Revoked memory ID / revocation event ID: `REPLACE`
- [ ] Rebuild dry-run passed.
- [ ] Rebuild apply passed.
- [ ] Ledger verification passed with anchored completeness and a consistent
      materialized view.
- Verified event count / key ID: `REPLACE`
- Timer stop: `REPLACE`
- Full rehearsal wall time: `REPLACE`
- Edited video runtime: `REPLACE` (must be under `3:00`; target `2:55`)

## Teardown

- Teardown preview digest prefix: `REPLACE_WITH_SAFE_PREFIX`
- [ ] Automated: digest-confirmed teardown removed only receipt-bound demo
      state and preserved the normal Verity plugin, ledger, key, policies, and
      unrelated Codex configuration.
- [ ] Automated: the reserved demo MCP name is absent from configuration.
- [ ] Manual: after restart, Desktop `/mcp` no longer lists
      `verity_cordon_poisoned_docs`.

## Result

- T056 acceptance result: `PASS/FAIL`
- Deviations or content-safe failure class: `REPLACE_OR_NONE`
- Fallback label, if used: `live_codex_subscription / recorded_fixture / deterministic_only / failed_semantic`
- Operator initials: `REPLACE`
