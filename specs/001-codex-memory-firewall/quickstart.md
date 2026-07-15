# Quickstart: Codex Memory Firewall

This is the acceptance path for `001-codex-memory-firewall`. Run commands from
the repository root. The supported judge distribution is a source checkout;
`bootstrap.sh` builds the Control Room assets because `apps/control-room/dist/`
is not committed.

## Platform Status

- Python 3.12 or newer
- `uv`
- Node.js `^20.19.0` or `>=22.13.0` with npm
- macOS is the locally exercised platform
- Linux is an intended local target but is not yet recorded as exercised
- Windows is not claimed as verified

## Bootstrap

```bash
./scripts/bootstrap.sh
```

Bootstrap performs a frozen Python dependency sync, checks that the installed
package and `verity` entry point work without `PYTHONPATH`, installs the locked
frontend dependencies, and builds the frontend. It creates no signing key,
database, passphrase, or capability.

## Offline Demonstration

```bash
export VERITY_DATA_DIR=.verity-demo
./scripts/demo-offline.sh
```

Create a local Control Room passphrase of at least 12 characters when prompted.
The passphrase is not echoed or printed. The default script run resets only the
ignored `.verity-demo` directory, executes the full synthetic sequence, and
serves the Control Room at `http://127.0.0.1:8765`.

Offline mode requires no OpenAI API key. It uses:

- the recorded fixture candidate extractor and semantic adjudicator;
- the real deterministic detector and policy pipeline;
- the real SQLite event ledger, SHA-256 chain, Ed25519 signatures, and expected
  head;
- the real active/quarantine views, revocation, and rebuild logic;
- the real daemon API and built Control Room.

The sequence is deterministic:

1. Activate shadow policy.
2. Submit a synthetic poisoned-document response.
3. Record `actual_action=allow` and `would_have_action=quarantine` for its
   persistent operational instruction.
4. Activate enforcement policy and evaluate the same synthetic response.
5. Quarantine the enforcement-mode poisoned candidate.
6. Rescan the earlier shadow-admitted memory under the current enforcement
   policy and atomically revoke it when that decision is unsafe.
7. Rebuild the active view and preserve unrelated legitimate memory.
8. Render a simulated `SessionStart` through the real memory service and assert
   that approved memory is present while the poisoned instruction is absent.
9. Verify the ledger and materialized view.

For stage reliability, the command launches only the reviewed fixture at
`examples/poisoned-docs-mcp/` under a minimal environment, exchanges bounded
MCP-style JSON-RPC over stdio, validates its identity and inert safety flag, and
then sends the returned synthetic response directly into the core memory
service. It does not launch Codex or require MCP client configuration.

Inspect the demo state from another terminal:

```bash
export VERITY_DATA_DIR=.verity-demo
uv run verity status
uv run verity memory list
uv run verity policy show
uv run verity ledger verify
```

Run without serving the UI:

```bash
VERITY_DEMO_NO_SERVE=1 ./scripts/demo-offline.sh
```

## Inspect, Revoke, and Rebuild

The CLI intentionally provides no undocumented filter or reset flags. List all
content-safe inventory records, then inspect a selected identifier:

```bash
export VERITY_DATA_DIR=.verity-demo
uv run verity memory list
uv run verity memory show <MEMORY_ID>
```

Append a reasoned revocation and replay the view:

```bash
uv run verity memory revoke <MEMORY_ID> \
  --reason "Confirmed synthetic demo finding" \
  --yes
uv run verity memory rebuild --dry-run
uv run verity memory rebuild
uv run verity ledger verify
```

`--dry-run` compares replay with stored projections without replacing them. A
normal rebuild replaces derived projections and then verifies them. Revocation
does not delete historical events.

Export only public verification material when needed:

```bash
uv run verity ledger export-public-key \
  --output .verity-demo/public-key.json
```

Routine CLI output contains content-safe representations, identifiers, digests,
actions, and error classes. It does not print private keys, OpenAI keys, browser
passphrases, or mutation capabilities.

To re-evaluate one active memory with the current sanitizer, detector bundle,
semantic provider when required, and active policy, use the confirmed targeted
rescan path:

```bash
uv run verity memory rescan <MEMORY_ID> \
  --reason "Evaluate this memory under the current enforcement policy" \
  --yes
```

The rescan records a new actual and would-have policy decision. Under an
enforcement policy, if the actual action is redact, quarantine, or block, the
same transaction appends a `MemoryRevoked` event and removes only that memory
from the active view. It is a one-memory operation, not an automatic
policy-wide sweep.

## Policy Commands

```bash
uv run verity policy validate \
  src/verity_cordon/policies/default-enforce.yaml
uv run verity policy show
uv run verity policy activate \
  src/verity_cordon/policies/default-shadow.yaml \
  --reason "Synthetic shadow evaluation" \
  --yes
```

Activation requires `--yes` and appends `PolicyActivated`. Invalid activation
does not replace an intact last-known-good policy. If no valid policy is
available, commits and injection fail closed.

## Live GPT-5.6 Path

Set `OPENAI_API_KEY` in the local shell or another untracked secret source
without printing it. Do not commit a populated `.env`.

```bash
export VERITY_DATA_DIR=.verity-live-demo
./scripts/demo-live.sh
```

Live mode is implemented to use the configured `gpt-5.6` alias through the
official async Responses API with Pydantic structured output, `store=False`, no
tools, no prior response, bounded input, a strict timeout, and one bounded
retry. It records requested and returned model identifiers and never silently
falls back to fixtures.

Deterministic secret screening precedes the request, but pattern-based
sanitization is not exhaustive. `store=False` is not a Zero Data Retention
claim. The repository does not yet record a successful credentialed live API
run, so fixture results must not be described as live GPT-5.6 results.

## Codex Integration

Preview the exact changes. A preview intentionally exits with status 2 so it
cannot be confused with an applied installation:

```bash
uv run verity install-codex
```

After reviewing the preview and hook definition:

```bash
uv run verity install-codex --yes
uv run verity doctor --confirm-hook-trust
```

The installer creates a backup, registers a private local plugin marketplace,
installs Verity's reviewed command hooks, enables hooks, and disables native
Codex local-memory generation and use. It does not edit Codex-generated memory
files.

The thin adapter forwards selected `UserPromptSubmit`, `PostToolUse`,
`PreCompact`, `PostCompact`, and `Stop` fields under a strict deadline. The
daemon returns `202 Accepted` after a signed `EvidenceCaptured` event and
bounded sanitized queue row are durably committed; model evaluation occurs in
the daemon background, not the hook process. `SessionStart` injects only a
healthy, verified, typed, delimited active view. Failure yields no Verity memory
rather than raw fallback.

The installer and hook contract were exercised with Codex CLI 0.144.4 against
an isolated temporary configuration. Hook coverage remains limited to
documented surfaces.

Preview and then apply removal:

```bash
uv run verity uninstall-codex
uv run verity uninstall-codex --yes
```

The uninstaller preserves the Verity ledger, signing key, and unrelated Codex
configuration.

## Transactional Streaming Acceptance

```bash
uv run pytest -q tests/adversarial/test_streaming.py
```

This suite covers uncommitted invisibility, split-chunk detection, complete
final scanning, block/abort/cancellation safety, resource limits, terminal-state
enforcement, no partial commit, and concurrent stream isolation.

## Verification

```bash
./scripts/verify.sh
```

The script is configured to check the installed CLI without `PYTHONPATH`, audit
Python and npm dependencies, check formatting/lint/types, validate OpenAPI, run
backend and example tests with coverage, run frontend type/lint/component tests
and a production build, and check the saved evaluation report.

Desktop browser behavior, keyboard/focus accessibility, and console errors are
verified separately with a manual browser smoke; `verify.sh` does not claim an
automated axe-core gate.

The saved fixture report covers 14 original synthetic samples: 5/5 benign
allowed and 9/9 risky protected, with 0 false positives and 0 false negatives
for that fixture only. Its 226-event ledger verified with a consistent
materialized view. See `evals/results/latest.md`; these are not universal or
live-model accuracy claims.

## Clean-Checkout Acceptance

This publication gate remains pending until the final public URL and commit are
available:

```bash
git clone <PUBLIC_REPOSITORY_URL> verity-cordon-judge
cd verity-cordon-judge
./scripts/bootstrap.sh
export VERITY_DATA_DIR=.verity-demo
./scripts/demo-offline.sh
```

The public YouTube video, Devpost submission, and real `/feedback` Session ID
remain operator actions and are not represented as complete here.
