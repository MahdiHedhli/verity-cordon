# Quickstart: Codex Memory Firewall

This guide is the acceptance path for the active feature. Commands are run from
the repository root. The offline path uses synthetic data and recorded semantic
fixtures; it never needs an OpenAI API key.

## Supported Judge Platforms

- macOS 14 or later on Apple Silicon or Intel
- Current Linux distributions on x86_64 or arm64
- Python 3.12 through 3.14
- Node.js 22 LTS is needed only to rebuild the Control Room; the committed
  production assets support the normal offline judge path without rebuilding it
- Windows is not claimed as verified for the hackathon build

## Fast Offline Path

```bash
./scripts/bootstrap.sh
./scripts/demo-offline.sh
```

The demo prints a loopback URL, normally `http://127.0.0.1:8765`. It initializes
an isolated data directory, verifies its signing key and empty ledger, seeds one
legitimate fact plus the synthetic poisoned-documentation scenario, and starts
the real daemon and Control Room.

Expected overview state:

- Semantic provider: `Recorded fixture`
- Ledger: `Verified`
- One legitimate active memory
- One synthetic persistent instruction with explicit policy outcome
- No real environment values, credentials, or external network calls

Stop the demo with `Ctrl-C`. Its isolated data is disposable and ignored by Git.

## Demonstrate Shadow Mode

```bash
uv run verity demo offline --scenario poisoned-docs --mode shadow --no-serve
uv run verity memory list --all
```

Expected result:

- `actual_action`: `allow`
- `would_have_action`: `quarantine`
- `shadow_mode`: `true`
- The synthetic malicious operational instruction is active but labeled
  `shadow_admitted`.
- No exfiltration or external tool call occurs.

Render the exact approved-memory payload that a supported `SessionStart` hook
would receive:

```bash
uv run verity codex-hook session-start --simulate
```

The output is JSON with a delimited developer-context block. This step is a
deterministic harness over the same adapter contract used by the real hook.

## Demonstrate Enforcement

```bash
uv run verity demo offline --scenario poisoned-docs --mode enforce --reset --no-serve
uv run verity memory list --all
uv run verity codex-hook session-start --simulate
```

Expected result:

- The legitimate project fact is active.
- The persistent operational instruction is quarantined.
- The injection payload contains the legitimate fact and excludes the poisoned
  instruction.

## Revoke and Replay

List shadow-admitted memory and copy the synthetic malicious memory ID:

```bash
uv run verity memory list --status active --shadow-admitted
uv run verity memory revoke <MEMORY_ID> --reason "New policy identifies persistent tool instruction"
uv run verity memory rebuild
uv run verity ledger verify
```

Expected result:

- A new `MemoryRevoked` event exists.
- The target memory is absent from the active view.
- The unrelated legitimate memory remains.
- Rebuilt and stored views match.
- The ledger verifies.

The Control Room exposes the same flow with a preview and confirmation step.

## Inspect Decisions and Ledger

```bash
uv run verity status
uv run verity memory list --all
uv run verity policy show
uv run verity ledger verify
uv run verity ledger export-public-key --output .verity-demo/public-key.json
```

Routine output contains safe statements, IDs, digests, actions, versions, and
failure classes. It does not print private keys, bearer capabilities, raw
credentials, or retained evidence.

## Live GPT-5.6 Path

Copy placeholders only and set the real key in your local shell or untracked
`.env` file:

```bash
cp .env.example .env
```

Set `OPENAI_API_KEY` locally without echoing it, then run:

```bash
./scripts/demo-live.sh
```

Live mode uses the configured `gpt-5.6` alias through the Responses API. It
records the requested alias, returned model, prompt version, schema version, and
provider state. Obvious secrets are redacted before the request. Responses use
structured Pydantic output, `store=False`, no tools, no durable model memory,
bounded input, a short timeout, and one retry.

If the key or API is unavailable, live mode reports a live-provider failure and
applies policy fallback. It never silently replaces the live provider with a
fixture.

## Codex Integration

Inspect planned changes without modifying user configuration:

```bash
uv run verity install-codex --dry-run
```

Install the project plugin and controlled memory configuration:

```bash
uv run verity install-codex
uv run verity doctor
```

The installer:

1. Creates a timestamped backup before any user-level configuration mutation.
2. Disables native local memory generation and use for the controlled plane.
3. Enables hooks and installs the Verity plugin/hook definitions.
4. Never edits Codex-generated memory files as its primary control mechanism.
5. Requires the operator to inspect and trust the hook definition in Codex.

Start a new Codex session after reviewing hooks. Use `verity doctor` to verify
effective memory flags, plugin state, daemon reachability, policy, key,
capability-file permissions, ledger, and Control Room assets.

Remove only Verity-managed integration entries with:

```bash
uv run verity uninstall-codex
```

The uninstaller does not delete the event ledger, signing key, or unrelated
Codex configuration.

## Policy Validation

```bash
uv run verity policy validate src/verity_cordon/policies/default.yaml
uv run verity policy show
uv run verity policy activate src/verity_cordon/policies/default.yaml
```

Activation appends `PolicyActivated`. Invalid policy leaves the last-known-good
policy untouched and blocks new commits when no valid policy is available.

## Transactional Stream Acceptance

```bash
uv run pytest -q tests/adversarial/test_streaming.py
```

The suite proves uncommitted invisibility, split-chunk detection, complete final
scan, no partial commit after block/abort/cancellation, resource limits,
double-commit rejection, and concurrent stream isolation.

## Critical Verification

```bash
./scripts/verify.sh
```

The script runs formatting checks, lint, static types, backend tests, security
and contract tests, evaluation fixtures, frontend type/lint/tests/build, and the
offline end-to-end path. The exact commands and results are also recorded in
the final handoff; no unexecuted gate is described as passing.

## Clean-Checkout Acceptance

To validate without disturbing the primary workspace:

```bash
git clone <PUBLIC_REPOSITORY_URL> verity-cordon-judge
cd verity-cordon-judge
./scripts/bootstrap.sh
./scripts/demo-offline.sh
```

Replace the placeholder with the final public URL after publication. The
repository remains the testing source of truth; the final demo video and real
`/feedback` Session ID are operator submission actions.
