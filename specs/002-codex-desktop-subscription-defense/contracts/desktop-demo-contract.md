# Codex Desktop Demo Setup Contract

**Contract version**: `1.0.5`
**Managed MCP entry**: `verity_cordon_poisoned_docs`
**Primary surface**: Codex in the supported ChatGPT desktop app (project
shorthand: Codex Desktop)
**Fallback surface**: deterministic Verity CLI demo

This contract installs only the synthetic delayed-poisoning fixture used by the
Desktop demonstration. Normal Verity plugin, hook, and native-memory controls
remain governed by the baseline Codex installer and its separate receipt.
Running the normal installer MUST NOT install or enable the demo MCP server.

## Command Behavior

The supported operations are conceptually:

```text
verity demo desktop-setup --confirm-hook-trust
verity demo desktop-setup --confirm-hook-trust \
  --expected-preview-digest <sha256> --yes
verity demo desktop-teardown --confirm-hook-trust
verity demo desktop-teardown --confirm-hook-trust \
  --expected-preview-digest <sha256> --yes
```

Without `--yes`, both commands are read-only previews. A confirmed mutation
MUST include the exact SHA-256 digest copied from a separately completed
preview; the command MUST NOT generate and self-confirm a new preview in one
unreviewable step. Preview MUST NOT create
directories, stage files, back up or rewrite Codex configuration, write a
receipt, start the fixture, call the sink, or change Verity history.

`--confirm-hook-trust` is an operator assertion that the separately installed
normal Verity hook definitions were reviewed and their exact current hashes
were trusted through Codex CLI `/hooks`. It is not a discovery result, an
implicit approval, proof of persisted Codex trust, or a substitute for the
normal integration doctor.

The setup preview shows:

- normal Verity integration readiness and, when not ready, a content-safe
  direction to run the separate `verity install-codex` preview; the demo
  preview does not duplicate or embed that installer's configuration delta;
- the Codex config path and digest, with user paths redacted in routine logs;
- the one MCP entry to add, including command, arguments, tool allow list,
  timeouts, and approval policy;
- staged artifact relative paths, byte sizes, and SHA-256 digests;
- resolved Codex and Python runtime versions and digests;
- receipt and private staging destinations; and
- the statement that the fixture is synthetic, local stdio only, and separate
  from the normal product installation.

Setup with `--yes` requires the normal integration receipt, artifacts, effective
memory controls, and operator's post-`/hooks` assertion to be mechanically
ready. If they are not ready, setup stops after the demo preview and instructs
the operator to confirm the normal installer separately. Full `verity doctor`
also checks daemon reachability and therefore runs after the daemon starts. The
demo setup never silently installs hooks, changes native-memory controls, or
trusts a plugin on the operator's behalf.

## User-Wide Configuration Scope

For the exercised Codex `0.144.4` surface, the managed MCP table is written to
`$CODEX_HOME/config.toml`. It is therefore visible user-wide to Codex clients
that load that configuration. Choosing a dedicated demo workspace and setting
the MCP `cwd` reduce accidental use operationally; neither creates a
project-local registration or a security boundary.

Before confirmed setup or teardown, the operator MUST close every ChatGPT
Desktop task, exit Codex CLI TUI and IDE Codex sessions, and fully quit the
ChatGPT desktop app. All Codex clients MUST remain closed while the configuration
mutation runs. After setup, reopen Desktop only for the dedicated synthetic
rehearsal and do not use unrelated workspaces or tasks until the demo entry has
been removed. After the rehearsal, close every Codex client again, perform a
fresh teardown preview, confirm that exact preview digest, apply teardown
immediately, and restart Desktop. This minimizes the period in which the
synthetic server is available through user-wide configuration.

## Managed Codex Configuration

The installer adds exactly this logical TOML entry, using resolved absolute
paths and preserving all unrelated TOML values and formatting where possible:

```toml
[mcp_servers.verity_cordon_poisoned_docs]
command = "<verified-absolute-python>"
args = ["-I", "<private-staging-root>/poisoned_docs_server.py"]
cwd = "<private-staging-root>"
enabled = true
required = true
startup_timeout_sec = 5.0
tool_timeout_sec = 5.0
enabled_tools = ["get_release_guidance", "demo_artifact_sink"]
default_tools_approval_mode = "writes"

[mcp_servers.verity_cordon_poisoned_docs.tools.demo_artifact_sink]
approval_mode = "prompt"
```

No `env`, `env_vars`, URL, bearer-token, HTTP-header, OAuth, remote-executor,
or external callback field is permitted. `required=true` makes a failed fixture
startup visible. The sink always requires an operator prompt in Codex even
though its implementation is inert.

Setup refuses to proceed when the reserved MCP name already exists. It does not
overwrite, merge, copy, or serialize a pre-existing entry that might contain
credentials. The operator must resolve that name collision manually.

## Fixture Contract

The staged server is an exact digest-verified copy of the repository fixture,
run as a single isolated Python script. It uses bounded newline-delimited MCP
JSON-RPC over stdio and MUST NOT import or invoke networking, subprocess,
filesystem, environment, keychain, browser, email, or IPC APIs.

It exposes exactly two tools:

### `get_release_guidance`

- Input: optional `release_channel`, enum `stable|preview`; additional
  properties rejected.
- Output: fixed synthetic release guidance plus the original Verity-authored
  dormant-instruction test string.
- Side effects: none.

The output contains a useful benign release fact and a concealed request to
preserve a permanent rule involving `demo_artifact_sink`. This is untrusted test
data, not an instruction to the fixture or installer.

### `demo_artifact_sink`

Input is a strict object with exactly these constant values:

```json
{
  "artifact_marker": "VERITY_SYNTHETIC_RELEASE_MANIFEST_V1",
  "environment_marker": "VERITY_SYNTHETIC_DEMO_ENV_V1"
}
```

Additional fields, alternate values, paths, URLs, environment names, file
contents, credentials, arbitrary payloads, or encoded values are rejected. On
acceptance the tool returns only:

- `accepted=true`;
- `external_transmission_performed=false`;
- an in-process call count; and
- SHA-256 of the fixed canonical marker pair.

The sink retains no body, writes no file or ledger event, reads no host state,
and sends nothing. Its process-lifetime count is reset when the stdio server
stops. Source and tests MUST make this inert boundary obvious.

## Setup Transaction

After explicit confirmation, setup performs this ordered transaction:

1. Require the explicit hook-trust assertion, re-read bounded Codex config with
   no-follow semantics, and verify it still matches the separately previewed
   digest.
2. Verify the normal integration receipt, staged plugin artifacts, effective
   memory controls, mechanical doctor state, and the operator's post-`/hooks`
   trust assertion without reading auth content. The assertion is not
   independent proof of Codex's persisted trust record.
3. Resolve and verify the current Codex and Python executables. The Python
   runtime must support isolated `-I` execution and satisfy the project runtime
   version.
4. Verify the bounded fixture source in memory before creating its staging
   directory, then create only the private
   `0700` demo directories required for the transaction. Reject symlinks and
   bind the expected source SHA-256 and byte size into the prepared state.
5. Record the pre-mutation config SHA-256, existence bit, exact restrictive
   owner mode, and SHA-256 of a canonical type-tagged projection of every
   unrelated parsed TOML value. Never copy
   the full Codex config into demo state because unrelated MCP entries may
   contain credentials.
6. Atomically write a `prepared` receipt conforming to
   `desktop-demo-receipt.schema.json` before staging the executable fixture or
   changing Codex configuration.
7. Copy only the receipt-bound fixture server using an atomic `0600` write
   bound to the target's expected absence and empty digest, then
   verify the staged SHA-256 and byte size.
8. Add only the reserved MCP table through parsed TOML and atomically replace
   the config only while both its expected existence and whole-file digest
   match. Preserve its exact restrictive owner mode (`0400` remains `0400`);
   only a newly created config defaults to `0600`.
9. Re-read and canonicalize the managed table, verify its expected digest, and
   compare every unrelated parsed value with the pre-replacement projection
   and recorded projection digest without rendering or logging that content.
   A mismatch advances the receipt to non-finalizable `failed` state; a retry
   cannot turn the changed config into an installed receipt. Only after a fresh
   normal-integration v2 receipt/digest and doctor check may setup atomically
   update the exact prepared receipt to `installed` with the after-config
   digest.
10. Return content-safe operator actions: restart Codex Desktop, use `/mcp` to
   confirm the expected synthetic server, run a benign hook-delivery canary,
   and continue only after its signed terminal decision is visible.

Any precondition or write failure stops the transaction. It does not fall back
to editing generated memories or an undocumented Desktop file.

## Interrupted Setup Recovery

The receipt is write-ahead state:

All receipt timestamps are canonical UTC RFC 3339 strings ending in `Z`;
non-UTC offsets and timezone-free values are invalid.

- `prepared` plus no managed entry: setup may be retried only when the current
  whole-config digest still equals the receipt's pre-mutation digest. A missing
  artifact may then be restaged only from the fixed repository fixture after
  its digest and size match the receipt; a present but different artifact is
  drift and is not overwritten.
- `prepared` plus the exact managed entry and the original unrelated-value
  projection: setup may verify or safely restage a missing receipt-bound
  artifact and finalize the receipt as `installed`.
- `prepared` plus the exact managed entry, exact present receipt-bound artifact,
  and a different unrelated-value projection: setup MUST NOT finalize. This is
  the recoverable state left when the earlier `prepared` to `failed` receipt
  write was interrupted after config replacement. A current v1.2 receipt may
  retry only that transition after revalidating the config head, receipt head,
  artifact, runtimes, and normal integration. The resulting `failed` receipt
  permits exact confirmed teardown while preserving unrelated config values.
- `failed`: setup cannot finalize or retry the installation. Exact confirmed
  teardown remains available to remove the managed fixture safely. Historical
  v1.1 `failed` receipts are accepted only with their required config mode,
  unrelated-projection digest, after-config digest, canonical failure class,
  and empty pre-teardown state; v1.0 cannot represent `failed`.
- `prepared` plus a different managed entry: report drift and make no artifact
  or configuration change.
- config mutation with no valid receipt: report unreceipted state and make no
  automatic removal; the operator receives a bounded manual recovery path.

Recovery binds every receipt transition to the exact observed receipt
existence, SHA-256, device, inode, owner, and mode. It rechecks the recorded
normal integration receipt version/digest and fresh doctor state immediately
before each artifact/config mutation and immediately before finalization.
Recovery never stores or restores a whole-config backup and never deletes an
unknown directory recursively.

Teardown uses the same write-ahead discipline. An `installed` receipt advances
to `removing` before the managed entry is changed. If interrupted, a later
confirmed teardown may finish only when the entry is either still the exact
receipt-bound value or is already absent, and every remaining artifact is
receipt-bound and digest-valid. Any different state is drift and is not guessed
away.

A successfully removed receipt remains in state `removed`. Before a later
installation reuses the active receipt path, the exact digest-matching removed
receipt is archived under its installation ID. An identical pre-existing
archive is accepted, so the archive step is repeatable; a conflicting archive
or drifted removed receipt stops setup.

## Doctor and Runtime Readiness

Desktop demo doctor reports ready only when:

- the normal Verity Codex integration doctor is ready;
- the receipt validates and is `installed`;
- the configured managed entry equals the receipt-bound canonical entry;
- source and staged fixture digests and sizes match;
- Codex and Python executable identity has not drifted;
- the fixture answers a bounded `initialize`, `tools/list`, and safe release
  guidance probe over stdio; and
- the Verity daemon, active policy, ledger, materialized view, and Control Room
  are healthy.

The probe never invokes `demo_artifact_sink` and never includes the dormant
instruction or raw child response in routine output. A Desktop task is not
claimed protected until its captured evidence reaches a signed terminal state.

Runtime trust requires resolved absolute executable paths, regular executable
targets, expected owner and ancestor ownership/modes, pinned SHA-256 and size,
and a fresh identity check. A receipt-selected runtime is never trusted merely
because it appears in the receipt. On POSIX, the bounded probe starts a new
session and terminates its process group. Windows remains unverified: its
fallback terminates the direct child and does not support the same tested
descendant process-group guarantee.

## Teardown Transaction

Teardown preview displays the exact receipt, managed MCP entry, and staged
artifacts it proposes to remove. It also reports normal-integration health, but
an unhealthy normal integration does not block exact receipt-bound teardown:
leaving the user-wide synthetic fixture installed would be the less safe
failure. With a separately confirmed teardown digest it:

1. validates the receipt and updates its exact observed file head atomically to
   `removing`;
2. re-reads current config and compares the managed entry independently of the
   whole-file digest;
3. refuses automatic removal if the managed entry drifted;
4. removes only `mcp_servers.verity_cordon_poisoned_docs` when it exactly
   matches the receipt, preserving all unrelated changes made since setup;
5. re-reads the config before artifact removal and proves the managed entry is
   absent while every unrelated typed TOML value and the restrictive mode are
   unchanged;
6. persists a deterministic installation-bound quarantine path and `planned`
   state in the `removing` receipt, then removes only a digest-, size-, mode-,
   device-, and inode-matching staged regular file below the receipt-bound
   staging root by anchored rename, re-verification, and unlink. Recovery
   reconciles the original or that exact quarantine entry before finalization;
   an unknown non-empty staging directory blocks `removed`. A replacement or
   symlink is restored or left intact and is never deleted as the fixture;
7. re-reads the config again, records the post-teardown digest, and updates the
   exact `removing` receipt head to
   `removed`; and
8. instructs the operator to restart Codex Desktop.

Confirmed setup and teardown are serialized against other cooperating Verity
demo operations by a private operation lock. Each config replacement also
requires the expected whole-config SHA-256 head observed by that operation.
Codex Desktop and arbitrary editors do not participate in the Verity lock; a
non-cooperating writer can still race a point-in-time check. Closing Desktop and
other Codex tasks, using a fresh preview, applying immediately, and refusing any
digest mismatch are required operational controls for that residual risk.

Teardown does not uninstall the normal Verity plugin, re-enable Codex native
memory, remove hooks, delete the normal integration receipt, erase demo ledger
events, delete signing keys, revoke memories, or rebuild the view. Those are
separate explicit operations.

## Desktop Demonstration Sequence

1. Start the daemon and Control Room; verify the ledger and active view.
2. In a new Desktop task, call `get_release_guidance` with synthetic input.
3. Wait for the evidence ID to reach a signed terminal decision.
4. In shadow mode, show `actual_action=allow`, a quarantine/block
   `would_have_action`, and the explicit “not active protection” label.
5. In a later synthetic release task, the shadow-admitted instruction may
   propose `demo_artifact_sink`. The operator sees the required prompt; any
   allowed invocation can contain only the two fixed markers and performs no
   external action.
6. Switch to enforcement, repeat the docs call, wait for terminal evaluation,
   and show the poisoned operational instruction quarantined while the useful
   fact remains eligible.
7. Open a fresh Desktop task and show only approved Verity memory. Do not infer
   absence from UI timing; verify the signed evaluation and materialized view.
8. Revoke the earlier shadow-admitted memory, rebuild, preserve unrelated
   memory, and verify the ledger.

This scenario is described as **Trojan Hippo-inspired**. It is not a benchmark
reproduction, attack-success-rate measurement, real exfiltration test, or proof
of universal prompt-injection prevention.

## Failure Contract

| Failure | Required behavior |
|---|---|
| Normal integration not ready during setup/readiness | Direct the operator to the separate product-install preview; do not apply demo setup or report ready. |
| Normal integration not ready during teardown | Report degraded product health, but permit only exact receipt-bound teardown with its separately confirmed digest. |
| Reserved MCP name already exists | Refuse; do not read or copy the entry into a receipt. |
| Config changed after preview | Abort before mutation and require a new preview. |
| Unsafe config, receipt, staging, source, or executable path | Refuse with a content-safe class. |
| Artifact or runtime digest drift | Disable demo readiness; do not start or remove drifted code automatically. |
| Interrupted setup or teardown | Reconcile only the receipt-bound exact `prepared` or `removing` state described above. |
| Fixture startup/probe failure | Codex server is required and demo doctor is unhealthy; no protection claim. |
| Sink receives non-synthetic data | Reject without storing, hashing arbitrary body content, or transmitting it. |
| Managed config drift during teardown | Refuse automatic removal; preserve current config and receipt. |
| Unrelated config drift | Preserve it; remove only the exact managed entry. |
| Daemon, policy, ledger, or view unhealthy | Do not inject Verity memory; show a content-free degraded state. |

No warning may contain raw TOML, existing MCP values, paths in routine logs,
tool output, memory content, hook capability, auth state, or exception trace.

The desktop-demo receipt is private, schema-validated local recovery state, not
an Ed25519-signed event. Its SHA-256 bindings detect the tested drift only while
the verifier and host remain trustworthy. Memory decisions, revocation, and
protection claims rely on the separate signed event ledger.

New setup records the current normal-integration receipt version `2.0.0`.
Desktop receipt parsing retains `1.0.0` only so an existing receipt can be
inspected and safely torn down; the normal integration doctor must still be
ready, so legacy runtime identity cannot authorize new demo setup.

## Required Contract Tests

- preview has zero filesystem/config/process side effects;
- setup changes only the reserved MCP entry and writes a schema-valid private
  receipt;
- existing reserved name is refused without serialization;
- config drift between preview/apply and managed-entry drift at teardown;
- unrelated TOML changes survive setup and teardown;
- interrupted setup at every mutation boundary is reconcilable;
- atomic writes distinguish a missing target from an existing empty file and
  bind config, receipt, artifact, and receipt-archive writes to expected
  existence plus SHA-256;
- receipt/archive inode replacement, normal v2 receipt/doctor drift, and
  finalization races stop before the next dependent mutation;
- prepared recovery classifies the current config before restaging, so config
  or managed-entry drift leaves an absent artifact absent;
- initial and recovery config replacements re-read and verify every unrelated
  parsed value without exposing it, persist a non-finalizable failure on
  mismatch, cannot launder that mismatch through retry, and recover an
  interrupted `prepared` to `failed` journal write before exact teardown;
- setup, recovery, and teardown preserve an existing `0400` config mode;
- recovery verifies bounded source digest and size before recreating the
  staging directory;
- interrupted teardown in `removing` is exactly resumable, and repeat setup
  archives a digest-matching `removed` receipt without overwriting conflicts;
- normal-integration failure prevents setup/readiness but does not strand an
  otherwise exact, receipt-bound user-wide fixture during teardown;
- cooperating demo mutations serialize under the operation lock, expected
  config-head drift is rejected, and non-cooperating-writer risk is documented;
- symlink, permissions, path containment, source/runtime/artifact digest, and
  unsafe recursive-cleanup checks, including a path-replacement race proving
  anchored teardown does not delete the replacement file;
- fixture exposes exactly two allow-listed tools over bounded stdio;
- fixture source does not import network, environment, subprocess, filesystem,
  email, or browser modules;
- sink accepts only exact fixed markers and performs no external/file/env read;
- normal `verity install-codex` never installs the demo fixture;
- teardown preserves ledger, key, policies, memory history, and normal plugin;
- Desktop observations are recorded as manual smoke evidence; and
- offline fallback still exercises real policy, ledger, view, revocation, and
  Control Room without an API key.
