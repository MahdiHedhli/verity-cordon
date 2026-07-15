# Codex Desktop Demo Setup Contract

**Contract version**: `1.0.0`
**Managed MCP entry**: `verity_cordon_poisoned_docs`
**Primary surface**: Codex Desktop
**Fallback surface**: deterministic Verity CLI demo

This contract installs only the synthetic delayed-poisoning fixture used by the
Desktop demonstration. Normal Verity plugin, hook, and native-memory controls
remain governed by the baseline Codex installer and its separate receipt.
Running the normal installer MUST NOT install or enable the demo MCP server.

## Command Behavior

The supported operations are conceptually:

```text
verity demo desktop-setup
verity demo desktop-setup --yes
verity demo desktop-teardown
verity demo desktop-teardown --yes
```

Without `--yes`, both commands are read-only previews. Preview MUST NOT create
directories, stage files, back up or rewrite Codex configuration, write a
receipt, start the fixture, call the sink, or change Verity history.

The setup preview shows:

- normal Verity integration readiness and, when not ready, the exact separate
  plugin/hook/memory-control changes that `verity install-codex` would propose;
- the Codex config path and digest, with user paths redacted in routine logs;
- the one MCP entry to add, including command, arguments, tool allow list,
  timeouts, and approval policy;
- staged artifact relative paths, byte sizes, and SHA-256 digests;
- resolved Codex and Python runtime versions and digests;
- receipt and backup destinations; and
- the statement that the fixture is synthetic, local stdio only, and separate
  from the normal product installation.

Setup with `--yes` requires the normal integration doctor to be ready. If it is
not ready, setup stops after the combined preview and instructs the operator to
confirm the normal installer separately. It never silently installs hooks,
changes native-memory controls, or trusts a plugin on the operator's behalf.

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

1. Re-read bounded Codex config with no-follow semantics and verify it still
   matches the previewed digest.
2. Verify normal integration receipt, staged plugin artifacts, effective memory
   controls, and hook trust/doctor state without reading auth content.
3. Resolve and verify the current Codex and Python executables. The Python
   runtime must support isolated `-I` execution and satisfy the project runtime
   version.
4. Create a private `0700` staging directory and copy only the fixture server
   using atomic `0600` writes. Reject symlinks and verify source/destination
   SHA-256 and byte size.
5. Write a private config backup when the config existed. The backup is
   recovery evidence, not a future whole-file restore strategy.
6. Atomically write a `prepared` receipt conforming to
   `desktop-demo-receipt.schema.json` before changing Codex configuration.
7. Add only the reserved MCP table through parsed TOML and atomically replace
   the config with mode no broader than its prior secure mode.
8. Re-read and canonicalize the managed table, verify its expected digest and
   all unrelated parsed values, then atomically update the receipt to
   `installed` with the after-config digest.
9. Return content-safe operator actions: restart Codex Desktop, open a new task,
   confirm the plugin trust prompt if Codex presents one, and run doctor.

Any precondition or write failure stops the transaction. It does not fall back
to editing generated memories or an undocumented Desktop file.

## Interrupted Setup Recovery

The receipt is write-ahead state:

- `prepared` plus no managed entry: setup may be retried or staged artifacts
  may be removed after their digests verify.
- `prepared` plus the exact managed entry: setup may verify artifacts and
  finalize the receipt as `installed`.
- `prepared` plus a different managed entry: report drift and make no change.
- config mutation with no valid receipt: report unreceipted state and make no
  automatic removal; the operator receives a bounded manual recovery path.

Recovery never restores the entire backup over a newer config and never deletes
an unknown directory recursively.

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

## Teardown Transaction

Teardown preview displays the exact receipt, managed MCP entry, and staged
artifacts it proposes to remove. With confirmation it:

1. validates the receipt and updates it atomically to `removing`;
2. re-reads current config and compares the managed entry independently of the
   whole-file digest;
3. refuses automatic removal if the managed entry drifted;
4. removes only `mcp_servers.verity_cordon_poisoned_docs` when it exactly
   matches the receipt, preserving all unrelated changes made since setup;
5. removes only digest-matching staged regular files below the receipt-bound
   staging root, then removes empty managed directories;
6. records the post-teardown config digest and updates the receipt to
   `removed`; and
7. instructs the operator to restart Codex Desktop.

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
| Normal integration not ready | Show separate product-install preview; do not apply demo setup. |
| Reserved MCP name already exists | Refuse; do not read or copy the entry into a receipt. |
| Config changed after preview | Abort before mutation and require a new preview. |
| Unsafe config, backup, receipt, staging, source, or executable path | Refuse with a content-safe class. |
| Artifact or runtime digest drift | Disable demo readiness; do not start or remove drifted code automatically. |
| Interrupted setup | Reconcile only the receipt-bound exact state described above. |
| Fixture startup/probe failure | Codex server is required and demo doctor is unhealthy; no protection claim. |
| Sink receives non-synthetic data | Reject without storing, hashing arbitrary body content, or transmitting it. |
| Managed config drift during teardown | Refuse automatic removal; preserve current config and receipt. |
| Unrelated config drift | Preserve it; remove only the exact managed entry. |
| Daemon, policy, ledger, or view unhealthy | Do not inject Verity memory; show a content-free degraded state. |

No warning may contain raw TOML, existing MCP values, paths in routine logs,
tool output, memory content, hook capability, auth state, or exception trace.

## Required Contract Tests

- preview has zero filesystem/config/process side effects;
- setup changes only the reserved MCP entry and writes a schema-valid private
  receipt;
- existing reserved name is refused without serialization;
- config drift between preview/apply and managed-entry drift at teardown;
- unrelated TOML changes survive setup and teardown;
- interrupted setup at every mutation boundary is reconcilable;
- symlink, permissions, path containment, source/runtime/artifact digest, and
  unsafe recursive-cleanup checks;
- fixture exposes exactly two allow-listed tools over bounded stdio;
- fixture source does not import network, environment, subprocess, filesystem,
  email, or browser modules;
- sink accepts only exact fixed markers and performs no external/file/env read;
- normal `verity install-codex` never installs the demo fixture;
- teardown preserves ledger, key, policies, memory history, and normal plugin;
- Desktop observations are recorded as manual smoke evidence; and
- offline fallback still exercises real policy, ledger, view, revocation, and
  Control Room without an API key.
