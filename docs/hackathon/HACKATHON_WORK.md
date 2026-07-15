# Hackathon Work Record

## Work Boundary

- **OpenAI Build Week submission period**: 2026-07-13 09:00 PT through
  2026-07-21 17:00 PT
- **Verity Cordon project start**: 2026-07-15
- **Clean baseline commit**: `ef2c80d` (`chore: establish hackathon baseline`)
- **Integrated default branch**: `main`
- **Implemented baseline feature**: `specs/001-codex-memory-firewall/`
- **Current implementation branch**: `codex/002-desktop-subscription-defense`
- **Only active sprint feature**:
  `specs/002-codex-desktop-subscription-defense/`

The baseline is an empty root commit created after confirming that the workspace
was empty. Every product artifact and implementation file is new hackathon work
on the feature branch. OWASP Agent Memory Guard is research and prior art, not a
renamed codebase.

## Tooling Baseline

- GitHub Spec Kit `v0.12.15`, release commit
  `7b91c1eda46e1107a53831cd3f14f608b4b7bad0`
- Codex CLI observed and used for isolated integration verification: `0.144.4`
- Spec Kit source-of-truth commit: `d7c2cd7`
- Direct API runtime target remains configured as `gpt-5.6`; the exercised
  ChatGPT-subscription provider uses `gpt-5.6-luna`

## Commit Record

| Commit or range | Purpose | Status |
|---|---|---|
| `ef2c80d` | Empty, clean hackathon baseline | Complete |
| `d7c2cd7` | Spec Kit initialization, constitution, active feature spec | Complete |
| `f27c636` | Research, plan, contracts, checklists, and task graph | Complete |
| `8368cf2` | Reproducible package foundation | Complete |
| `06cad96` | Signed policy and event-ledger foundation | Complete |
| `09533d6` | Candidate screening and memory evaluation pipeline | Complete |
| `cdba594` | Ledger verification, revocation, and replay | Complete |
| `2ac638e` | Secure daemon, streaming, and live semantic implementation | Complete |
| `5a2aa36` | Explicit demo and signed memory-expiration lifecycle | Complete |
| `9f2089b` | Complete Control Room, Codex integration, security hardening, and verification suite | Complete |
| `c632e62` | Converged specifications and hackathon release materials | Complete |
| `c632e62..95459ac` | Fresh-clone, audit, repeatable verification, and publication evidence | Complete |
| `95459ac` | Initial verified public `main` commit | Complete |
| `485e49b..5bd85ff` | Sprint 002 specification, subscription boundary, Desktop defense, and secure demo vertical slice | Complete |
| `104e0f0` | Pushed Sprint 002 clean-verification checkpoint with deterministic uncached Ruff checks | Complete |
| `c70db72` | Pinned release verification to the bootstrapped environment and enforced the declared Node engine | Complete |
| `79a12d0` | Recorded fresh-clone and Control Room browser acceptance evidence | Complete |

The feature-001 branch was fast-forwarded into `main` without rewriting history
or force-pushing. Sprint 002 remains on its public feature branch pending
operator review and merge.

## Sprint 002 Baseline

Feature 002 began on 2026-07-15 from public `main` commit
`00f7e44e64187dbf531a84bb0c1933e474ff6c08` on branch
`codex/002-desktop-subscription-defense`. The sprint promotes Codex Desktop to
the primary demo surface and adds an explicit subscription-backed semantic
provider while preserving the implemented feature-001 controls and no-key
fallback.

The operator workspace contained unrelated untracked duplicate files named
`* 2.*` before sprint work began. They were excluded from early staging and
test discovery, then removed only after the operator explicitly authorized a
workspace cleanup on 2026-07-15. Generated frontend dependencies were rebuilt
with `npm ci`.

The first tracked-path baseline run executed the 267 root backend tests. It
reported 266 passing tests and one timeout in the three-second bounded stdio
fixture used by the offline end-to-end demo. The same focused test failed once
and then passed unchanged on the next run in 4.90 seconds; a direct fixture
invocation also succeeded. This is recorded as a pre-existing demo-reliability
flakiness signal under concurrent host load, not as a passing baseline gate.
Feature 002 must remove the ambiguity and pass the clean-checkout gate before
handoff. An attempted combined root/evaluation/example invocation was discarded
because the independently packaged example projects require their own project
environments; later verification uses `scripts/verify.sh` and its intended
per-project commands.

The feature-002 pre-implementation Spec Kit analysis then reviewed all 45
functional, security, and success requirements against the 58-task graph. Its
two critical process/test-matrix findings and six high-severity consistency or
coverage findings were remediated before substantive code work: the verified
Codex argument order became canonical, private demo state was ignored, daemon
readiness API work and a timed manual Desktop rehearsal were made explicit,
every security story received its required scenario matrix, executable/home
trust rules were made normative, and the privacy criterion now excludes only
the fixed literals in designated source definitions. No deferred capability
entered active scope.

## Sprint 002 Live Subscription Evidence

- **Date**: 2026-07-15
- **Codex CLI**: `0.144.4`
- **Authentication boundary**: supported ChatGPT sign-in status; Verity did not
  read credential files or print raw status output
- **First requested model**: `gpt-5.6`; unavailable for the signed-in identity,
  recorded content-safely as `failed/process_exit` with no fallback
- **Exercised model**: `gpt-5.6-luna`
- **Input**: fixed sanitized synthetic operational instruction only
- **Provider outcome**: `live_codex_subscription`
- **Isolation label**: `agentic_sandboxed`
- **Policy input recommendation**: `quarantine`; deterministic policy remains
  final authority
- **Observed provider latency**: 11,026 ms
- **Raw child output retained or logged**: no

This smoke proves only that the configured local subscription path completed on
the recorded host and date. It does not establish universal model entitlement,
latency, tool absence inside the Codex binary, or protection from a compromised
host.

## Milestones

- [x] Repository and official-rule preflight
- [x] Baseline commit and feature branch
- [x] Current Spec Kit installation and Codex initialization
- [x] Constitution and feature specification
- [x] Official Codex, GPT-5.6, Build Week, and donor research
- [x] Plan, contracts, checklists, tasks, and pre-implementation analysis
- [x] Minimal safe-memory vertical slice
- [x] Shadow and enforcement attack demonstration
- [x] Documented Codex plugin/hook integration
- [ ] Successful credentialed live GPT-5.6 API exercise
- [x] Revocation, replay, and ledger tamper verification
- [x] Confirmed one-memory rescan under the current signed policy
- [x] Transactional streaming and detector plugin
- [x] Real bounded-stdio poisoned-tool fixture and approved-only simulated
  `SessionStart` demo assertion
- [x] Control Room polish and desktop browser verification
- [x] Final clean-checkout offline demonstration
- [x] Final full verification after security hardening
- [x] Final Spec Kit analysis and checklist convergence
- [x] Public repository creation and push
- [ ] Operator video, `/feedback`, and Devpost submission

## Verified Checkpoints

### Deterministic evaluation

The saved 2026-07-15 Sprint 002 evaluation uses 20 original Apache-2.0 synthetic fixtures
and the recorded semantic provider:

- 7/7 benign fixtures allowed
- 13/13 risky fixtures protected
- 0 false positives and 0 false negatives for this fixture only
- 326 signed events verified
- Materialized view consistent

These are fixture-scoped results, not universal accuracy or live GPT-5.6
performance. The exact dataset digest and timings are in
`evals/results/latest.md` and `evals/results/latest.json`.

### Automated gates

The Sprint 002 US1/US2 checkpoint ran the canonical `./scripts/verify.sh`
after an independent containment review found and test-first repaired three
pre-publication issues: successful Codex child descendants were not accounted
for, blocked stdin transfer sat outside the semantic deadline, and signed
evidence status could regress to pending after a rescan. The repaired gate
passed 400 backend tests, 13 example/plugin tests, 9 frontend tests, Ruff,
mypy, OpenAPI validation, frontend type/lint/build, Python and npm dependency
audits, 80% backend coverage, and the 20-sample fixture evaluation with 0
fixture-scoped false positives and 0 fixture-scoped false negatives. The
success-path descendant, blocked-stdin, opened-output inode, safe-rescan, and
revoking-rescan cases now have explicit regressions.

The Sprint 002 US3/US4 checkpoint then added the full shadow-admission and
selective-recovery path plus a separate reversible Codex Desktop demo
installer. The installer previews without mutation, requires explicit
confirmation and reviewed-hook trust, manages only the reserved
`verity_cordon_poisoned_docs` MCP entry and a digest-bound staged script, writes
a strict private recovery receipt, refuses config/artifact/runtime drift, and
tears down only exact managed state. The normal `install-codex` path remains
separate and never stages the attack fixture.

The canonical `./scripts/verify.sh` gate passed 437 backend tests in 105.14
seconds, 13 isolated example/plugin tests, and 6 frontend files / 10 tests.
Ruff, mypy, OpenAPI validation, frontend type/lint/build, Python and npm
dependency audits, 79% aggregate backend coverage, and the 20-sample fixture
evaluation all passed. The evaluation recorded 7/7 benign samples allowed,
13/13 risky samples protected, 0 fixture-scoped false positives, 0
fixture-scoped false negatives, a verified 326-event ledger, and a consistent
materialized view. These are automated contract and fixture results; an actual
timed Codex Desktop UI rehearsal remains separately operator-visible evidence.

Fresh-clone Sprint 002 acceptance then ran at pushed remote checkpoint
`104e0f06d3d2b3be5d36e2f3884af1adf3076c04` from a new clone beneath a
private trusted parent. Bootstrap completed without an OpenAI API key, and the
no-key offline demo exercised the real policy engine, signed ledger, memory
materialization, and recovery flow. It finished with 65 events, a verified
chain, and a consistent materialized view. The complete clean-checkout
`./scripts/verify.sh` gate passed 506 backend tests, 13 isolated
example/plugin tests, 10 frontend tests, 80% backend coverage, Ruff, mypy,
frontend lint/type/test/build, schema and OpenAPI validation, Python and npm
dependency audits, and the 20-fixture evaluation with 0 fixture-scoped false
positives and 0 fixture-scoped false negatives.

An earlier acceptance attempt below `/tmp` was rejected by the intentional
trusted-root security boundary because the clone inherited a shared writable
ancestor. The boundary was not weakened to make the test pass; clean
acceptance was rerun from the private trusted parent instead.

The environment-pinning hardening at
`c70db7296427f1525d52e0b2a0854fa34f123d2d` then passed bootstrap and the
complete verification gate again from a second fresh private clone. This run
used the checked-out `.venv` directly, ignored caller `PYTHONPATH` state, and
enforced the Control Room's declared Node.js engine before frontend work.

The timed final post-hardening `./scripts/verify.sh` run reported 267 backend tests,
10 example/plugin tests, 7 frontend tests, 80% backend coverage, a successful
frontend production build, valid OpenAPI, clean formatting/lint/type checks,
and zero known findings from the configured Python and npm dependency audits.
The fixture evaluation gate also completed with 0 false positives and 0 false
negatives on the repository's 14 original synthetic samples. After the
documented bootstrap, the complete gate took 28.94 seconds of wall time on the
exercised macOS developer host, satisfying SC-010's five-minute bound.

A later exact-commit rerun revealed that `uv` could recreate its
underscore-prefixed editable-install path file with macOS's hidden flag after a
prior run. `scripts/verify.sh` now normalizes that disposable virtual-environment
metadata on every standalone run, matching bootstrap behavior. The complete
post-fix gate passed in 30.71 seconds, and the immediate direct package import
also succeeded.

Bootstrap was rerun after fixing editable-install metadata on macOS. A built
wheel was also installed into an isolated temporary environment and its package
import and CLI entry point succeeded.

Fresh-clone acceptance then ran against committed feature state `c632e62` in an
isolated `/tmp` clone with `OPENAI_API_KEY` explicitly absent:

```bash
env -u OPENAI_API_KEY ./scripts/bootstrap.sh
env -u OPENAI_API_KEY VERITY_DEMO_NO_SERVE=1 ./scripts/demo-offline.sh
/usr/bin/time -p ./scripts/verify.sh
```

Bootstrap completed without creating a credential. The offline demo used the
real policy, signed ledger, materialized view, rescan/revocation/rebuild path,
approved-only session context, and bounded local stdio fixture; it reported a
verified, consistent 65-event ledger and no external transmission. The full
clean-clone gate passed in 38.67 seconds with 267 backend tests, 10
example/plugin tests, 7 frontend tests, 80% backend coverage, valid contracts,
zero dependency-audit findings, and the 14-sample fixture evaluation at 0 false
positives and 0 false negatives. No credential value was required or logged.

After targeted rescan and demo hardening, the five rescan acceptance tests, a
10-test rescan/demo/CLI focus set, and a 41-test related
ledger/revocation/shadow/contracts set passed. A no-serve offline demo invoked
the reviewed bounded-stdio fixture, performed current-policy rescan and
revocation, rebuilt the view, rendered approved-only simulated `SessionStart`
context through the real memory service, and verified a consistent 65-event
ledger. These were focused checkpoint results; the later final full
verification and fresh-clone gates passed.

The subsequent corruption-startup contract test passed: after tampering with a
signed ledger event, runtime restart exposed content-safe read-only Control Room
status and policy state, labeled policy validation invalid, returned no
`SessionStart` context, and kept signed writes disabled without loading detector
plugins. Three focused injection-budget tests also passed. These results support
the bounded failure-mode and whole-record budget claims and were included in the
later final full gate.

Output-hygiene hardening then passed Ruff, targeted mypy, and 106 focused and
regression tests. That checkpoint covers bounded/sanitized detector plugin
results, bounded and re-sanitized model free text and model identifiers, and
content-safe detail projection. Additional focused tests passed for
source-label and stream-reason sanitization, local-path hardening, and Codex
receipt/current-Python binding. These changes are included in the final full
gate above.

### Publication security audit

An independent read-only audit of all 234 intended tracked files and reachable
history found no real credentials, private keys, mutation capabilities, runtime
databases, ledger heads, salts, receipts, personal absolute paths, unsafe file
types or modes, large blobs, or unsupported product claims. Fresh wheel and
source distributions were also scanned; the wheel installed and its CLI ran in
an isolated environment. `git fsck --full --strict`, Ruff, mypy, dependency
audits, and focused security tests passed.

The audit identified only synthetic credential-shaped strings in explicitly
marked test fixtures. They are not secrets, but GitHub push protection may
still ask for a false-positive review. Secret scanning will not be disabled to
work around a hypothetical block. Ignored demo runtime state was removed before
publication.

### Public repository

- URL: https://github.com/MahdiHedhli/verity-cordon
- Initial public commit: `95459ac6559d79220307624847804aa5f29963f2`
- Visibility: public
- Default branch: `main`
- License detected from the anonymous GitHub API: Apache-2.0
- Topics: `codex`, `developer-tools`, `memory-security`, `openai-build-week`,
  `prompt-injection`, `security`
- GitHub security state: secret scanning enabled, push protection enabled,
  Dependabot security updates enabled, and private vulnerability reporting
  enabled

An unauthenticated API request and anonymous raw-file requests confirmed the
public repository, README positioning, default branch, and license after the
initial push.

### Browser and Codex integration

A desktop-width browser smoke exercised Overview, inventory, candidate detail,
quarantine and its block confirmation, revocation/replay state, policy, and an
authenticated full ledger verification. The smoke exposed and then verified a
fix for cross-stream rescan revocation status in candidate detail. The final
65-event browser receipt reported anchored completeness and a consistent view;
the observed console was clean. Keyboard/focus and accessibility labels
received a manual smoke; no automated axe-core result is claimed.

The plan's earlier hard under-one-second UI interaction target was removed
during convergence because the available browser-control transport adds its own
latency and did not provide a defensible product-local measurement. Responsive
local navigation remains browser-smoke evidence, not a published latency SLO.

The Codex installer, uninstaller, hook configuration, and doctor behavior were
exercised against Codex CLI 0.144.4 in an isolated temporary configuration. A
bounded subagent implemented and verified that isolated integration; the
primary thread reviewed and integrated it. No operator's real Codex configuration
was needed for the acceptance check.

The Sprint 002 browser smoke used an ephemeral clean-clone runtime at
1280x720. It verified Overview, Candidate Detail with a typed
`MemoryRevoked` event, the quarantine Block action, and selective revocation
while preserving one unrelated active memory. The mode sequence was
enforce-to-shadow-to-enforce and ended in enforce mode on policy `1.0.2`.
Ledger Verification reported 69 events with anchored completeness and a
consistent materialized view. The browser console had 0 errors and 0 warnings,
and the page had no horizontal overflow. The accessibility smoke found the
expected main landmark, navigation landmark, level-one heading, and skip link,
with 0 unlabeled controls and 0 duplicate IDs.

This browser evidence exercises the local Control Room, not the Codex Desktop
app itself. The timed, operator-visible Codex Desktop
attack-enforcement-clean-task-revocation-ledger rehearsal remains open and is
not represented as completed.

## New Work versus Prior Art

Verity Cordon's implemented contribution is an async-first local daemon, a
documented Codex controlled memory plane, schema-constrained GPT-5.6 extraction
and assessment implementation, deterministic Pydantic policy authority, a
persistent signed event chain, explicit shadow actions, event-specific
revocation and replay, signed targeted rescan, transactional streamed memory
writes, a loopback Control Room, and a judge-ready offline product path whose
mock tool is invoked over reviewed bounded stdio.

See `BASELINE_COMPARISON.md` for source-backed donor details.

## Spec Kit Analysis

The pre-implementation consistency analysis ran on 2026-07-15 after two
independent read-only review passes. All 39 functional, security, and public
claim requirements and all 12 success criteria mapped to the 77-task graph. No
deferred `VC-FUT-*` capability entered active scope. Contract metaschema and
OpenAPI validation passed at that checkpoint. A final post-implementation
analysis then added four explicit convergence tasks: privacy-safe span coverage,
performance evidence, the still-unexercised credentialed live-model gate, and
the clarification record. The telemetry, measurement, and clarification gaps
are closed; the live-model task remains openly pending because no API key is
present. After the clean-clone and security-audit evidence was recorded, the
final read-only analysis found no critical or high consistency gap, no active
deferred capability, and no unresolved material ambiguity. T080 and the live
submission-checklist item remain intentionally unchecked.

## Open Issues and Operator Actions

- Review and merge `codex/002-desktop-subscription-defense` into public `main`;
  no pull request or merge is represented as complete.
- Exercise the credentialed live GPT-5.6 path if a suitable local key is
  available; otherwise disclose it as unexercised.
- Perform and time the operator-visible Codex Desktop app rehearsal; automated
  fixture, subscription, Control Room, and hook-contract evidence does not
  substitute for that app-level observation.
- Run `/feedback` in the primary project thread and record the real Session ID.
- Record and upload a public YouTube video with audio under three minutes.
- Keep the free judge path available through 2026-08-05 17:00 PT.
- Submit and review the Devpost entry before 2026-07-21 17:00 PT.

## Submission Status

Not submitted. The public repository is independently verified. No successful
credentialed live API call, video, screenshot, `/feedback` Session ID, or
Devpost submission is represented as complete until independently created and
verified.

## Sprint 002 Handoff Snapshot

- **Public repository**: `https://github.com/MahdiHedhli/verity-cordon`
- **Branch**: `codex/002-desktop-subscription-defense`
- **Final verified implementation/evidence checkpoint**:
  `79a12d0c8058d579664c90740a8bd44ae3359c68`
- **Automated verification**: 506 backend tests, 13 isolated example/plugin
  tests, 10 frontend tests, 80% backend coverage, schema/OpenAPI validation,
  dependency audits, type checks, lint, production build, and 20 fixture
  evaluations with 0 fixture-scoped false positives and 0 fixture-scoped false
  negatives
- **Browser verification**: protected quarantine action, selective revocation,
  shadow/enforce transitions, 69-event anchored ledger verification, consistent
  materialized view, 0 console errors or warnings, and the recorded 1280x720
  layout/accessibility smoke
- **Known limitations**: the Codex Desktop app rehearsal is not yet observed;
  the subscription smoke exercised semantic assessment with `gpt-5.6-luna`
  rather than the direct API target `gpt-5.6`; the fixed sink sequence is an
  inert simulation and does not prove a causal memory-to-tool-call path; and a
  compromised host, Codex binary, or signing key remains out of scope
- **Deferred roadmap**: all `VC-FUT-*` backends, additional agents, remote
  control-plane capabilities, enterprise identity, packaged local models, and
  exporter ecosystems remain outside the active feature task graph
- **Submission status**: not submitted; video, final form entry, logged-out link
  checks, and the real `/feedback` Session ID remain operator-owned
- **Exact next operator sequence**: close unrelated Codex tasks; follow the
  preview/digest-confirmed setup in `scripts/demo-desktop.sh`; quit/restart
  Codex Desktop around setup and teardown; run and time the documented attack,
  enforcement, clean-task, revocation, and ledger sequence; immediately tear
  down the user-wide fixture; review and merge the feature branch; record and
  upload the under-three-minute public video; run `/feedback` in this primary
  task; enter the real Session ID; test public links logged out; and submit
  before 2026-07-21 17:00 PT
