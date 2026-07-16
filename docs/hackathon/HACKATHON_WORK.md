# Hackathon Work Record

## Work Boundary

- **OpenAI Build Week submission period**: 2026-07-13 09:00 PT through
  2026-07-21 17:00 PT
- **Verity Cordon project start**: 2026-07-15
- **Clean baseline commit**: `ef2c80d` (`chore: establish hackathon baseline`)
- **Integrated default branch**: `main`
- **Implemented baseline feature**: `specs/001-codex-memory-firewall/`
- **Current implementation branch**: `codex/002-release-review-hardening`
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
| `a831e3e` | Closed subscription schema, hook-trust, runbook, screenshot, and release-audit gaps | Complete |
| `e458786` | Aligned runtime status and semantic-failure contracts after post-merge review | Complete |
| `0da11e5` | Bound actual runtime status responses to the public OpenAPI contract | Complete |
| `8540cbb` | Unified CLI and daemon subscription-readiness reporting | Complete |
| `3a18cf7` | Merged PR #2 contract and readiness alignment into public `main` | Complete |
| `3d8a91d` | Closed release-review integration, recovery, provenance, and race gaps | Complete |

The feature-001 branch was fast-forwarded into `main` without rewriting history
or force-pushing. Sprint 002 subsequently merged through PR #1, and its
post-merge contract/readiness alignment merged through PR #2 at
`3a18cf7dfc14ef59d48198789b567a44157c3b2b`. Release-review hardening remains on
the current feature branch until its remote review and public-main verification
are complete.

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
- **Requested subscription model identifier**: `gpt-5.6-luna`; the current
  event stream does not attest the returned remote model
- **Input**: fixed sanitized synthetic operational instruction only
- **Provider outcome**: `live_codex_subscription`
- **Isolation label**: `agentic_sandboxed`
- **Policy input recommendation**: `quarantine`; deterministic policy remains
  final authority
- **Observed provider latency**: 11,026 ms
- **Raw child output retained or logged**: no

This smoke proves only that the configured local subscription path completed on
the recorded host and date. It preceded the exact incremental JSONL grammar and
other release-review hardening. A later hardened probe was externally
rate-limited and proved fail-closed handling only; a successful hardened live
completion remains pending. None of this establishes universal model
entitlement, latency, tool absence inside the Codex binary, remote-model
attestation, or protection from a compromised host.

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
- [ ] Release-hardening remote review closure and public-main verification
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

### Baseline publication security audit (historical)

At the feature-001 publication checkpoint, an independent read-only audit of
all 234 then-intended tracked files and reachable
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

Sprint 002 added tracked implementation, test, specification, and release files;
the feature-001 count is retained as dated evidence rather than presented as a
current-branch total. The current branch is covered by the later clean-checkout
verification and Sprint 002 closure audit below.

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

### Sprint 002 closure preflight

On 2026-07-15, a content-safe preflight observed macOS 26.4.1 on arm64,
ChatGPT desktop app `26.707.72221` build `5307`, and Codex CLI `0.144.4` with
ChatGPT subscription authentication ready. The app was running, so no
user-wide configuration mutation, Desktop loading claim, or manual rehearsal
was attempted.

The normal Verity installer preview remained read-only, exited `2` as designed,
reported the five expected Boolean configuration deltas with no issue, and
confirmed the normal plugin was not yet installed. Native Codex memory remained
enabled, demo data and receipts were absent, the reserved demo MCP name was
absent, and port 8765 was available. Current official hook guidance also exposed
a runbook gap: non-managed hooks require exact-definition trust through CLI
`/hooks`; Verity's `--confirm-hook-trust` is only the operator assertion made
after that Codex-managed review. The installer output, quickstart, demo script,
submission instructions, and blank `DESKTOP_REHEARSAL_RECORD.md` were aligned to
that boundary and to one canonical shadow-trigger-enforce-revoke sequence.

The first full no-key subscription pipeline attempt then failed closed at live
candidate extraction. Content-safe diagnostics isolated the cause to the strict
output schema: `requested_ttl_seconds` was nullable but absent from the nested
candidate object's required list. Verity made the nullable field required,
added strict-schema regression assertions, and reran the focused OpenAI and
subscription suite successfully (23 tests). The corrected live run used
supported ChatGPT sign-in and requested `gpt-5.6-luna` with no API key or
provider fallback. It extracted four synthetic candidates, completed live
semantic assessment, produced allow and quarantine outcomes, and ended in
45,806 ms with 50 verified signed events and a consistent materialized view.
The requested model identifier is recorded; `returned_model` remains null by
contract because the runtime event stream does not attest a remote model.
These successful runs preceded the release-hardening exact incremental JSONL
grammar. A post-hardening, API-key-free probe on Codex CLI `0.144.4` was
classified locally into the fixed safe category `rate_limit`, returned
retryable `failed/process_exit` in 3,704 ms, produced no disposition or final
document, and left cleanup health clean. Raw child content was neither printed
nor retained. This proves fail-closed failure handling, not successful hardened
live completion; that revalidation remains pending while subscription capacity
is unavailable.

A real 1280x720 Control Room overview was captured from the offline deterministic
fixture and added as `docs/assets/control-room-overview.jpg`. It shows only
content-safe aggregate state and truncated synthetic IDs, is explicitly
captioned as fixture-backed, and produced zero browser console warnings or
errors. It is a product screenshot, not fabricated live-provider or Desktop-app
evidence.

PR #1 merged Sprint 002 into public `main` at
`e7074276ad40ee60a889e540c22a07659744097e`. Two late automated review findings
then exposed real public-contract drift: the runtime status response had three
fields absent from its closed OpenAPI schema, and the semantic failure JSON
Schema omitted six runtime failure classes. Commit `e458786` centralized the
provider-isolation mapping, aligned both contracts and the frontend type, and
added executable equality and response-validation regressions. A follow-up
review also found that CLI status could report a subscription provider ready
without a runner; `8540cbb` aligned it with daemon fail-safe behavior and added
a regression. The complete post-fix gate passed 510 backend tests, 13 isolated
example/plugin tests, 10 frontend tests, 80% backend coverage, dependency
audits, production build, and the 20-fixture evaluation. PR #2 then merged the
contract/readiness alignment into public `main` at
`3a18cf7dfc14ef59d48198789b567a44157c3b2b`.

Review of the still-open late PR #1 threads and three independent containment
reviews drove a final release hardening pass across the subscription runner,
normal Codex installer, and Desktop demo installer. The pass serialized runner
health, bound executable trust before and after child execution, enforced hard
resource ceilings, validated successful provider provenance, made normal
install/remove operations receipt-journaled and retry-safe, and bound Desktop
configuration, archive, artifact, receipt, and teardown transitions to exact
expected state. It also added interruption, drift, concurrency, replacement,
non-disclosure, and recovery regressions. Independent re-reviews found no
remaining P1 or P2 issue.

The final local `./scripts/verify.sh` release gate passed 706 backend tests in
174.84 seconds with 81% aggregate coverage, 13 isolated example/plugin tests,
and 6 Control Room files / 11 tests. Ruff formatting and lint, mypy across 60
source files, OpenAPI and JSON Schema validation, frontend type checking, lint,
production build, Python and npm dependency audits, and the 20-sample fixture
evaluation all passed. The evaluation remained fixture-scoped at 0 false
positives and 0 false negatives. A first verification process became
unobservable after macOS cloud-conflict copies appeared only inside the
generated `.venv`; those duplicate generated files were removed without
changing tracked source, package import was rechecked, and the complete gate was
rerun to the recorded exit-zero result.

Fresh-clone acceptance then checked out pushed branch commit
`18e04942a637af9eacc3b491fce8c7a9540f21c9` beneath a new private trusted cache
parent with `OPENAI_API_KEY` explicitly absent. Bootstrap completed without
creating a signing key, database, or credential. The no-serve offline demo used
the real policy, signed ledger, materialized view, rescan/revocation/rebuild,
approved-only simulated session context, and bounded stdio fixture; it ended
with 65 verified events, a consistent view, two unrelated active memories
preserved, and no external transmission. The clean clone then passed the same
complete 706-backend-test, 13-example/plugin-test, 11-frontend-test verification
gate with 81% coverage and zero configured dependency-audit findings.

The post-hardening API-key-free subscription probe on Codex CLI `0.144.4`
reached external rate limiting. Verity returned the fixed content-safe
`failed/process_exit` category in 3,704 ms, retained no final document or raw
child output, made no disposition, and reported clean cleanup health. This is
failure-path evidence, not a successful hardened semantic completion or remote
model attestation. The successful hardened live path remains pending capacity.

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

The feature-001 analysis history is preserved in its own specification and
earlier commits. The final 2026-07-15 read-only analysis selected only active
feature `002-codex-desktop-subscription-defense`: 26 functional requirements,
10 security/failure requirements, 10 measurable outcomes, 15 acceptance
scenarios across four user stories, and 66 unique sequential tasks. All 46
requirements and all 15 scenarios map to implementation or verification tasks,
for 100% traceability. All 93 checklist items are complete. The analysis found
zero unresolved ambiguity, duplication, constitution violation, unmapped task,
or deferred-scope leakage. Convergence would append no task and therefore left
`tasks.md` unchanged. T056 remains the explicit operator-observed Desktop
acceptance-evidence gate; T066 remains the remote release-closure gate.

## Open Issues and Operator Actions

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
credentialed direct-API call, operator-observed Desktop rehearsal, public
video, `/feedback` Session ID, or Devpost submission is represented as complete
until independently created and verified. The tracked offline-fixture product
screenshot is complete and is not presented as Desktop-app or live-provider
evidence.

## Sprint 002 Handoff Snapshot

- **Public repository**: `https://github.com/MahdiHedhli/verity-cordon`
- **Branch**: `codex/002-release-review-hardening`
- **Public `main` before release-review hardening**:
  `3a18cf7dfc14ef59d48198789b567a44157c3b2b`
- **Locally verified release-review implementation commit**:
  `3d8a91d3142e6f56477963652ebe093fb4dc37eb`
- **Locally verified release implementation commit**:
  `a831e3e20bbdc656b3d8199ad75ab76eeb3a7c3d`
- **Locally verified contract-alignment commit**:
  `e458786`
- **Locally verified readiness-alignment commit**:
  `8540cbb`
- **Prior clean-checkout implementation/evidence checkpoint**:
  `79a12d0c8058d579664c90740a8bd44ae3359c68`
- **Automated verification**: 706 backend tests, 13 isolated example/plugin
  tests, 11 frontend tests, 81% backend coverage, schema/OpenAPI validation,
  dependency audits, type checks, lint, production build, and 20 fixture
  evaluations with 0 fixture-scoped false positives and 0 fixture-scoped false
  negatives
- **Browser verification**: protected quarantine action, selective revocation,
  shadow/enforce transitions, 69-event anchored ledger verification, consistent
  materialized view, 0 console errors or warnings, and the recorded 1280x720
  layout/accessibility smoke
- **Known limitations**: the Codex Desktop app rehearsal is not yet observed;
  the subscription pipeline exercised extraction and assessment with the
  requested `gpt-5.6-luna` identifier but does not attest the remote model, and
  the direct API target `gpt-5.6` remains unexercised; the fixed sink sequence is an
  inert simulation and does not prove a causal memory-to-tool-call path; and a
  compromised host, Codex binary, or signing key remains out of scope
- **Deferred roadmap**: all `VC-FUT-*` backends, additional agents, remote
  control-plane capabilities, enterprise identity, packaged local models, and
  exporter ecosystems remain outside the active feature task graph
- **Submission status**: not submitted; video, final form entry, logged-out link
  checks, and the real `/feedback` Session ID remain operator-owned
- **Release sequence at this checkpoint**: close every ChatGPT Desktop task, exit all
  Codex CLI TUI and IDE sessions, and fully quit the ChatGPT desktop app;
  preview and apply the normal Verity integration; deliberately start CLI,
  use `/hooks` to trust the exact reviewed Verity hook definitions, exit CLI,
  and set the post-review assertion; follow the preview/digest-confirmed setup
  in `scripts/demo-desktop.sh`; start the daemon and pass doctor/status before
  restarting Desktop; verify `/mcp` and a benign hook canary; run and time the
  documented attack,
  enforcement, clean-task, revocation, and ledger sequence; immediately tear
  down the user-wide fixture; record and upload the under-three-minute public
  video; run `/feedback` in this primary
  task; enter the real Session ID; test public links logged out; and submit
  before 2026-07-21 17:00 PT
