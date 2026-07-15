# Demo Requirements Checklist: Codex Memory Firewall

**Purpose**: Validate that demo requirements define a coherent, reproducible,
judge-friendly product experience

**Created**: 2026-07-15

**Audience**: Product and engineering reviewers before implementation

> Checked items validate written requirements, not completion of the demo.

## Judge Path

- [x] CHK001 Is the offline path explicitly API-key-free and based on real policy, ledger, materialization, service, and UI code? [Completeness, Spec FR-022]
- [x] CHK002 Are supported platforms and runtime prerequisites bounded? [Clarity, Spec Assumptions]
- [x] CHK003 Is a clean-checkout path defined in no more than five primary commands? [Measurability, Spec SC-008]
- [x] CHK004 Are expected offline outcomes documented for safe and malicious candidates? [Coverage, Quickstart Fast Offline Path]
- [x] CHK005 Is live mode explicitly labeled and prohibited from silent fixture fallback? [Consistency, Spec FR-023]

## Narrative Coverage

- [x] CHK006 Does the required flow cover attack capture, shadow outcome, enforcement, new-session injection, revocation, replay, and verification? [Completeness, Spec US1-US7]
- [x] CHK007 Is shadow mode prohibited from being presented as active protection? [Clarity, Spec FR-007]
- [x] CHK008 Is the poisoned tool clearly constrained to synthetic, inert, loopback-only behavior? [Safety, Spec FR-024]
- [x] CHK009 Are the exact GPT-5.6 runtime contributions distinguished from Codex development collaboration? [Clarity, Spec US7]
- [x] CHK010 Is deterministic policy authority retained in the live semantic narrative? [Consistency, Spec FR-005/FR-006]

## Control Room Experience

- [x] CHK011 Are overview, inventory, timeline, detail, quarantine, revocation, policy, and ledger views required? [Completeness, Spec FR-015]
- [x] CHK012 Are confirmation, keyboard access, failure, loading, empty, and disconnected states required for trust-changing flows? [Coverage, Spec SFR-007 and Edge Cases]
- [x] CHK013 Are safe representations required instead of raw evidence or secrets? [Security, Spec FR-004/SFR-009]
- [x] CHK014 Are semantic provider state, shadow state, and ledger state visibly distinguishable? [Clarity, Spec US2/US4/US5]
- [x] CHK015 Is browser verification measurable through interaction, accessibility, layout, and console-error outcomes? [Measurability, Spec SC-009/SC-012]

## Video and Recovery

- [x] CHK016 Is the video required to be strictly less than three minutes with audio and public YouTube visibility? [Compliance, Research OpenAI Build Week]
- [x] CHK017 Does the script allocate time to the problem, working product, GPT-5.6, Codex, and final positioning? [Coverage, Demo narrative requirement]
- [x] CHK018 Is the demo resilient to a live API failure by preserving a complete offline path? [Recovery, Spec US7]
- [x] CHK019 Are reset and isolated data behavior specified so repeated runs remain deterministic? [Reproducibility, Quickstart]
- [x] CHK020 Are screenshots, videos, deployments, and session IDs prohibited from fabrication? [Integrity, Spec Assumptions]
