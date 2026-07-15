# Post-Hackathon Roadmap

This register preserves broader product history without placing deferred work in
the active `001-codex-memory-firewall` task graph. Status is descriptive, not a
commitment or a public support claim.

## Repository and Upstream Work

### VC-FUT-001 — Separate OWASP Website and Python Codebase

**Status**: Deferred.

Separate the OWASP informational website repository from the Agent Memory Guard
Python codebase.

**Reason**: Requires OWASP governance and does not improve the Verity Cordon
hackathon demonstration.

## Storage Backends

- **VC-FUT-002**: Redis memory backend.
- **VC-FUT-003**: PostgreSQL event store.
- **VC-FUT-004**: Vector database integration.

**Status**: Deferred.

**Reason**: SQLite provides the complete local MVP and judge path.

## Plugin Ecosystem

### VC-FUT-005 — Full Python Entry-Point Package Ecosystem

**Status**: Partially deferred.

**Hackathon treatment**: Define stable detector boundaries and implement
detector entry-point discovery with one small reference plugin only if the core
vertical slice remains healthy. Do not publish a collection of packages.

## Additional Agent Integrations

- **VC-FUT-006**: LangChain adapter.
- **VC-FUT-007**: AutoGen adapter.
- **VC-FUT-008**: CrewAI adapter.
- **VC-FUT-009**: Claude Code adapter.
- **VC-FUT-010**: Cursor adapter.

**Status**: Deferred.

**Reason**: The hackathon product is Codex-first.

## Local Semantic Models

- **VC-FUT-011**: ONNX local semantic detector.
- **VC-FUT-012**: Model packaging, downloading, updating, and device selection.

**Status**: Deferred.

**Reason**: GPT-5.6 provides the hackathon semantic path. Local inference needs
separate model provenance, update, resource, and failure design.

## Remote Policy and Fleet Administration

- **VC-FUT-013**: Remote policy control plane.
- **VC-FUT-014**: Signed remote policy bundles.
- **VC-FUT-015**: Fleet-wide policy rollout and rollback.

**Status**: Deferred.

**Reason**: Remote policy delivery is a privileged security surface requiring
identity, enrollment, rollback, and tenant isolation.

## Observability Ecosystem

### VC-FUT-016 — Full OpenTelemetry SDK and Exporters

**Status**: Partially deferred.

**Hackathon treatment**: Instrument the core with privacy-safe span and metric
interfaces. Do not build a full exporter ecosystem.

### VC-FUT-017 — SIEM-Specific Integrations

**Status**: Deferred.

## Enterprise Access Control

- **VC-FUT-018**: Multi-tenant administration.
- **VC-FUT-019**: Enterprise identity, SSO, and RBAC.

**Status**: Deferred.

## Cryptographic Hardening

- **VC-FUT-020**: Hardware-backed signing keys.
- **VC-FUT-021**: Production key rotation, recovery, enrollment, and revocation.
- **VC-FUT-022**: Distributed or replicated ledgers.
- **VC-FUT-023**: Merkle checkpoints and external transparency anchoring.

**Status**: Deferred.

**Hackathon treatment**: Use a local Ed25519 installation key and hash-chained
events. Clearly document the local-host threat boundary.

## Governance and Compliance

- **VC-FUT-024**: Long-term retention administration.
- **VC-FUT-025**: Enterprise compliance mappings.
- **VC-FUT-026**: Policy-authoring IDE extension.

**Status**: Deferred.

**Hackathon treatment**: Generate JSON Schema for policies so existing editors
can provide completion and diagnostics.

## Managed Commercial Platform

- **VC-FUT-027**: Managed Verity control plane.
- **VC-FUT-028**: Managed detector marketplace.
- **VC-FUT-029**: Cross-host memory federation.
- **VC-FUT-030**: Advanced factual verification and external evidence
  reconciliation.

**Status**: Deferred.

## Promotion Rule

A deferred capability becomes active only after receiving:

1. Its own numbered Spec Kit feature
2. Prioritized user stories
3. Independent acceptance tests
4. A constitution-compliant plan
5. A generated task graph
6. A milestone
7. An explicit scope decision confirming the current critical path remains
   protected
