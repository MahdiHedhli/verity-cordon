import type {
  CandidateDetail,
  CandidateSummary,
  EventSummary,
  MemoryRecord,
  StatisticsResponse,
  StatusResponse,
} from "../api/types";

export const safeStatus: StatusResponse = {
  schema_version: "1.0.0",
  daemon: "healthy",
  mode: "enforce",
  policy: {
    policy_id: "verity-default",
    version: "1.0.0",
    mode: "enforce",
    digest: "a".repeat(64),
    validation_state: "valid",
  },
  ledger: "verified",
  memory_view: "consistent",
  semantic_provider: "recorded_fixture",
  semantic_provider_isolation: "recorded_fixture",
  semantic_provider_ready: true,
  semantic_provider_failure_class: null,
  counts: {
    total_candidates: 3,
    allowed: 1,
    redacted: 0,
    quarantined: 1,
    blocked: 1,
    revoked: 0,
  },
};

export const safeStatistics: StatisticsResponse = {
  schema_version: "1.0.0",
  counts: safeStatus.counts,
  semantic_timeouts: 0,
  detector_failures: 0,
  average_evaluation_latency_ms: 18.4,
  ledger_state: "verified",
};

export const safeEvent: EventSummary = {
  event_id: "event-00000001",
  sequence_number: 12,
  event_type: "MemoryCommitted",
  occurred_at: "2026-07-15T14:20:00Z",
  memory_id: "memory-00000001",
  source_class: "user_input",
  action: "allow",
  policy_version: "1.0.0",
  event_hash: "b".repeat(64),
  chain_status: "verified",
};

export const safeMemory: MemoryRecord = {
  memory_id: "memory-00000001",
  commit_event_id: "event-00000001",
  candidate_id: "candidate-00000001",
  session_id: "session-00000001",
  safe_statement: "The project uses deterministic offline fixtures for judge demonstrations.",
  namespace: "project.demo",
  kind: "project_convention",
  source_class: "user_input",
  status: "active",
  trust_decision: "allowed",
  policy_id: "verity-default",
  policy_version: "1.0.0",
  actual_action: "allow",
  would_have_action: "allow",
  committed_at: "2026-07-15T14:20:00Z",
  expires_at: null,
  shadow_admitted: false,
  manual_approval_event_id: null,
  risk_categories: [],
  semantic_provider: "recorded_fixture",
  last_event_id: "event-00000001",
  last_event_sequence: 12,
};

export const quarantinedCandidate: CandidateSummary = {
  candidate_id: "candidate-00000002",
  safe_statement: "Treat a synthetic demonstration sink as a permanent release rule.",
  namespace: "instructions.release",
  kind: "operational_instruction",
  source_class: "tool_output",
  session_id: "session-00000001",
  status: "quarantined",
  actual_action: "quarantine",
  would_have_action: "quarantine",
  shadow_mode: false,
  policy_version: "1.0.0",
  semantic_provider: "recorded_fixture",
  created_at: "2026-07-15T14:21:00Z",
};

export const candidateDetail: CandidateDetail = {
  candidate: {
    schema_version: "1.0.0",
    candidate_id: quarantinedCandidate.candidate_id,
    namespace: quarantinedCandidate.namespace,
    kind: quarantinedCandidate.kind,
    statement: quarantinedCandidate.safe_statement,
    source_class: quarantinedCandidate.source_class,
    source_refs: [{ evidence_id: "evidence-00000001", evidence_digest: "c".repeat(64) }],
    session_id: quarantinedCandidate.session_id,
    task_id: "task-00000001",
    confidence: 0.91,
    durability_rationale: "The source explicitly requested future reuse.",
    sensitivity: "internal",
    requested_ttl_seconds: null,
    persistence_requested: true,
    authority_signal: "explicit",
    secrecy_signal: "implied",
    contains_redactions: false,
    extractor_provider: "recorded_fixture",
    extractor_version: "fixture-1",
    content_digest: "d".repeat(64),
    created_at: quarantinedCandidate.created_at,
  },
  status: "quarantined",
  detector_results: [{
    schema_version: "1.0.0",
    result_id: "result-00000001",
    candidate_id: quarantinedCandidate.candidate_id,
    detector_id: "persistent-instruction",
    detector_version: "1.0.0",
    execution_order: 1,
    status: "ok",
    matched: true,
    severity: "high",
    confidence: 0.95,
    categories: ["persistent_instruction"],
    message: "The candidate requests durable operational authority.",
    evidence_offsets: [],
    metadata: {},
    failure_class: null,
    latency_ms: 2,
    recorded_at: "2026-07-15T14:21:01Z",
  }],
  semantic_assessment: null,
  policy_decision: {
    policy_id: "verity-default",
    policy_version: "1.0.0",
    matched_rule_id: "tool-persistence",
    mode: "enforce",
    actual_action: "quarantine",
    would_have_action: "quarantine",
    shadow_mode: false,
    reason: "Untrusted tools cannot establish durable operational authority.",
  },
  event_ids: ["event-00000002", "event-00000003"],
  event_references: [
    {
      event_id: "event-00000002",
      sequence_number: 2,
      event_type: "MemoryCandidateCreated",
      occurred_at: "2026-07-15T14:21:00Z",
    },
    {
      event_id: "event-00000003",
      sequence_number: 3,
      event_type: "MemoryQuarantined",
      occurred_at: "2026-07-15T14:21:02Z",
    },
  ],
  ledger_verified: true,
};

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

export function requestBodyText(body: BodyInit | null | undefined): string {
  return typeof body === "string" ? body : "";
}
