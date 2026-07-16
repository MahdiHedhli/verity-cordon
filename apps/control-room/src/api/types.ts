export type Action = "allow" | "redact" | "quarantine" | "block";
export type Mode = "enforce" | "shadow";
export type MemoryStatus =
  | "active"
  | "quarantined"
  | "blocked"
  | "redacted"
  | "revoked"
  | "superseded"
  | "expired";
export type MemoryKind =
  | "fact"
  | "user_preference"
  | "project_convention"
  | "operational_instruction"
  | "tool_observation"
  | "task_summary"
  | "identity_assertion"
  | "policy_statement"
  | "credential_material"
  | "unknown";
export type SourceClass =
  | "user_input"
  | "tool_output"
  | "agent_output"
  | "imported_file"
  | "prior_memory"
  | "compaction"
  | "session_summary"
  | "external_event";
export type SemanticProviderState =
  | "live_openai"
  | "live_codex_subscription"
  | "recorded_fixture"
  | "deterministic_only"
  | "failed"
  | "not_required";
export type ProviderIsolation =
  | "tool_free_api"
  | "agentic_sandboxed"
  | "recorded_fixture"
  | "local_deterministic"
  | "failed";

export interface PolicySummary {
  policy_id: string;
  version: string;
  mode: Mode;
  digest: string;
  validation_state: "valid" | "invalid" | "last_known_good";
}

export interface DecisionCounts {
  total_candidates: number;
  allowed: number;
  redacted: number;
  quarantined: number;
  blocked: number;
  revoked: number;
}

export interface StatusResponse {
  schema_version: "1.0.0";
  daemon: "healthy" | "degraded" | "read_only" | "unavailable";
  mode: Mode;
  policy: PolicySummary;
  ledger: "verified" | "unverified" | "invalid" | "unavailable";
  memory_view: "consistent" | "stale" | "rebuilding" | "unavailable";
  semantic_provider: SemanticProviderState;
  semantic_provider_isolation: ProviderIsolation;
  semantic_provider_ready: boolean;
  semantic_provider_failure_class: string | null;
  counts: DecisionCounts;
}

export interface StatisticsResponse {
  schema_version: "1.0.0";
  counts: DecisionCounts;
  semantic_timeouts: number;
  detector_failures: number;
  average_evaluation_latency_ms: number;
  ledger_state: StatusResponse["ledger"];
}

export interface ControlRoomChallenge {
  schema_version: "1.0.0";
  challenge_id: string;
  nonce: string;
  salt: string;
  kdf: "PBKDF2-HMAC-SHA256";
  iterations: 310000;
  expires_at: string;
}

export interface ControlRoomSession {
  schema_version: "1.0.0";
  csrf_token: string;
  expires_at: string;
}

export interface CandidateSummary {
  candidate_id: string;
  safe_statement: string;
  namespace: string;
  kind: MemoryKind;
  source_class: SourceClass;
  session_id: string;
  status: MemoryStatus;
  actual_action: Action;
  would_have_action: Action;
  shadow_mode: boolean;
  policy_version: string;
  semantic_provider: SemanticProviderState;
  created_at: string;
}

export interface SourceReference {
  evidence_id: string;
  evidence_digest: string;
}

export interface MemoryCandidate {
  schema_version: "1.0.0";
  candidate_id: string;
  namespace: string;
  kind: MemoryKind;
  statement: string;
  source_class: SourceClass;
  source_refs: SourceReference[];
  session_id: string;
  task_id: string | null;
  confidence: number;
  durability_rationale: string;
  sensitivity: "public" | "internal" | "sensitive" | "restricted" | "credential";
  requested_ttl_seconds: number | null;
  persistence_requested: boolean;
  authority_signal: "none" | "implied" | "explicit" | "unknown";
  secrecy_signal: "none" | "implied" | "explicit" | "unknown";
  contains_redactions: boolean;
  extractor_provider:
    | "live_openai"
    | "live_codex_subscription"
    | "recorded_fixture"
    | "deterministic";
  extractor_version: string;
  content_digest: string;
  created_at: string;
}

export interface DetectorResult {
  schema_version: "1.0.0";
  result_id: string;
  candidate_id: string;
  detector_id: string;
  detector_version: string;
  execution_order: number;
  status: "ok" | "timeout" | "error" | "cancelled" | "malformed";
  matched: boolean | null;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: number;
  categories: string[];
  message: string;
  evidence_offsets: Array<{ source_ref: string; start: number; end: number }>;
  metadata: Record<string, string | number | boolean | null>;
  failure_class: string | null;
  latency_ms: number;
  recorded_at: string;
}

export interface SemanticAssessment {
  schema_version: "1.0.0";
  assessment_id: string;
  candidate_id: string;
  provider_state: "live_openai" | "live_codex_subscription" | "recorded_fixture" | "failed";
  requested_provider?: "fixture" | "openai" | "codex_subscription" | null;
  requested_model: string | null;
  returned_model: string | null;
  prompt_version: string;
  risk_score: number | null;
  categories: string[];
  persistence_intent: "none" | "implicit" | "explicit" | "unknown";
  authority_claim: "none" | "implied" | "explicit" | "unknown";
  exfiltration_risk: number | null;
  tool_hijack_risk: number | null;
  cross_task_risk: number | null;
  secret_risk: number | null;
  rationale: string | null;
  recommended_disposition: Action | null;
  sanitized_content_digest: string;
  cache_hit: boolean;
  latency_ms: number;
  failure: { class: string; retryable: boolean } | null;
  assessed_at: string;
}

export interface PolicyDecision {
  policy_id: string;
  policy_version: string;
  matched_rule_id: string | null;
  mode: Mode;
  actual_action: Action;
  would_have_action: Action;
  shadow_mode: boolean;
  reason: string;
}

export interface CandidateEventReference {
  event_id: string;
  sequence_number: number;
  event_type: string;
  occurred_at: string;
}

export interface CandidateDetail {
  candidate: MemoryCandidate;
  status: MemoryStatus;
  detector_results: DetectorResult[];
  semantic_assessment: SemanticAssessment | null;
  policy_decision: PolicyDecision;
  event_ids: string[];
  event_references: CandidateEventReference[];
  ledger_verified: boolean;
}

export interface MemoryRecord {
  memory_id: string;
  commit_event_id: string;
  candidate_id: string;
  session_id: string;
  safe_statement: string;
  namespace: string;
  kind: MemoryKind;
  source_class: SourceClass;
  status: Exclude<MemoryStatus, "quarantined" | "blocked">;
  trust_decision: "allowed" | "redacted" | "manually_approved" | "shadow_admitted";
  policy_id: string;
  policy_version: string;
  actual_action: Action;
  would_have_action: Action;
  committed_at: string;
  expires_at: string | null;
  shadow_admitted: boolean;
  manual_approval_event_id: string | null;
  risk_categories: string[];
  semantic_provider: SemanticProviderState;
  last_event_id: string;
  last_event_sequence: number;
}

export interface EventSummary {
  event_id: string;
  sequence_number: number;
  event_type: string;
  occurred_at: string;
  memory_id: string | null;
  source_class: SourceClass | null;
  action: Action | null;
  policy_version: string | null;
  event_hash: string;
  chain_status: "verified" | "unverified" | "invalid";
}

export interface PageResponse<T> {
  items: T[];
  next_cursor: string | null;
}

export interface RevocationPreview {
  memory_id: string;
  current_status: MemoryStatus;
  would_remove_from_active_view: boolean;
  unrelated_active_memories_preserved: number;
  resulting_active_count: number;
}

export interface RebuildResponse {
  dry_run: boolean;
  events_replayed: number;
  active_count: number;
  quarantined_count: number;
  differences_found: number;
  view_consistent: boolean;
  ledger_verified: boolean;
}

export interface TrustActionResponse {
  event_id: string;
  candidate_id: string;
  memory_id: string | null;
  status: MemoryStatus;
  ledger_verified: boolean;
  view_consistent: boolean;
}

export interface ActivePolicyResponse {
  summary: PolicySummary;
  policy: Record<string, unknown> & { mode: Mode; rules?: unknown[] };
}

export interface LedgerVerificationResponse {
  verified: boolean;
  completeness_state: "anchored_complete" | "tail_unproven" | "invalid";
  expected_head_source: "local_sidecar" | "supplied_checkpoint" | "none";
  expected_head_sequence: number | null;
  observed_head_sequence: number | null;
  total_events: number;
  first_invalid_event_id: string | null;
  failure_class: string | null;
  signing_key_id: string;
  public_key_fingerprint: string;
  materialized_view_consistent: boolean;
  verified_at: string;
}

export interface PublicKeyResponse {
  algorithm: "Ed25519";
  signing_key_id: string;
  public_key_base64: string;
  fingerprint_sha256: string;
}
