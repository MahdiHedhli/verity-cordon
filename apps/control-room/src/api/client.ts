import type {
  ActivePolicyResponse,
  CandidateDetail,
  CandidateSummary,
  ControlRoomChallenge,
  ControlRoomSession,
  EventSummary,
  LedgerVerificationResponse,
  MemoryRecord,
  PageResponse,
  PublicKeyResponse,
  RebuildResponse,
  RevocationPreview,
  StatisticsResponse,
  StatusResponse,
  TrustActionResponse,
} from "./types";

const API_ROOT = "/api/v1";
const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

const statusMessages: Record<number, string> = {
  400: "The request was not accepted.",
  401: "Operator actions are locked. Unlock this browser session and try again.",
  403: "The local security check rejected this request.",
  404: "The requested record is no longer available.",
  409: "The record changed. Refresh before trying again.",
  413: "The request exceeds the active safety limit.",
  422: "The request does not meet the active policy contract.",
  429: "Too many attempts. Wait before trying again.",
  503: "A required local safety service is unavailable.",
};

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number) {
    super(statusMessages[status] ?? "The local daemon returned an unexpected response.");
    this.name = "ApiError";
    this.status = status;
  }
}

interface RequestOptions {
  method?: "GET" | "POST";
  body?: unknown;
  csrfToken?: string | null;
  idempotencyKey?: string;
  signal?: AbortSignal | undefined;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers = new Headers({ Accept: "application/json" });

  if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  if (MUTATING_METHODS.has(method) && options.csrfToken) {
    headers.set("X-Verity-CSRF", options.csrfToken);
  }
  if (options.idempotencyKey) {
    headers.set("Idempotency-Key", options.idempotencyKey);
  }

  const requestInit: RequestInit = {
    method,
    headers,
    credentials: "same-origin",
  };
  if (options.body !== undefined) requestInit.body = JSON.stringify(options.body);
  if (options.signal) requestInit.signal = options.signal;

  const response = await fetch(`${API_ROOT}${path}`, requestInit);

  if (!response.ok) {
    if (response.status === 401) {
      window.dispatchEvent(new Event("verity-auth-expired"));
    }
    throw new ApiError(response.status);
  }

  return (await response.json()) as T;
}

export function createIdempotencyKey(scope: string): string {
  return `${scope}:${crypto.randomUUID()}`;
}

export const api = {
  status: (signal?: AbortSignal) => request<StatusResponse>("/status", { signal }),
  statistics: (signal?: AbortSignal) =>
    request<StatisticsResponse>("/statistics", { signal }),
  challenge: () =>
    request<ControlRoomChallenge>("/ui/challenge", { method: "POST", body: {} }),
  createSession: (challengeId: string, proof: string) =>
    request<ControlRoomSession>("/ui/session", {
      method: "POST",
      body: { challenge_id: challengeId, proof },
    }),
  candidates: (query = "") =>
    request<PageResponse<CandidateSummary>>(`/candidates${query ? `?${query}` : ""}`),
  candidate: (candidateId: string) =>
    request<CandidateDetail>(`/candidates/${encodeURIComponent(candidateId)}`),
  reviewCandidate: (
    candidateId: string,
    body: {
      actor_id: string;
      reason: string;
      confirmed: true;
      disposition: "approve" | "block" | "leave_quarantined";
    },
    csrfToken: string,
  ) =>
    request<TrustActionResponse>(
      `/candidates/${encodeURIComponent(candidateId)}/review`,
      {
        method: "POST",
        body,
        csrfToken,
        idempotencyKey: createIdempotencyKey("candidate-review"),
      },
    ),
  memories: (query = "") =>
    request<PageResponse<MemoryRecord>>(`/memories${query ? `?${query}` : ""}`),
  events: (query = "") =>
    request<PageResponse<EventSummary>>(`/events${query ? `?${query}` : ""}`),
  previewRevocation: (memoryId: string, csrfToken: string) =>
    request<RevocationPreview>(
      `/memories/${encodeURIComponent(memoryId)}/revoke/preview`,
      { method: "POST", body: {}, csrfToken },
    ),
  revokeMemory: (
    memoryId: string,
    body: { actor_id: string; reason: string; confirmed: true },
    csrfToken: string,
  ) =>
    request<TrustActionResponse>(`/memories/${encodeURIComponent(memoryId)}/revoke`, {
      method: "POST",
      body,
      csrfToken,
      idempotencyKey: createIdempotencyKey("memory-revoke"),
    }),
  rebuildMemory: (csrfToken: string) =>
    request<RebuildResponse>("/memory/rebuild", {
      method: "POST",
      body: { dry_run: false },
      csrfToken,
      idempotencyKey: createIdempotencyKey("memory-rebuild"),
    }),
  activePolicy: () => request<ActivePolicyResponse>("/policies/active"),
  activatePolicy: (
    body: {
      policy: Record<string, unknown>;
      actor_id: string;
      reason: string;
      confirmed: true;
    },
    csrfToken: string,
  ) =>
    request<unknown>("/policies/activate", {
      method: "POST",
      body,
      csrfToken,
      idempotencyKey: createIdempotencyKey("policy-activate"),
    }),
  verifyLedger: (csrfToken: string) =>
    request<LedgerVerificationResponse>("/ledger/verify", {
      method: "POST",
      body: {
        verify_materialized_view: true,
        require_anchored_completeness: true,
      },
      csrfToken,
    }),
  publicKey: () => request<PublicKeyResponse>("/ledger/public-key"),
};
