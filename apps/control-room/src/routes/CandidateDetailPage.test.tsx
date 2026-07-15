import { render, screen, within } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { candidateDetail, jsonResponse } from "../test/fixtures";
import { TestProviders } from "../test/TestProviders";
import { CandidateDetailPage } from "./CandidateDetailPage";

describe("CandidateDetailPage", () => {
  it("renders untrusted candidate text without interpreting markup", async () => {
    const unsafeLookingText = "<img src=x onerror=synthetic_demo_only>";
    vi.stubGlobal("fetch", vi.fn<typeof fetch>(() => Promise.resolve(jsonResponse({
      ...candidateDetail,
      candidate: { ...candidateDetail.candidate, statement: unsafeLookingText },
    }))));

    const { container } = render(
      <TestProviders initialEntries={[`/candidates/${candidateDetail.candidate.candidate_id}`]}>
        <Routes>
          <Route element={<CandidateDetailPage />} path="/candidates/:candidateId" />
        </Routes>
      </TestProviders>,
    );

    expect(await screen.findByText(unsafeLookingText)).toBeVisible();
    expect(container.querySelector("img")).not.toBeInTheDocument();
    expect(screen.getByText("Untrusted tools cannot establish durable operational authority.")).toBeVisible();
    expect(screen.getByRole("region", { name: "Decision and recovery timeline" })).toBeVisible();
    expect(screen.queryByText("Delayed attack timeline")).not.toBeInTheDocument();
    expect(screen.queryByText("Delayed-task exposure")).not.toBeInTheDocument();
  });

  it("shows the subscription provider identity and reduced-isolation boundary", async () => {
    vi.stubGlobal("fetch", vi.fn<typeof fetch>(() => Promise.resolve(jsonResponse({
      ...candidateDetail,
      candidate: {
        ...candidateDetail.candidate,
        extractor_provider: "live_codex_subscription",
      },
      semantic_assessment: {
        schema_version: "1.0.0",
        assessment_id: "assessment-subscription-0001",
        candidate_id: candidateDetail.candidate.candidate_id,
        provider_state: "live_codex_subscription",
        requested_model: "gpt-5.6",
        returned_model: null,
        prompt_version: "codex-subscription-risk-v1",
        risk_score: 0.92,
        categories: ["persistent_instruction"],
        persistence_intent: "explicit",
        authority_claim: "explicit",
        exfiltration_risk: 0.8,
        tool_hijack_risk: 0.9,
        cross_task_risk: 0.85,
        secret_risk: 0.1,
        rationale: "The tool output requests concealed durable authority.",
        recommended_disposition: "quarantine",
        sanitized_content_digest: "e".repeat(64),
        cache_hit: false,
        latency_ms: 48,
        failure: null,
        assessed_at: "2026-07-15T14:21:02Z",
      },
    }))));

    render(
      <TestProviders initialEntries={[`/candidates/${candidateDetail.candidate.candidate_id}`]}>
        <Routes>
          <Route element={<CandidateDetailPage />} path="/candidates/:candidateId" />
        </Routes>
      </TestProviders>,
    );

    expect(await screen.findAllByText(/live codex subscription/i)).not.toHaveLength(0);
    expect(screen.getByText(/lower-isolation agentic provider/i)).toBeVisible();
    expect(screen.getByText(/agentic_sandboxed/i)).toBeVisible();
    expect(screen.getByText(/tool activity invalidates the result/i)).toBeVisible();
  });

  it("shows shadow admission and selective revocation as a delayed-attack timeline", async () => {
    const eventReferences = [
      {
        event_id: "019f0000-0000-7000-8000-000000000001",
        sequence_number: 21,
        event_type: "MemoryCandidateCreated",
        occurred_at: "2026-07-15T14:21:00Z",
      },
      {
        event_id: "019f0000-0000-7000-8000-000000000002",
        sequence_number: 25,
        event_type: "MemoryCommitted",
        occurred_at: "2026-07-15T14:21:02Z",
      },
      {
        event_id: "019f0000-0000-7000-8000-000000000003",
        sequence_number: 31,
        event_type: "MemoryRevoked",
        occurred_at: "2026-07-15T14:22:00Z",
      },
    ];
    vi.stubGlobal("fetch", vi.fn<typeof fetch>(() => Promise.resolve(jsonResponse({
      ...candidateDetail,
      status: "revoked",
      policy_decision: {
        ...candidateDetail.policy_decision,
        mode: "shadow",
        actual_action: "allow",
        would_have_action: "quarantine",
        shadow_mode: true,
      },
      event_ids: eventReferences.map((event) => event.event_id),
      event_references: eventReferences,
      ledger_verified: true,
    }))));

    render(
      <TestProviders initialEntries={[`/candidates/${candidateDetail.candidate.candidate_id}`]}>
        <Routes>
          <Route element={<CandidateDetailPage />} path="/candidates/:candidateId" />
        </Routes>
      </TestProviders>,
    );

    const timeline = await screen.findByRole("region", { name: "Decision and recovery timeline" });
    expect(within(timeline).getByText("Actual action")).toBeVisible();
    expect(within(timeline).getByText("Would-have action")).toBeVisible();
    expect(within(timeline).getByText("allow")).toBeVisible();
    expect(within(timeline).getByText("quarantine")).toBeVisible();
    expect(within(timeline).getByText(/Shadow mode is not active protection/i)).toBeVisible();
    expect(within(timeline).getByText(/delayed influence remained possible/i)).toBeVisible();
    expect(within(timeline).getByText(/revoked and excluded from active memory injection/i)).toBeVisible();
    expect(within(timeline).getByText("Memory Revoked")).toBeVisible();
    expect(within(timeline).getByText(/019f0000-0000-7000-8000-000000000003/)).toBeVisible();
    expect(within(timeline).getByText(/append-only history/i)).toBeVisible();
  });
});
