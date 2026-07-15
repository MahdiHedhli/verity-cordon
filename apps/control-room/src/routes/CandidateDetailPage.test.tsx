import { render, screen } from "@testing-library/react";
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
});
