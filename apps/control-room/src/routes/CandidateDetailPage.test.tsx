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
});
