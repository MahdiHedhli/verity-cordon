import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Outlet, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { jsonResponse, quarantinedCandidate, requestBodyText, requestUrl } from "../test/fixtures";
import { TestProviders } from "../test/TestProviders";
import { QuarantinePage } from "./QuarantinePage";

function OutletHost(): React.JSX.Element {
  return <Outlet context={{ requestUnlock: vi.fn() }} />;
}

describe("QuarantinePage", () => {
  it("requires a reason and sends an authenticated confirmed approval", async () => {
    const fetchMock = vi.fn<typeof fetch>((input, init) => {
      const url = requestUrl(input);
      if (url.includes("/review") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({
          event_id: "event-00000004",
          candidate_id: quarantinedCandidate.candidate_id,
          memory_id: "memory-00000002",
          status: "active",
          ledger_verified: true,
          view_consistent: true,
        }));
      }
      if (url.includes("/candidates")) {
        return Promise.resolve(jsonResponse({ items: [quarantinedCandidate], next_cursor: null }));
      }
      return Promise.resolve(jsonResponse({}, 404));
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(
      <TestProviders>
        <Routes>
          <Route element={<OutletHost />}>
            <Route element={<QuarantinePage />} index />
          </Route>
        </Routes>
      </TestProviders>,
    );

    expect(await screen.findByText(quarantinedCandidate.safe_statement)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Approve" }));
    await user.type(screen.getByLabelText("Reason"), "Reviewed against the synthetic demonstration provenance.");
    await user.click(screen.getByRole("button", { name: "Approve candidate" }));

    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([url, init]) => requestUrl(url).includes("/review") && init?.method === "POST")).toBe(true);
    });
    const reviewCall = fetchMock.mock.calls.find(([url]) => requestUrl(url).includes("/review"));
    const headers = reviewCall?.[1]?.headers as Headers;
    expect(headers.get("X-Verity-CSRF")).toBe("synthetic-csrf-value-for-tests-only");
    expect(headers.get("Idempotency-Key")).toMatch(/^candidate-review:/u);
    expect(JSON.parse(requestBodyText(reviewCall?.[1]?.body))).toMatchObject({
      actor_id: "control-room.operator",
      confirmed: true,
      disposition: "approve",
    });
  });
});
