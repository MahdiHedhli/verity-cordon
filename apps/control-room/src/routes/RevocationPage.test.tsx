import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Outlet, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { jsonResponse, requestBodyText, requestUrl, safeMemory } from "../test/fixtures";
import { TestProviders } from "../test/TestProviders";
import { RevocationPage } from "./RevocationPage";

function OutletHost(): React.JSX.Element {
  return <Outlet context={{ requestUnlock: vi.fn() }} />;
}

describe("RevocationPage", () => {
  it("previews impact before submitting a reasoned revocation", async () => {
    const fetchMock = vi.fn<typeof fetch>((input, init) => {
      const url = requestUrl(input);
      if (url.endsWith("/revoke/preview")) {
        return Promise.resolve(jsonResponse({
          memory_id: safeMemory.memory_id,
          current_status: "active",
          would_remove_from_active_view: true,
          unrelated_active_memories_preserved: 2,
          resulting_active_count: 2,
        }));
      }
      if (url.endsWith("/revoke") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({
          event_id: "event-00000005",
          candidate_id: safeMemory.candidate_id,
          memory_id: safeMemory.memory_id,
          status: "revoked",
          ledger_verified: true,
          view_consistent: true,
        }));
      }
      if (url.endsWith("/memory/rebuild") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({
          dry_run: false,
          events_replayed: 14,
          active_count: 2,
          quarantined_count: 1,
          differences_found: 0,
          view_consistent: true,
          ledger_verified: true,
        }));
      }
      if (url.includes("/memories")) {
        return Promise.resolve(jsonResponse({ items: [safeMemory], next_cursor: null }));
      }
      return Promise.resolve(jsonResponse({}, 404));
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(
      <TestProviders>
        <Routes>
          <Route element={<OutletHost />}>
            <Route element={<RevocationPage />} index />
          </Route>
        </Routes>
      </TestProviders>,
    );

    await user.click(await screen.findByRole("button", { name: "Preview revocation" }));
    expect(await screen.findByText("Unrelated memories preserved")).toBeVisible();
    expect(screen.getAllByText("2", { selector: "dd" })).toHaveLength(2);
    await user.type(screen.getByLabelText("Reason"), "The source event was reclassified during the synthetic evaluation.");
    await user.click(screen.getByRole("button", { name: "Revoke and replay" }));

    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([url]) => requestUrl(url).endsWith("/revoke"))).toBe(true);
    });
    const revokeCall = fetchMock.mock.calls.find(([url]) => requestUrl(url).endsWith("/revoke"));
    expect(JSON.parse(requestBodyText(revokeCall?.[1]?.body))).toMatchObject({
      actor_id: "control-room.operator",
      confirmed: true,
    });
    expect(fetchMock.mock.calls.some(([url]) => requestUrl(url).endsWith("/memory/rebuild"))).toBe(true);
  });
});
