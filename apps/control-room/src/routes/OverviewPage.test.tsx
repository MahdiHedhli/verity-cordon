import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { jsonResponse, requestUrl, safeEvent, safeMemory, safeStatistics, safeStatus } from "../test/fixtures";
import { TestProviders } from "../test/TestProviders";
import { OverviewPage } from "./OverviewPage";

describe("OverviewPage", () => {
  it("renders health, metrics, and recent signed events", async () => {
    vi.stubGlobal("fetch", vi.fn<typeof fetch>((input) => {
      const url = requestUrl(input);
      if (url.endsWith("/status")) return Promise.resolve(jsonResponse(safeStatus));
      if (url.endsWith("/statistics")) return Promise.resolve(jsonResponse(safeStatistics));
      if (url.includes("/events")) return Promise.resolve(jsonResponse({ items: [safeEvent], next_cursor: null }));
      if (url.includes("/memories")) return Promise.resolve(jsonResponse({ items: [safeMemory], next_cursor: null }));
      return Promise.resolve(jsonResponse({}, 404));
    }));

    render(<TestProviders><OverviewPage /></TestProviders>);

    expect(await screen.findByRole("heading", { name: "Memory is explicit here." })).toBeVisible();
    expect(screen.getByText("18 ms")).toBeVisible();
    expect(screen.getByText("Memory Committed")).toBeVisible();
    expect(screen.getAllByText("verified").length).toBeGreaterThan(0);
  });
});
