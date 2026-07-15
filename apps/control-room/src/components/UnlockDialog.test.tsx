import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth/AuthProvider";
import { jsonResponse, requestBodyText } from "../test/fixtures";
import { UnlockDialog } from "./UnlockDialog";

vi.mock("../auth/crypto", () => ({
  deriveChallengeProof: vi.fn().mockResolvedValue("synthetic-one-time-proof-value-0000000000000"),
}));

describe("UnlockDialog", () => {
  it("clears the passphrase and sends only a derived proof", async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({
        schema_version: "1.0.0",
        challenge_id: "challenge-00000001",
        nonce: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
        salt: "AQEBAQEBAQEBAQEBAQEBAQ",
        kdf: "PBKDF2-HMAC-SHA256",
        iterations: 310000,
        expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
      }))
      .mockResolvedValueOnce(jsonResponse({
        schema_version: "1.0.0",
        csrf_token: "synthetic-csrf-value-for-tests-only",
        expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
      }, 201));
    vi.stubGlobal("fetch", fetchMock);
    const onClose = vi.fn();
    const user = userEvent.setup();

    render(
      <AuthProvider>
        <UnlockDialog onClose={onClose} open />
      </AuthProvider>,
    );

    const passphrase = screen.getByLabelText<HTMLInputElement>("Control Room passphrase");
    await user.type(passphrase, "SYNTHETIC_TEST_ONLY_VALUE");
    await user.click(screen.getByRole("button", { name: "Unlock actions" }));

    await waitFor(() => expect(onClose).toHaveBeenCalledOnce());
    expect(passphrase).toHaveValue("");
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const sessionCall = fetchMock.mock.calls[1];
    expect(sessionCall).toBeDefined();
    const requestBody = requestBodyText(sessionCall?.[1]?.body);
    expect(requestBody).toContain("synthetic-one-time-proof");
    expect(requestBody).not.toContain("SYNTHETIC_TEST_ONLY_VALUE");
    expect(sessionCall?.[1]?.credentials).toBe("same-origin");
  });

  it("clears the passphrase after a rejected proof", async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({
        schema_version: "1.0.0",
        challenge_id: "challenge-00000002",
        nonce: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
        salt: "AQEBAQEBAQEBAQEBAQEBAQ",
        kdf: "PBKDF2-HMAC-SHA256",
        iterations: 310000,
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      }))
      .mockResolvedValueOnce(jsonResponse({}, 403));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(
      <AuthProvider>
        <UnlockDialog onClose={vi.fn()} open />
      </AuthProvider>,
    );

    const passphrase = screen.getByLabelText<HTMLInputElement>("Control Room passphrase");
    await user.type(passphrase, "SYNTHETIC_TEST_ONLY_VALUE");
    await user.click(screen.getByRole("button", { name: "Unlock actions" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("local security check rejected");
    expect(passphrase).toHaveValue("");
  });
});
