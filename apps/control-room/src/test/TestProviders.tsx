import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { PropsWithChildren } from "react";
import { MemoryRouter } from "react-router-dom";
import { AuthContext, type AuthContextValue } from "../auth/AuthContext";

export const unlockedAuth: AuthContextValue = {
  isUnlocked: true,
  sessionExpiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
  csrfToken: "synthetic-csrf-value-for-tests-only",
  unlock: () => Promise.resolve(),
  lock: () => undefined,
};

interface TestProvidersProps extends PropsWithChildren {
  auth?: AuthContextValue;
  initialEntries?: string[];
}

export function TestProviders({
  auth = unlockedAuth,
  children,
  initialEntries = ["/"],
}: TestProvidersProps): React.JSX.Element {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return (
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>
  );
}
