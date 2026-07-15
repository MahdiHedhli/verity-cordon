import { useCallback, useEffect, useMemo, useState, type PropsWithChildren } from "react";
import { api } from "../api/client";
import { AuthContext } from "./AuthContext";
import { deriveChallengeProof } from "./crypto";

export function AuthProvider({ children }: PropsWithChildren): React.JSX.Element {
  const [csrfToken, setCsrfToken] = useState<string | null>(null);
  const [sessionExpiresAt, setSessionExpiresAt] = useState<string | null>(null);

  const lock = useCallback(() => {
    setCsrfToken(null);
    setSessionExpiresAt(null);
  }, []);

  useEffect(() => {
    if (!sessionExpiresAt) {
      return undefined;
    }
    const parsedExpiry = Date.parse(sessionExpiresAt);
    const delay = Number.isFinite(parsedExpiry)
      ? Math.min(15 * 60_000, Math.max(0, parsedExpiry - Date.now()))
      : 0;
    const timeout = window.setTimeout(lock, delay);
    return () => window.clearTimeout(timeout);
  }, [lock, sessionExpiresAt]);

  useEffect(() => {
    window.addEventListener("verity-auth-expired", lock);
    return () => window.removeEventListener("verity-auth-expired", lock);
  }, [lock]);

  const unlock = useCallback(async (passphrase: string) => {
    const challenge = await api.challenge();
    if (Date.parse(challenge.expires_at) <= Date.now()) {
      throw new Error("The local challenge expired. Try again.");
    }
    const proof = await deriveChallengeProof(passphrase, challenge);
    const session = await api.createSession(challenge.challenge_id, proof);
    setCsrfToken(session.csrf_token);
    setSessionExpiresAt(session.expires_at);
  }, []);

  const value = useMemo(
    () => ({
      isUnlocked: csrfToken !== null,
      sessionExpiresAt,
      csrfToken,
      unlock,
      lock,
    }),
    [csrfToken, lock, sessionExpiresAt, unlock],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
