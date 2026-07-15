import { createContext } from "react";

export interface AuthContextValue {
  isUnlocked: boolean;
  sessionExpiresAt: string | null;
  csrfToken: string | null;
  unlock: (passphrase: string) => Promise<void>;
  lock: () => void;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
