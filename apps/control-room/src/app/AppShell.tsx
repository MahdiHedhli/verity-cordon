import { useQuery } from "@tanstack/react-query";
import {
  BookKey,
  Boxes,
  CheckCircle2,
  Clock3,
  FileKey2,
  Gauge,
  KeyRound,
  LockKeyhole,
  OctagonX,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { Button } from "../components/Button";
import { StatusPill } from "../components/StatusPill";
import { UnlockDialog } from "../components/UnlockDialog";

const navigation: ReadonlyArray<{ to: string; label: string; icon: LucideIcon; end?: boolean }> = [
  { to: "/", label: "Overview", icon: Gauge, end: true },
  { to: "/memories", label: "Memory inventory", icon: Boxes },
  { to: "/events", label: "Event timeline", icon: Clock3 },
  { to: "/quarantine", label: "Quarantine", icon: OctagonX },
  { to: "/revocation", label: "Revocation", icon: BookKey },
  { to: "/policies", label: "Policies", icon: FileKey2 },
  { to: "/ledger", label: "Ledger verification", icon: CheckCircle2 },
] as const;

export function AppShell(): React.JSX.Element {
  const [unlockOpen, setUnlockOpen] = useState(false);
  const { isUnlocked, lock, sessionExpiresAt } = useAuth();
  const statusQuery = useQuery({
    queryKey: ["status"],
    queryFn: ({ signal }) => api.status(signal),
    refetchInterval: 15_000,
  });

  return (
    <div className="app-frame">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand__mark" aria-hidden="true"><ShieldCheck size={24} /></span>
          <span>
            <strong>Verity Cordon</strong>
            <small>Memory Control Room</small>
          </span>
        </div>

        <nav aria-label="Control Room">
          {navigation.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              className={({ isActive }) => `nav-link ${isActive ? "nav-link--active" : ""}`}
              key={to}
              to={to}
              {...(end === undefined ? {} : { end })}
            >
              <Icon aria-hidden="true" size={18} strokeWidth={1.8} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar__security">
          <p className="eyebrow">Trust boundary</p>
          <div className="sidebar__state">
            <span>Daemon</span>
            <StatusPill value={statusQuery.data?.daemon ?? "unavailable"} />
          </div>
          <div className="sidebar__state">
            <span>Mode</span>
            <StatusPill value={statusQuery.data?.mode ?? "unknown"} />
          </div>
          <div className="sidebar__state">
            <span>Ledger</span>
            <StatusPill value={statusQuery.data?.ledger ?? "unavailable"} />
          </div>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div className="topbar__boundary" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <div className="topbar__session">
            {isUnlocked ? (
              <>
                <span className="session-state">
                  <KeyRound aria-hidden="true" size={15} />
                  Actions unlocked
                  {sessionExpiresAt ? (
                    <span className="sr-only"> until {new Date(sessionExpiresAt).toLocaleTimeString()}</span>
                  ) : null}
                </span>
                <Button onClick={lock} size="small" variant="quiet">Lock</Button>
              </>
            ) : (
              <Button onClick={() => setUnlockOpen(true)} size="small" variant="secondary">
                <LockKeyhole aria-hidden="true" size={15} />
                Unlock actions
              </Button>
            )}
          </div>
        </header>
        <main id="main-content" tabIndex={-1}>
          <Outlet context={{ requestUnlock: () => setUnlockOpen(true) }} />
        </main>
        <footer>
          <span>Local control plane · loopback only</span>
          <span>Verifiable memory. Revocable trust.</span>
        </footer>
      </div>
      <UnlockDialog open={unlockOpen} onClose={() => setUnlockOpen(false)} />
    </div>
  );
}

export interface AppOutletContext {
  requestUnlock: () => void;
}
