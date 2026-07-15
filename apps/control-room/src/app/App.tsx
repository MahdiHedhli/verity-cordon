import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { DataState } from "../components/DataState";
import { AppShell } from "./AppShell";

const OverviewPage = lazy(() =>
  import("../routes/OverviewPage").then((module) => ({ default: module.OverviewPage })),
);
const MemoryInventoryPage = lazy(() =>
  import("../routes/MemoryInventoryPage").then((module) => ({ default: module.MemoryInventoryPage })),
);
const EventTimelinePage = lazy(() =>
  import("../routes/EventTimelinePage").then((module) => ({ default: module.EventTimelinePage })),
);
const CandidateDetailPage = lazy(() =>
  import("../routes/CandidateDetailPage").then((module) => ({ default: module.CandidateDetailPage })),
);
const QuarantinePage = lazy(() =>
  import("../routes/QuarantinePage").then((module) => ({ default: module.QuarantinePage })),
);
const RevocationPage = lazy(() =>
  import("../routes/RevocationPage").then((module) => ({ default: module.RevocationPage })),
);
const PoliciesPage = lazy(() =>
  import("../routes/PoliciesPage").then((module) => ({ default: module.PoliciesPage })),
);
const LedgerPage = lazy(() =>
  import("../routes/LedgerPage").then((module) => ({ default: module.LedgerPage })),
);
const NotFoundPage = lazy(() =>
  import("../routes/NotFoundPage").then((module) => ({ default: module.NotFoundPage })),
);

export function App(): React.JSX.Element {
  return (
    <Suspense fallback={<DataState loading />}>
      <Routes>
        <Route element={<AppShell />}>
          <Route element={<OverviewPage />} index />
          <Route element={<MemoryInventoryPage />} path="memories" />
          <Route element={<CandidateDetailPage />} path="candidates/:candidateId" />
          <Route element={<EventTimelinePage />} path="events" />
          <Route element={<QuarantinePage />} path="quarantine" />
          <Route element={<RevocationPage />} path="revocation" />
          <Route element={<PoliciesPage />} path="policies" />
          <Route element={<LedgerPage />} path="ledger" />
          <Route element={<Navigate replace to="/" />} path="home" />
          <Route element={<NotFoundPage />} path="*" />
        </Route>
      </Routes>
    </Suspense>
  );
}
