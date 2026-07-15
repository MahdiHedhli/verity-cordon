import { useMutation, useQuery } from "@tanstack/react-query";
import { CheckCircle2, Fingerprint, Link2, ShieldAlert } from "lucide-react";
import { useOutletContext } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { AppOutletContext } from "../app/AppShell";
import { useAuth } from "../auth/useAuth";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { DataState } from "../components/DataState";
import { PageHeader } from "../components/PageHeader";
import { StatusPill } from "../components/StatusPill";
import { formatDate, shortDigest, shortId } from "../lib/format";

export function LedgerPage(): React.JSX.Element {
  const { csrfToken, isUnlocked } = useAuth();
  const { requestUnlock } = useOutletContext<AppOutletContext>();
  const statusQuery = useQuery({ queryKey: ["status"], queryFn: ({ signal }) => api.status(signal) });
  const publicKeyQuery = useQuery({ queryKey: ["ledger", "public-key"], queryFn: api.publicKey });
  const verificationMutation = useMutation({
    mutationFn: async () => {
      if (!csrfToken) throw new Error("Operator actions are locked.");
      return api.verifyLedger(csrfToken);
    },
  });

  const runVerification = () => {
    if (!isUnlocked) {
      requestUnlock();
      return;
    }
    verificationMutation.mutate();
  };

  const error = statusQuery.error ?? publicKeyQuery.error;
  if (statusQuery.isPending || publicKeyQuery.isPending) return <div className="page"><DataState loading /></div>;
  if (error || !statusQuery.data || !publicKeyQuery.data) return <div className="page"><DataState error={error} /></div>;

  const status = statusQuery.data;
  const publicKey = publicKeyQuery.data;
  const result = verificationMutation.data;

  return (
    <div className="page">
      <PageHeader
        actions={<Button disabled={verificationMutation.isPending} onClick={runVerification}>{verificationMutation.isPending ? "Verifying chain…" : "Run full verification"}</Button>}
        description="Verify event order, previous hashes, payload digests, Ed25519 signatures, expected head, and materialized-view consistency."
        eyebrow="Cryptographic evidence"
        title="Ledger verification"
      />

      {verificationMutation.error ? (
        <div className="inline-alert" role="alert"><ShieldAlert aria-hidden="true" size={18} />{verificationMutation.error instanceof ApiError ? verificationMutation.error.message : "Full verification could not be completed."}</div>
      ) : null}

      <div className="ledger-hero">
        <Card className={`verification-seal verification-seal--${result?.verified ? "verified" : status.ledger}`}>
          <div className="verification-seal__icon" aria-hidden="true"><CheckCircle2 size={30} /></div>
          <p className="eyebrow">Current chain state</p>
          <h2>{result?.verified ? "Chain verified" : status.ledger === "verified" ? "Daemon reports verified" : "Verification required"}</h2>
          <StatusPill value={result?.completeness_state ?? status.ledger} />
          <p>{result ? `Verified ${formatDate(result.verified_at)} across ${result.total_events} events.` : "Run full verification to establish anchored completeness in this browser session."}</p>
        </Card>
        <Card>
          <div className="section-heading"><div><p className="eyebrow">Installation identity</p><h2>Signing key</h2></div><Fingerprint aria-hidden="true" size={22} /></div>
          <dl className="detail-list">
            <div><dt>Algorithm</dt><dd>{publicKey.algorithm}</dd></div>
            <div><dt>Key ID</dt><dd className="mono" title={publicKey.signing_key_id}>{shortId(publicKey.signing_key_id, 28)}</dd></div>
            <div><dt>Public-key fingerprint</dt><dd className="mono" title={publicKey.fingerprint_sha256}>{shortDigest(publicKey.fingerprint_sha256)}</dd></div>
            <div><dt>Public key encoding</dt><dd>Raw 32-byte key · standard padded Base64</dd></div>
          </dl>
        </Card>
      </div>

      {result ? (
        <Card>
          <div className="section-heading"><div><p className="eyebrow">Verification receipt</p><h2>Chain and view checks</h2></div><Link2 aria-hidden="true" size={22} /></div>
          <div className="verification-grid">
            <div><span>Cryptographic chain</span><StatusPill value={result.verified ? "verified" : "invalid"} /></div>
            <div><span>Completeness</span><StatusPill value={result.completeness_state} /></div>
            <div><span>Materialized view</span><StatusPill value={result.materialized_view_consistent ? "consistent" : "stale"} /></div>
            <div><span>Expected-head source</span><strong>{result.expected_head_source.replaceAll("_", " ")}</strong></div>
            <div><span>Expected sequence</span><strong className="mono">{result.expected_head_sequence ?? "—"}</strong></div>
            <div><span>Observed sequence</span><strong className="mono">{result.observed_head_sequence ?? "—"}</strong></div>
            <div><span>Total events</span><strong>{result.total_events}</strong></div>
            <div><span>First invalid event</span><strong className="mono" title={result.first_invalid_event_id ?? undefined}>{shortId(result.first_invalid_event_id, 22)}</strong></div>
          </div>
          {result.failure_class ? <div className="failure-receipt"><strong>Failure class</strong><span className="mono">{result.failure_class}</span></div> : null}
        </Card>
      ) : null}

      <Card className="claim-boundary">
        <ShieldAlert aria-hidden="true" size={20} />
        <div><strong>What verification means</strong><p>Valid hashes and signatures establish integrity and provenance within the local-host threat boundary. They do not prove that a memory statement is factually true, and they do not protect a fully compromised host or signing key.</p></div>
      </Card>
    </div>
  );
}
