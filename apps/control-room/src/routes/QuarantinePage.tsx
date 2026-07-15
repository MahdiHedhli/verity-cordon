import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Eye, ShieldX } from "lucide-react";
import { useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { CandidateSummary } from "../api/types";
import type { AppOutletContext } from "../app/AppShell";
import { useAuth } from "../auth/useAuth";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { DataState } from "../components/DataState";
import { PageHeader } from "../components/PageHeader";
import { StatusPill } from "../components/StatusPill";
import { formatDate, formatLabel } from "../lib/format";

type Disposition = "approve" | "block" | "leave_quarantined";
interface PendingReview { candidate: CandidateSummary; disposition: Disposition }

export function QuarantinePage(): React.JSX.Element {
  const queryClient = useQueryClient();
  const { csrfToken, isUnlocked } = useAuth();
  const { requestUnlock } = useOutletContext<AppOutletContext>();
  const [pendingReview, setPendingReview] = useState<PendingReview | null>(null);

  const candidatesQuery = useQuery({
    queryKey: ["candidates", "quarantined"],
    queryFn: () => api.candidates("status=quarantined&limit=200"),
  });
  const reviewMutation = useMutation({
    mutationFn: async ({ reason }: { reason: string }) => {
      if (!pendingReview || !csrfToken) throw new Error("Operator actions are locked.");
      return api.reviewCandidate(
        pendingReview.candidate.candidate_id,
        {
          actor_id: "control-room.operator",
          reason,
          confirmed: true,
          disposition: pendingReview.disposition,
        },
        csrfToken,
      );
    },
    onSuccess: async () => {
      setPendingReview(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["candidates"] }),
        queryClient.invalidateQueries({ queryKey: ["memories"] }),
        queryClient.invalidateQueries({ queryKey: ["status"] }),
        queryClient.invalidateQueries({ queryKey: ["events"] }),
      ]);
    },
  });

  const beginReview = (candidate: CandidateSummary, disposition: Disposition) => {
    if (!isUnlocked) {
      requestUnlock();
      return;
    }
    reviewMutation.reset();
    setPendingReview({ candidate, disposition });
  };

  const actionLabel = pendingReview?.disposition === "approve"
    ? "Approve candidate"
    : pendingReview?.disposition === "block"
      ? "Block candidate"
      : "Leave quarantined";

  return (
    <div className="page">
      <PageHeader
        actions={<StatusPill value={`${candidatesQuery.data?.items.length ?? 0} quarantined`} tone="warning" />}
        description="Review safe candidate representations. Every outcome appends an operator-attributed event and requires a reason."
        eyebrow="Manual trust boundary"
        title="Quarantine review"
      />

      <DataState
        empty={!candidatesQuery.isPending && candidatesQuery.data?.items.length === 0}
        emptyMessage="Candidates that need human judgment will appear here."
        emptyTitle="Quarantine is clear"
        error={candidatesQuery.error}
        loading={candidatesQuery.isPending}
      />

      <div className="quarantine-list">
        {candidatesQuery.data?.items.map((candidate) => (
          <Card as="article" className="quarantine-card" key={candidate.candidate_id}>
            <div className="quarantine-card__main">
              <div className="quarantine-card__topline">
                <StatusPill value={candidate.status} />
                <span>{formatLabel(candidate.source_class)}</span>
                <time dateTime={candidate.created_at}>{formatDate(candidate.created_at)}</time>
              </div>
              <h2>{candidate.safe_statement}</h2>
              <dl className="compact-meta">
                <div><dt>Namespace</dt><dd className="mono">{candidate.namespace}</dd></div>
                <div><dt>Kind</dt><dd>{formatLabel(candidate.kind)}</dd></div>
                <div><dt>Policy</dt><dd className="mono">{candidate.policy_version}</dd></div>
                <div><dt>Semantic</dt><dd>{formatLabel(candidate.semantic_provider)}</dd></div>
              </dl>
              {candidate.shadow_mode ? (
                <div className="action-comparison action-comparison--inline">
                  <div><span>Actual</span><StatusPill value={candidate.actual_action} /></div>
                  <div><span>Would have</span><StatusPill value={candidate.would_have_action} /></div>
                </div>
              ) : null}
            </div>
            <div className="quarantine-card__actions">
              <Link className="button button--quiet button--small" to={`/candidates/${encodeURIComponent(candidate.candidate_id)}`}><Eye aria-hidden="true" size={15} />Inspect</Link>
              <Button onClick={() => beginReview(candidate, "approve")} size="small" variant="secondary"><Check aria-hidden="true" size={15} />Approve</Button>
              <Button onClick={() => beginReview(candidate, "block")} size="small" variant="danger"><ShieldX aria-hidden="true" size={15} />Block</Button>
              <Button onClick={() => beginReview(candidate, "leave_quarantined")} size="small" variant="quiet">Leave quarantined</Button>
            </div>
          </Card>
        ))}
      </div>

      <ConfirmDialog
        busy={reviewMutation.isPending}
        confirmLabel={actionLabel}
        danger={pendingReview?.disposition === "block"}
        description={pendingReview ? `Record why “${pendingReview.candidate.safe_statement}” should receive this operator decision.` : "Record this review decision."}
        error={reviewMutation.error instanceof ApiError ? reviewMutation.error.message : reviewMutation.error ? "The review could not be recorded." : null}
        onCancel={() => setPendingReview(null)}
        onConfirm={async (reason) => reviewMutation.mutateAsync({ reason }).then(() => undefined)}
        open={pendingReview !== null}
        title={actionLabel}
      />
    </div>
  );
}
