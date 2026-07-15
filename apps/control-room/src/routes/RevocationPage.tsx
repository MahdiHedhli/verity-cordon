import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RotateCcw, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { useOutletContext } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { MemoryRecord, RevocationPreview } from "../api/types";
import type { AppOutletContext } from "../app/AppShell";
import { useAuth } from "../auth/useAuth";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { DataState } from "../components/DataState";
import { PageHeader } from "../components/PageHeader";
import { StatusPill } from "../components/StatusPill";
import { formatDate, formatLabel, shortId } from "../lib/format";

interface PendingRevocation { memory: MemoryRecord; preview: RevocationPreview }

export function RevocationPage(): React.JSX.Element {
  const queryClient = useQueryClient();
  const { csrfToken, isUnlocked } = useAuth();
  const { requestUnlock } = useOutletContext<AppOutletContext>();
  const [pending, setPending] = useState<PendingRevocation | null>(null);
  const [previewingId, setPreviewingId] = useState<string | null>(null);

  const memoriesQuery = useQuery({
    queryKey: ["memories", "revocable"],
    queryFn: () => api.memories("limit=200"),
  });
  const previewMutation = useMutation({
    mutationFn: async (memory: MemoryRecord) => {
      if (!csrfToken) throw new Error("Operator actions are locked.");
      setPreviewingId(memory.memory_id);
      const preview = await api.previewRevocation(memory.memory_id, csrfToken);
      return { memory, preview };
    },
    onSuccess: setPending,
    onSettled: () => setPreviewingId(null),
  });
  const revokeMutation = useMutation({
    mutationFn: async (reason: string) => {
      if (!pending || !csrfToken) throw new Error("Operator actions are locked.");
      const revoked = await api.revokeMemory(
        pending.memory.memory_id,
        { actor_id: "control-room.operator", reason, confirmed: true },
        csrfToken,
      );
      const rebuilt = await api.rebuildMemory(csrfToken);
      if (!rebuilt.ledger_verified || !rebuilt.view_consistent) {
        throw new Error("Revocation was recorded, but replay verification did not succeed.");
      }
      return revoked;
    },
    onSuccess: () => {
      setPending(null);
    },
    onSettled: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["memories"] }),
        queryClient.invalidateQueries({ queryKey: ["status"] }),
        queryClient.invalidateQueries({ queryKey: ["events"] }),
      ]);
    },
  });

  const activeMemories = memoriesQuery.data?.items.filter((memory) => memory.status === "active" || memory.status === "redacted") ?? [];
  const beginPreview = (memory: MemoryRecord) => {
    if (!isUnlocked) {
      requestUnlock();
      return;
    }
    previewMutation.reset();
    previewMutation.mutate(memory);
  };

  return (
    <div className="page">
      <PageHeader
        description="Preview the exact active-view impact, append a revocation event, and preserve unrelated approved knowledge."
        eyebrow="Selective recovery"
        title="Revoke and replay"
      />

      {previewMutation.error ? (
        <div className="inline-alert" role="alert"><ShieldAlert aria-hidden="true" size={18} />{previewMutation.error instanceof ApiError ? previewMutation.error.message : "The revocation preview could not be produced."}</div>
      ) : null}

      <DataState
        empty={!memoriesQuery.isPending && activeMemories.length === 0}
        emptyMessage="Only active or redacted records can be selectively revoked."
        emptyTitle="No revocable memory"
        error={memoriesQuery.error}
        loading={memoriesQuery.isPending}
      />

      <div className="memory-card-grid">
        {activeMemories.map((memory) => (
          <Card as="article" className="memory-card" key={memory.memory_id}>
            <header><StatusPill value={memory.status} />{memory.shadow_admitted ? <StatusPill tone="warning" value="shadow admitted" /> : null}</header>
            <h2>{memory.safe_statement}</h2>
            <dl className="compact-meta">
              <div><dt>Namespace</dt><dd className="mono">{memory.namespace}</dd></div>
              <div><dt>Kind</dt><dd>{formatLabel(memory.kind)}</dd></div>
              <div><dt>Memory</dt><dd className="mono" title={memory.memory_id}>{shortId(memory.memory_id, 19)}</dd></div>
              <div><dt>Committed</dt><dd>{formatDate(memory.committed_at)}</dd></div>
            </dl>
            <Button disabled={previewingId === memory.memory_id} onClick={() => beginPreview(memory)} variant="danger">
              <RotateCcw aria-hidden="true" size={16} />
              {previewingId === memory.memory_id ? "Calculating impact…" : "Preview revocation"}
            </Button>
          </Card>
        ))}
      </div>

      <ConfirmDialog
        busy={revokeMutation.isPending}
        confirmLabel="Revoke and replay"
        danger
        description={pending ? `Revoke “${pending.memory.safe_statement}” by appending a new event. Historical events will remain intact.` : "Confirm selective revocation."}
        error={revokeMutation.error instanceof ApiError ? revokeMutation.error.message : revokeMutation.error ? "The revocation could not be completed." : null}
        onCancel={() => setPending(null)}
        onConfirm={async (reason) => revokeMutation.mutateAsync(reason).then(() => undefined)}
        open={pending !== null}
        title="Confirm selective revocation"
      >
        {pending ? (
          <dl className="impact-preview">
            <div><dt>Removed from active view</dt><dd>{pending.preview.would_remove_from_active_view ? "Yes" : "No"}</dd></div>
            <div><dt>Unrelated memories preserved</dt><dd>{pending.preview.unrelated_active_memories_preserved}</dd></div>
            <div><dt>Resulting active count</dt><dd>{pending.preview.resulting_active_count}</dd></div>
          </dl>
        ) : null}
      </ConfirmDialog>
    </div>
  );
}
