import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileCheck2, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { useOutletContext } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { Mode } from "../api/types";
import type { AppOutletContext } from "../app/AppShell";
import { useAuth } from "../auth/useAuth";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { DataState } from "../components/DataState";
import { PageHeader } from "../components/PageHeader";
import { StatusPill } from "../components/StatusPill";
import { formatDate, shortDigest } from "../lib/format";

function nextPatchVersion(version: unknown): string {
  if (typeof version !== "string") return "1.0.1";
  const match = /^(\d+)\.(\d+)\.(\d+)/u.exec(version);
  if (!match) return "1.0.1";
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  return `${major}.${minor}.${patch + 1}`;
}

function displayScalar(value: unknown, fallback = "—"): string {
  return typeof value === "string" || typeof value === "number" ? String(value) : fallback;
}

export function PoliciesPage(): React.JSX.Element {
  const queryClient = useQueryClient();
  const { csrfToken, isUnlocked } = useAuth();
  const { requestUnlock } = useOutletContext<AppOutletContext>();
  const [desiredMode, setDesiredMode] = useState<Mode | null>(null);

  const policyQuery = useQuery({ queryKey: ["policy", "active"], queryFn: api.activePolicy });
  const activationMutation = useMutation({
    mutationFn: async (reason: string) => {
      if (!policyQuery.data || !desiredMode || !csrfToken) {
        throw new Error("Operator actions are locked.");
      }
      const policy = {
        ...policyQuery.data.policy,
        mode: desiredMode,
        version: nextPatchVersion(policyQuery.data.policy.version),
        created_at: new Date().toISOString(),
      };
      return api.activatePolicy(
        { policy, actor_id: "control-room.operator", reason, confirmed: true },
        csrfToken,
      );
    },
    onSuccess: async () => {
      setDesiredMode(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["policy"] }),
        queryClient.invalidateQueries({ queryKey: ["status"] }),
        queryClient.invalidateQueries({ queryKey: ["events"] }),
      ]);
    },
  });

  const beginModeChange = (mode: Mode) => {
    if (!isUnlocked) {
      requestUnlock();
      return;
    }
    activationMutation.reset();
    setDesiredMode(mode);
  };

  if (policyQuery.isPending) return <div className="page"><DataState loading /></div>;
  if (policyQuery.error) return <div className="page"><DataState error={policyQuery.error} /></div>;

  const { summary, policy } = policyQuery.data;
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const nextMode = summary.mode === "enforce" ? "shadow" : "enforce";

  return (
    <div className="page">
      <PageHeader
        actions={<Button onClick={() => beginModeChange(nextMode)} variant={nextMode === "enforce" ? "primary" : "secondary"}>Switch to {nextMode}</Button>}
        description="Deterministic, versioned policy is the final authority. Semantic assessment remains advisory input."
        eyebrow="Policy authority"
        title="Active policy"
      />

      {summary.mode === "shadow" ? (
        <div className="mode-banner" role="status">
          <ShieldAlert aria-hidden="true" size={19} />
          <div><strong>Shadow mode is active.</strong><span>Actual actions may admit candidates that enforcement would quarantine or block.</span></div>
        </div>
      ) : null}

      <div className="policy-summary-grid">
        <Card>
          <p className="eyebrow">Identity</p>
          <h2 className="mono">{summary.policy_id}</h2>
          <dl className="detail-list">
            <div><dt>Version</dt><dd className="mono">{summary.version}</dd></div>
            <div><dt>Mode</dt><dd><StatusPill value={summary.mode} /></dd></div>
            <div><dt>Validation</dt><dd><StatusPill value={summary.validation_state} /></dd></div>
            <div><dt>Digest</dt><dd className="mono" title={summary.digest}>{shortDigest(summary.digest)}</dd></div>
            <div><dt>Engine profile</dt><dd className="mono">{displayScalar(policy.engine_profile)}</dd></div>
            <div><dt>Created</dt><dd>{typeof policy.created_at === "string" ? formatDate(policy.created_at) : "—"}</dd></div>
          </dl>
        </Card>
        <Card>
          <div className="section-heading"><div><p className="eyebrow">Safety posture</p><h2>Default behavior</h2></div><FileCheck2 aria-hidden="true" size={22} /></div>
          <dl className="detail-list">
            <div><dt>Default action</dt><dd><StatusPill value={displayScalar(policy.default_action, "unknown")} /></dd></div>
            <div><dt>Shadow action</dt><dd><StatusPill value={displayScalar(policy.shadow_action, "unknown")} /></dd></div>
            <div><dt>Rules</dt><dd>{rules.length}</dd></div>
            <div><dt>Protected namespaces</dt><dd>{Array.isArray(policy.protected_namespaces) ? policy.protected_namespaces.length : 0}</dd></div>
          </dl>
          {Array.isArray(policy.protected_namespaces) ? (
            <ul className="tag-list">{policy.protected_namespaces.map((namespace) => <li className="mono" key={String(namespace)}>{String(namespace)}</li>)}</ul>
          ) : null}
        </Card>
      </div>

      <Card>
        <div className="section-heading"><div><p className="eyebrow">Ordered evaluation</p><h2>Rules</h2></div><span className="record-count">{rules.length} rules</span></div>
        <div className="policy-rules">
          {rules.map((rule, index) => {
            const record = typeof rule === "object" && rule !== null ? rule as Record<string, unknown> : {};
            const ruleId = displayScalar(record.rule_id, `rule-${index + 1}`);
            return (
              <article key={ruleId}>
                <header>
                  <span className="mono">{ruleId}</span>
                  <StatusPill value={displayScalar(record.action, "unknown")} />
                </header>
                <p>{displayScalar(record.description, "Deterministic policy rule")}</p>
                <div className="rule-meta"><span>Priority <strong>{displayScalar(record.priority)}</strong></span><span>Manual review <strong>{record.manual_review_required === true ? "required" : "not required"}</strong></span></div>
              </article>
            );
          })}
        </div>
      </Card>

      <Card>
        <div className="section-heading"><div><p className="eyebrow">Explicit failure posture</p><h2>Failure behavior</h2></div></div>
        <pre className="policy-json">{JSON.stringify(policy.failure_behavior ?? {}, null, 2)}</pre>
      </Card>

      <ConfirmDialog
        busy={activationMutation.isPending}
        confirmLabel={`Activate ${desiredMode ?? "new"} mode`}
        danger={desiredMode === "shadow"}
        description={`A new immutable policy version will be activated in ${desiredMode ?? "the selected"} mode. This appends a PolicyActivated event.`}
        error={activationMutation.error instanceof ApiError ? activationMutation.error.message : activationMutation.error ? "The policy activation could not be completed." : null}
        onCancel={() => setDesiredMode(null)}
        onConfirm={async (reason) => activationMutation.mutateAsync(reason).then(() => undefined)}
        open={desiredMode !== null}
        reasonLabel="Reason for mode change"
        title={`Switch policy to ${desiredMode ?? "selected mode"}`}
      />
    </div>
  );
}
