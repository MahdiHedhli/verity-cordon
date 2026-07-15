import { useQuery } from "@tanstack/react-query";
import { Activity, Archive, Clock, OctagonX, ShieldCheck, TimerReset } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Card } from "../components/Card";
import { DataState } from "../components/DataState";
import { MetricCard } from "../components/MetricCard";
import { PageHeader } from "../components/PageHeader";
import { StatusPill } from "../components/StatusPill";
import { formatDate, formatLabel, shortId } from "../lib/format";

export function OverviewPage(): React.JSX.Element {
  const statusQuery = useQuery({
    queryKey: ["status"],
    queryFn: ({ signal }) => api.status(signal),
    refetchInterval: 15_000,
  });
  const statisticsQuery = useQuery({
    queryKey: ["statistics"],
    queryFn: ({ signal }) => api.statistics(signal),
    refetchInterval: 15_000,
  });
  const eventsQuery = useQuery({
    queryKey: ["events", "recent"],
    queryFn: () => api.events("limit=6"),
  });
  const memoriesQuery = useQuery({
    queryKey: ["memories", "overview-active"],
    queryFn: () => api.memories("status=active&limit=200"),
  });

  const error = statusQuery.error ?? statisticsQuery.error;
  if (statusQuery.isPending || statisticsQuery.isPending) {
    return <div className="page"><DataState loading /></div>;
  }
  if (error || !statusQuery.data || !statisticsQuery.data) {
    return <div className="page"><DataState error={error} /></div>;
  }

  const status = statusQuery.data;
  const statistics = statisticsQuery.data;
  const activeCount = memoriesQuery.data?.items.length ?? 0;

  return (
    <div className="page">
      <PageHeader
        description="A content-safe view of the local memory plane, policy decisions, and signed event history."
        eyebrow="System overview"
        title="Memory is explicit here."
      />

      {status.mode === "shadow" ? (
        <div className="mode-banner" role="status">
          <Activity aria-hidden="true" size={19} />
          <div>
            <strong>Shadow mode is observing, not protecting.</strong>
            <span>Would-have actions are recorded, while the configured shadow action is applied.</span>
          </div>
          <Link to="/policies">Review active policy</Link>
        </div>
      ) : null}

      <section aria-label="Key memory metrics" className="metric-grid">
        <MetricCard
          detail={memoriesQuery.data?.next_cursor ? "At least 200 materialized" : "Eligible for injection"}
          icon={Archive}
          label="Active memories"
          value={memoriesQuery.isPending ? "—" : activeCount}
        />
        <MetricCard
          detail="Awaiting operator review"
          icon={OctagonX}
          label="Quarantined"
          tone={status.counts.quarantined > 0 ? "warning" : "default"}
          value={status.counts.quarantined}
        />
        <MetricCard
          detail="Removed by append-only event"
          icon={TimerReset}
          label="Revoked"
          value={status.counts.revoked}
        />
        <MetricCard
          detail="Pipeline average"
          icon={Clock}
          label="Evaluation latency"
          value={`${statistics.average_evaluation_latency_ms.toFixed(0)} ms`}
        />
      </section>

      <div className="overview-grid">
        <Card className="health-card">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Local trust boundary</p>
              <h2>System state</h2>
            </div>
            <ShieldCheck aria-hidden="true" size={24} />
          </div>
          <dl className="status-list">
            <div><dt>Daemon health</dt><dd><StatusPill value={status.daemon} /></dd></div>
            <div><dt>Ledger chain</dt><dd><StatusPill value={status.ledger} /></dd></div>
            <div><dt>Memory view</dt><dd><StatusPill value={status.memory_view} /></dd></div>
            <div><dt>Semantic provider</dt><dd><StatusPill value={status.semantic_provider} tone="info" /></dd></div>
            <div><dt>Active policy</dt><dd><span className="mono">{status.policy.policy_id}@{status.policy.version}</span></dd></div>
          </dl>
        </Card>

        <Card className="decision-card">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Current corpus</p>
              <h2>Decision distribution</h2>
            </div>
            <span className="large-number">{status.counts.total_candidates}</span>
          </div>
          <div className="decision-bars" aria-label="Candidate decision counts">
            {[
              ["Allowed", status.counts.allowed, "allowed"],
              ["Redacted", status.counts.redacted, "redacted"],
              ["Quarantined", status.counts.quarantined, "quarantined"],
              ["Blocked", status.counts.blocked, "blocked"],
            ].map(([label, value, className]) => {
              const count = Number(value);
              const width = status.counts.total_candidates
                ? Math.max(2, (count / status.counts.total_candidates) * 100)
                : 0;
              return (
                <div className="decision-bar" key={String(label)}>
                  <span>{label}</span>
                  <div aria-hidden="true"><i className={`bar--${String(className)}`} style={{ width: `${width}%` }} /></div>
                  <strong>{count}</strong>
                </div>
              );
            })}
          </div>
          <div className="minor-stats">
            <span>Semantic timeouts <strong>{statistics.semantic_timeouts}</strong></span>
            <span>Detector failures <strong>{statistics.detector_failures}</strong></span>
          </div>
        </Card>
      </div>

      <Card>
        <div className="section-heading">
          <div>
            <p className="eyebrow">Append-only history</p>
            <h2>Recent decisions</h2>
          </div>
          <Link className="text-link" to="/events">View full timeline</Link>
        </div>
        <DataState
          empty={!eventsQuery.isPending && eventsQuery.data?.items.length === 0}
          error={eventsQuery.error}
          loading={eventsQuery.isPending}
        />
        {eventsQuery.data?.items.length ? (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Most recent ledger events</caption>
              <thead><tr><th>Sequence</th><th>Event</th><th>Memory</th><th>Action</th><th>Time</th><th>Chain</th></tr></thead>
              <tbody>
                {eventsQuery.data.items.map((event) => (
                  <tr key={event.event_id}>
                    <td className="mono">#{event.sequence_number}</td>
                    <td><strong>{formatLabel(event.event_type)}</strong></td>
                    <td className="mono" title={event.memory_id ?? undefined}>{shortId(event.memory_id)}</td>
                    <td>{event.action ? <StatusPill value={event.action} /> : "—"}</td>
                    <td>{formatDate(event.occurred_at)}</td>
                    <td><StatusPill value={event.chain_status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Card>
    </div>
  );
}
