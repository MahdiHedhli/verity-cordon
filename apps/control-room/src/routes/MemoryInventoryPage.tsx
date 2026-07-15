import { useQuery } from "@tanstack/react-query";
import { Filter, Search } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { MemoryKind, MemoryStatus, SemanticProviderState, SourceClass } from "../api/types";
import { Card } from "../components/Card";
import { DataState } from "../components/DataState";
import { PageHeader } from "../components/PageHeader";
import { StatusPill } from "../components/StatusPill";
import { formatDate, formatLabel, shortId } from "../lib/format";

const statuses: MemoryStatus[] = ["active", "redacted", "revoked", "superseded", "expired"];
const kinds: MemoryKind[] = ["fact", "user_preference", "project_convention", "operational_instruction", "tool_observation", "task_summary", "identity_assertion", "policy_statement", "unknown"];
const sources: SourceClass[] = ["user_input", "tool_output", "agent_output", "imported_file", "prior_memory", "compaction", "session_summary", "external_event"];
const providers: SemanticProviderState[] = ["live_openai", "live_codex_subscription", "recorded_fixture", "deterministic_only", "failed", "not_required"];

export function MemoryInventoryPage(): React.JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const queryString = searchParams.toString();
  const memoriesQuery = useQuery({
    queryKey: ["memories", queryString],
    queryFn: () => api.memories(queryString),
  });

  const updateFilter = (name: string, value: string) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      if (value) next.set(name, value);
      else next.delete(name);
      next.delete("cursor");
      return next;
    }, { replace: true });
  };

  return (
    <div className="page">
      <PageHeader
        description="Safe materialized records derived from the signed ledger. Quarantined and blocked candidates never appear here."
        eyebrow="Materialized view"
        title="Memory inventory"
      />

      <Card className="filters-card">
        <div className="filters-card__heading"><Filter aria-hidden="true" size={17} /><strong>Filter the active and historical view</strong></div>
        <div className="filter-grid">
          <label>Status<select onChange={(event) => updateFilter("status", event.target.value)} value={searchParams.get("status") ?? ""}><option value="">All statuses</option>{statuses.map((value) => <option key={value} value={value}>{formatLabel(value)}</option>)}</select></label>
          <label>Kind<select onChange={(event) => updateFilter("kind", event.target.value)} value={searchParams.get("kind") ?? ""}><option value="">All kinds</option>{kinds.map((value) => <option key={value} value={value}>{formatLabel(value)}</option>)}</select></label>
          <label>Source<select onChange={(event) => updateFilter("source_class", event.target.value)} value={searchParams.get("source_class") ?? ""}><option value="">All sources</option>{sources.map((value) => <option key={value} value={value}>{formatLabel(value)}</option>)}</select></label>
          <label>Semantic provider<select onChange={(event) => updateFilter("semantic_provider", event.target.value)} value={searchParams.get("semantic_provider") ?? ""}><option value="">All providers</option>{providers.map((value) => <option key={value} value={value}>{formatLabel(value)}</option>)}</select></label>
          <label>Namespace<div className="input-with-icon"><Search aria-hidden="true" size={15} /><input maxLength={160} onBlur={(event) => updateFilter("namespace", event.target.value.trim())} defaultValue={searchParams.get("namespace") ?? ""} placeholder="project.testing" /></div></label>
          <label>Session<div className="input-with-icon"><Search aria-hidden="true" size={15} /><input maxLength={128} onBlur={(event) => updateFilter("session_id", event.target.value.trim())} defaultValue={searchParams.get("session_id") ?? ""} placeholder="Session ID" /></div></label>
          <label>Policy version<input maxLength={64} onBlur={(event) => updateFilter("policy_version", event.target.value.trim())} defaultValue={searchParams.get("policy_version") ?? ""} placeholder="1.0.0" /></label>
          <label>Risk category<input maxLength={64} onBlur={(event) => updateFilter("risk_category", event.target.value.trim())} defaultValue={searchParams.get("risk_category") ?? ""} placeholder="persistent_instruction" /></label>
        </div>
      </Card>

      <Card>
        <div className="section-heading">
          <div><p className="eyebrow">Ledger-derived records</p><h2>Memory records</h2></div>
          <span className="record-count">{memoriesQuery.data?.items.length ?? 0} shown</span>
        </div>
        <DataState
          empty={!memoriesQuery.isPending && memoriesQuery.data?.items.length === 0}
          emptyMessage="Adjust filters or run the offline demonstration to create evaluated memory."
          error={memoriesQuery.error}
          loading={memoriesQuery.isPending}
        />
        {memoriesQuery.data?.items.length ? (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Safe memory inventory</caption>
              <thead><tr><th>Memory</th><th>Namespace</th><th>Kind</th><th>Source</th><th>Status</th><th>Decision</th><th>Committed</th></tr></thead>
              <tbody>
                {memoriesQuery.data.items.map((memory) => (
                  <tr key={memory.memory_id}>
                    <td className="statement-cell">
                      <Link to={`/candidates/${encodeURIComponent(memory.candidate_id)}`}>{memory.safe_statement}</Link>
                      <span className="mono" title={memory.memory_id}>{shortId(memory.memory_id, 18)}</span>
                    </td>
                    <td className="mono">{memory.namespace}</td>
                    <td>{formatLabel(memory.kind)}</td>
                    <td>{formatLabel(memory.source_class)}</td>
                    <td><StatusPill value={memory.status} /></td>
                    <td>
                      <StatusPill value={memory.actual_action} />
                      {memory.shadow_admitted ? <span className="inline-note">would {memory.would_have_action}</span> : null}
                    </td>
                    <td>{formatDate(memory.committed_at)}</td>
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
