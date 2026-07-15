import { useQuery } from "@tanstack/react-query";
import { Filter } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { Card } from "../components/Card";
import { DataState } from "../components/DataState";
import { PageHeader } from "../components/PageHeader";
import { StatusPill } from "../components/StatusPill";
import { formatDate, formatLabel, shortDigest, shortId } from "../lib/format";

const eventTypes = [
  "EvidenceCaptured", "MemoryCandidateCreated", "DetectorVerdictRecorded",
  "SemanticAssessmentRecorded", "PolicyDecisionRecorded", "MemoryCommitted",
  "MemoryRedacted", "MemoryQuarantined", "MemoryBlocked", "MemoryApproved",
  "MemoryRevoked", "MemorySuperseded", "MemoryExpired", "PolicyActivated",
  "PolicyActivationRejected", "LedgerCheckpointCreated", "StreamStarted",
  "StreamAborted", "StreamCommitted",
] as const;

export function EventTimelinePage(): React.JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const queryString = searchParams.toString();
  const eventsQuery = useQuery({
    queryKey: ["events", queryString],
    queryFn: () => api.events(queryString),
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
        description="Content-safe summaries of the signed, append-only security history. Event payloads are never rendered here."
        eyebrow="Audit history"
        title="Event timeline"
      />
      <Card className="filters-card filters-card--compact">
        <div className="filters-card__heading"><Filter aria-hidden="true" size={17} /><strong>Narrow the timeline</strong></div>
        <div className="filter-grid filter-grid--compact">
          <label>Event type<select onChange={(event) => updateFilter("event_type", event.target.value)} value={searchParams.get("event_type") ?? ""}><option value="">All event types</option>{eventTypes.map((value) => <option key={value} value={value}>{formatLabel(value)}</option>)}</select></label>
          <label>Memory ID<input maxLength={128} onBlur={(event) => updateFilter("memory_id", event.target.value.trim())} defaultValue={searchParams.get("memory_id") ?? ""} placeholder="Filter exact memory ID" /></label>
        </div>
      </Card>
      <Card>
        <DataState
          empty={!eventsQuery.isPending && eventsQuery.data?.items.length === 0}
          error={eventsQuery.error}
          loading={eventsQuery.isPending}
        />
        {eventsQuery.data?.items.length ? (
          <ol className="timeline">
            {eventsQuery.data.items.map((event) => (
              <li key={event.event_id}>
                <span className={`timeline__node timeline__node--${event.chain_status}`} aria-hidden="true" />
                <article>
                  <header>
                    <div><span className="mono sequence">#{event.sequence_number}</span><h2>{formatLabel(event.event_type)}</h2></div>
                    <time dateTime={event.occurred_at}>{formatDate(event.occurred_at)}</time>
                  </header>
                  <dl className="timeline__meta">
                    <div><dt>Event</dt><dd className="mono" title={event.event_id}>{shortId(event.event_id, 20)}</dd></div>
                    <div><dt>Memory</dt><dd className="mono" title={event.memory_id ?? undefined}>{shortId(event.memory_id, 20)}</dd></div>
                    <div><dt>Source</dt><dd>{event.source_class ? formatLabel(event.source_class) : "System"}</dd></div>
                    <div><dt>Policy</dt><dd className="mono">{event.policy_version ?? "—"}</dd></div>
                    <div><dt>Digest</dt><dd className="mono" title={event.event_hash}>{shortDigest(event.event_hash)}</dd></div>
                    <div><dt>Chain</dt><dd><StatusPill value={event.chain_status} /></dd></div>
                  </dl>
                  {event.action ? <div className="timeline__action"><span>Action</span><StatusPill value={event.action} /></div> : null}
                </article>
              </li>
            ))}
          </ol>
        ) : null}
      </Card>
    </div>
  );
}
