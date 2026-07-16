import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Bot, Fingerprint, ScanSearch, ShieldCheck } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { Card } from "../components/Card";
import { DataState } from "../components/DataState";
import { PageHeader } from "../components/PageHeader";
import { StatusPill } from "../components/StatusPill";
import { formatDate, formatLabel, shortDigest } from "../lib/format";

export function CandidateDetailPage(): React.JSX.Element {
  const { candidateId } = useParams<{ candidateId: string }>();
  const detailQuery = useQuery({
    queryKey: ["candidate", candidateId],
    queryFn: () => api.candidate(candidateId ?? ""),
    enabled: Boolean(candidateId),
  });

  if (detailQuery.isPending) return <div className="page"><DataState loading /></div>;
  if (detailQuery.error) {
    return <div className="page"><DataState error={detailQuery.error} /></div>;
  }

  const detail = detailQuery.data;
  const candidate = detail.candidate;
  const semantic = detail.semantic_assessment;
  const decision = detail.policy_decision;
  const shadowAdmitted = decision.shadow_mode && decision.actual_action === "allow";
  const subscriptionAttempt = semantic?.provider_state === "live_codex_subscription"
    || semantic?.requested_provider === "codex_subscription";

  return (
    <div className="page">
      <Link className="back-link" to="/memories"><ArrowLeft aria-hidden="true" size={16} />Back to inventory</Link>
      <PageHeader
        actions={<StatusPill value={detail.status} />}
        description="A safe representation with provenance, detector evidence, semantic input, policy authority, and ledger references."
        eyebrow="Candidate detail"
        title="Why this memory received its decision"
      />

      <Card className="candidate-statement">
        <div className="section-heading">
          <div><p className="eyebrow">Sanitized candidate</p><h2>{formatLabel(candidate.kind)}</h2></div>
          <span className="mono" title={candidate.content_digest}>{shortDigest(candidate.content_digest)}</span>
        </div>
        <blockquote>{candidate.statement}</blockquote>
        {candidate.contains_redactions ? <p className="redaction-note">Detected sensitive material was replaced before evaluation.</p> : null}
      </Card>

      <div className="detail-grid">
        <Card>
          <div className="section-heading"><div><p className="eyebrow">Origin</p><h2>Provenance</h2></div><Fingerprint aria-hidden="true" size={22} /></div>
          <dl className="detail-list">
            <div><dt>Candidate ID</dt><dd className="mono">{candidate.candidate_id}</dd></div>
            <div><dt>Namespace</dt><dd className="mono">{candidate.namespace}</dd></div>
            <div><dt>Source class</dt><dd>{formatLabel(candidate.source_class)}</dd></div>
            <div><dt>Session</dt><dd className="mono">{candidate.session_id}</dd></div>
            <div><dt>Task</dt><dd className="mono">{candidate.task_id ?? "—"}</dd></div>
            <div><dt>Created</dt><dd>{formatDate(candidate.created_at)}</dd></div>
            <div><dt>Extractor</dt><dd>{formatLabel(candidate.extractor_provider)} · <span className="mono">{candidate.extractor_version}</span></dd></div>
            <div><dt>Persistence requested</dt><dd>{candidate.persistence_requested ? "Yes" : "No"}</dd></div>
            <div><dt>Authority signal</dt><dd><StatusPill value={candidate.authority_signal} /></dd></div>
            <div><dt>Secrecy signal</dt><dd><StatusPill value={candidate.secrecy_signal} /></dd></div>
          </dl>
          <h3>Evidence references</h3>
          <ul className="reference-list">
            {candidate.source_refs.map((reference) => (
              <li key={reference.evidence_id}><span className="mono">{reference.evidence_id}</span><span className="mono" title={reference.evidence_digest}>{shortDigest(reference.evidence_digest)}</span></li>
            ))}
          </ul>
        </Card>

        <Card>
          <div className="section-heading"><div><p className="eyebrow">Final authority</p><h2>Policy decision</h2></div><ShieldCheck aria-hidden="true" size={22} /></div>
          <div className="action-comparison">
            <div><span>Actual action</span><StatusPill value={decision.actual_action} /></div>
            <div><span>Would-have action</span><StatusPill value={decision.would_have_action} /></div>
          </div>
          {decision.shadow_mode ? <p className="shadow-callout">This candidate was admitted under shadow mode. Shadow mode is not active protection.</p> : null}
          <dl className="detail-list">
            <div><dt>Policy</dt><dd className="mono">{decision.policy_id}@{decision.policy_version}</dd></div>
            <div><dt>Mode</dt><dd><StatusPill value={decision.mode} /></dd></div>
            <div><dt>Matched rule</dt><dd className="mono">{decision.matched_rule_id ?? "Default action"}</dd></div>
            <div><dt>Ledger status</dt><dd><StatusPill value={detail.ledger_verified ? "verified" : "unverified"} /></dd></div>
          </dl>
          <h3>Decision rationale</h3>
          <p>{decision.reason}</p>
        </Card>
      </div>

      <Card>
        <div className="section-heading"><div><p className="eyebrow">Deterministic layer</p><h2>Detector findings</h2></div><ScanSearch aria-hidden="true" size={22} /></div>
        <DataState empty={detail.detector_results.length === 0} emptyMessage="No detector result was recorded for this candidate." />
        {detail.detector_results.length ? (
          <div className="finding-grid">
            {detail.detector_results.map((result) => (
              <article className="finding" key={result.result_id}>
                <header><strong className="mono">{result.detector_id}</strong><StatusPill value={result.status === "ok" ? result.severity : result.status} /></header>
                <p>{result.message}</p>
                <div className="finding__meta"><span>v{result.detector_version}</span><span>{result.latency_ms} ms</span><span>{Math.round(result.confidence * 100)}% confidence</span></div>
                {result.categories.length ? <ul className="tag-list">{result.categories.map((category) => <li key={category}>{formatLabel(category)}</li>)}</ul> : null}
              </article>
            ))}
          </div>
        ) : null}
      </Card>

      <Card>
        <div className="section-heading"><div><p className="eyebrow">Advisory input</p><h2>Semantic assessment</h2></div><Bot aria-hidden="true" size={22} /></div>
        {!semantic ? (
          <DataState empty emptyTitle="Semantic review was not required" emptyMessage="Deterministic findings and policy were sufficient for this decision." />
        ) : (
          <div className="semantic-layout">
            <div className="risk-score">
              <span>Risk score</span>
              <strong>{semantic.risk_score === null ? "—" : Math.round(semantic.risk_score * 100)}</strong>
              <StatusPill value={semantic.provider_state} tone={semantic.provider_state === "failed" ? "danger" : "info"} />
            </div>
            <div>
              {subscriptionAttempt ? (
                <p className="shadow-callout">
                  This assessment {semantic.provider_state === "failed" ? "attempted" : "used"} the lower-isolation agentic provider <span className="mono">agentic_sandboxed</span>. Tool activity invalidates the result; deterministic policy retains final authority.
                </p>
              ) : null}
              <p>{semantic.rationale ?? "The semantic provider failed without producing a risk recommendation."}</p>
              <dl className="score-grid">
                <div><dt>Persistence</dt><dd>{formatLabel(semantic.persistence_intent)}</dd></div>
                <div><dt>Authority</dt><dd>{formatLabel(semantic.authority_claim)}</dd></div>
                <div><dt>Exfiltration</dt><dd>{semantic.exfiltration_risk === null ? "—" : `${Math.round(semantic.exfiltration_risk * 100)}%`}</dd></div>
                <div><dt>Tool hijack</dt><dd>{semantic.tool_hijack_risk === null ? "—" : `${Math.round(semantic.tool_hijack_risk * 100)}%`}</dd></div>
                <div><dt>Cross-task</dt><dd>{semantic.cross_task_risk === null ? "—" : `${Math.round(semantic.cross_task_risk * 100)}%`}</dd></div>
                <div><dt>Secret risk</dt><dd>{semantic.secret_risk === null ? "—" : `${Math.round(semantic.secret_risk * 100)}%`}</dd></div>
              </dl>
              <div className="provider-line">{semantic.requested_provider ? <span>Attempted <span className="mono">{formatLabel(semantic.requested_provider)}</span></span> : null}<span>Prompt <span className="mono">{semantic.prompt_version}</span></span><span>Model <span className="mono">{semantic.returned_model ?? semantic.requested_model ?? "none"}</span></span><span>{semantic.latency_ms} ms</span></div>
            </div>
          </div>
        )}
      </Card>

      <Card aria-labelledby="decision-recovery-timeline-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Decision to recovery</p>
            <h2 id="decision-recovery-timeline-title">Decision and recovery timeline</h2>
          </div>
          <StatusPill value={detail.status} />
        </div>
        <ol className="timeline">
          <li>
            <span aria-hidden="true" className="timeline__node" />
            <article>
              <header><div><span className="mono sequence">1</span><strong>Trust decision</strong></div></header>
              <div className="action-comparison action-comparison--inline">
                <div><span>Actual action</span><StatusPill value={decision.actual_action} /></div>
                <div><span>Would-have action</span><StatusPill value={decision.would_have_action} /></div>
              </div>
            </article>
          </li>
          <li>
            <span aria-hidden="true" className="timeline__node" />
            <article>
              <header><div><span className="mono sequence">2</span><strong>Future-memory effect</strong></div></header>
              {shadowAdmitted ? (
                <p><strong>Shadow mode is not active protection.</strong> The actual allow action admitted this candidate, so delayed influence remained possible until revocation or another ineligibility event.</p>
              ) : (
                <p>The actual {formatLabel(decision.actual_action)} action governed whether this candidate could enter future memory injection.</p>
              )}
            </article>
          </li>
          <li>
            <span aria-hidden="true" className={`timeline__node${detail.ledger_verified ? " timeline__node--verified" : ""}`} />
            <article>
              <header>
                <div><span className="mono sequence">3</span><strong>Related signed events</strong></div>
                <StatusPill value={detail.ledger_verified ? "verified" : "unverified"} />
              </header>
              <p>{detail.event_references.length} event references remain bound to this candidate.</p>
              <ul className="event-id-list">
                {detail.event_references.map((event) => (
                  <li key={event.event_id}>
                    <strong>{formatLabel(event.event_type)}</strong>{" "}
                    <span className="mono">#{event.sequence_number} · {event.event_id}</span>
                  </li>
                ))}
              </ul>
            </article>
          </li>
          <li>
            <span aria-hidden="true" className={`timeline__node${detail.status === "revoked" ? " timeline__node--verified" : ""}`} />
            <article>
              <header><div><span className="mono sequence">4</span><strong>Current outcome</strong></div><StatusPill value={detail.status} /></header>
              {detail.status === "revoked" ? (
                <p>This candidate is revoked and excluded from active memory injection. Its related signed events remain in append-only history.</p>
              ) : (
                <p>The current candidate state is {formatLabel(detail.status)}. No revocation is represented by this response.</p>
              )}
            </article>
          </li>
        </ol>
      </Card>
    </div>
  );
}
