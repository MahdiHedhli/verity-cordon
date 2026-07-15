interface StatusPillProps {
  value: string;
  tone?: "positive" | "warning" | "danger" | "neutral" | "info";
}

const positiveValues = new Set(["active", "allow", "allowed", "healthy", "verified", "consistent", "valid", "anchored_complete", "enforce"]);
const warningValues = new Set(["quarantined", "quarantine", "shadow", "stale", "tail_unproven", "redacted", "degraded", "last_known_good"]);
const dangerValues = new Set(["blocked", "block", "revoked", "invalid", "unavailable", "failed", "read_only"]);

function inferTone(value: string): StatusPillProps["tone"] {
  if (positiveValues.has(value)) return "positive";
  if (warningValues.has(value)) return "warning";
  if (dangerValues.has(value)) return "danger";
  return "neutral";
}

export function StatusPill({ value, tone }: StatusPillProps): React.JSX.Element {
  const resolvedTone = tone ?? inferTone(value);
  return (
    <span className={`status-pill status-pill--${resolvedTone}`}>
      <span aria-hidden="true" className="status-pill__dot" />
      {value.replaceAll("_", " ")}
    </span>
  );
}
