import type { LucideIcon } from "lucide-react";
import { Card } from "./Card";

interface MetricCardProps {
  label: string;
  value: string | number;
  detail: string;
  icon: LucideIcon;
  tone?: "default" | "warning" | "danger";
}

export function MetricCard({
  label,
  value,
  detail,
  icon: Icon,
  tone = "default",
}: MetricCardProps): React.JSX.Element {
  return (
    <Card className={`metric-card metric-card--${tone}`}>
      <div className="metric-card__icon" aria-hidden="true">
        <Icon size={18} strokeWidth={1.8} />
      </div>
      <p>{label}</p>
      <strong>{value}</strong>
      <span>{detail}</span>
    </Card>
  );
}
