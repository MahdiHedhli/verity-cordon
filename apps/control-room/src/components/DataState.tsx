import { AlertTriangle, LoaderCircle } from "lucide-react";
import { ApiError } from "../api/client";

interface DataStateProps {
  loading?: boolean;
  error?: Error | null;
  empty?: boolean;
  emptyTitle?: string;
  emptyMessage?: string;
}

export function DataState({
  loading = false,
  error = null,
  empty = false,
  emptyTitle = "Nothing to show",
  emptyMessage = "No records match the current view.",
}: DataStateProps): React.JSX.Element | null {
  if (loading) {
    return (
      <div aria-live="polite" className="data-state">
        <LoaderCircle aria-hidden="true" className="spin" size={20} />
        <p>Reading verified local state…</p>
      </div>
    );
  }
  if (error) {
    const message = error instanceof ApiError ? error.message : "The local daemon could not be reached.";
    return (
      <div className="data-state data-state--error" role="alert">
        <AlertTriangle aria-hidden="true" size={20} />
        <div>
          <strong>Unable to load this view</strong>
          <p>{message}</p>
        </div>
      </div>
    );
  }
  if (empty) {
    return (
      <div className="data-state">
        <div>
          <strong>{emptyTitle}</strong>
          <p>{emptyMessage}</p>
        </div>
      </div>
    );
  }
  return null;
}
