import { useId, useRef, type ReactNode, type SyntheticEvent } from "react";
import { useDialogFocusTrap } from "../hooks/useDialogFocusTrap";
import { Button } from "./Button";

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  error?: string | null;
  reasonLabel?: string;
  children?: ReactNode;
  onCancel: () => void;
  onConfirm: (reason: string) => Promise<void>;
}

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  danger = false,
  busy = false,
  error = null,
  reasonLabel = "Reason",
  children,
  onCancel,
  onConfirm,
}: ConfirmDialogProps): React.JSX.Element | null {
  const titleId = useId();
  const descriptionId = useId();
  const inputId = useId();
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  useDialogFocusTrap(dialogRef, open, onCancel, busy);

  if (!open) return null;

  const handleSubmit = (event: SyntheticEvent<HTMLFormElement, SubmitEvent>) => {
    event.preventDefault();
    const reason = inputRef.current?.value.trim() ?? "";
    if (reason) void onConfirm(reason);
  };

  return (
    <div className="dialog-backdrop">
      <section
        aria-describedby={descriptionId}
        aria-labelledby={titleId}
        aria-modal="true"
        className="dialog"
        ref={dialogRef}
        role="dialog"
      >
        <form onSubmit={handleSubmit}>
          <div className={`dialog__marker ${danger ? "dialog__marker--danger" : ""}`} />
          <h2 id={titleId}>{title}</h2>
          <p id={descriptionId}>{description}</p>
          {children}
          <label htmlFor={inputId}>{reasonLabel}</label>
          <textarea
            id={inputId}
            ref={inputRef}
            maxLength={1000}
            minLength={1}
            placeholder="Record the operator rationale…"
            required
            rows={3}
          />
          {error ? <p className="form-error" role="alert">{error}</p> : null}
          <div className="dialog__actions">
            <Button disabled={busy} onClick={onCancel} variant="quiet">Cancel</Button>
            <Button disabled={busy} type="submit" variant={danger ? "danger" : "primary"}>
              {busy ? "Recording…" : confirmLabel}
            </Button>
          </div>
        </form>
      </section>
    </div>
  );
}
