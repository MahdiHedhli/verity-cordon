import { KeyRound, LockKeyhole } from "lucide-react";
import { useCallback, useId, useRef, useState, type SyntheticEvent } from "react";
import { ApiError } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { useDialogFocusTrap } from "../hooks/useDialogFocusTrap";
import { Button } from "./Button";

interface UnlockDialogProps {
  open: boolean;
  onClose: () => void;
}

export function UnlockDialog({ open, onClose }: UnlockDialogProps): React.JSX.Element | null {
  const { unlock } = useAuth();
  const titleId = useId();
  const descriptionId = useId();
  const passphraseId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = useCallback(() => {
    setError(null);
    formRef.current?.reset();
    onClose();
  }, [onClose]);

  useDialogFocusTrap(dialogRef, open, close, busy);

  if (!open) return null;

  const handleSubmit = async (event: SyntheticEvent<HTMLFormElement, SubmitEvent>) => {
    event.preventDefault();
    const input = inputRef.current;
    if (!input || input.value.length < 12) return;

    setBusy(true);
    setError(null);
    const passphrase = input.value;
    input.value = "";
    formRef.current?.reset();
    try {
      await unlock(passphrase);
      close();
    } catch (caught) {
      const message = caught instanceof ApiError
        ? caught.message
        : caught instanceof Error
          ? caught.message
          : "The local proof could not be created.";
      setError(message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="dialog-backdrop">
      <section
        aria-describedby={descriptionId}
        aria-labelledby={titleId}
        aria-modal="true"
        className="dialog dialog--unlock"
        ref={dialogRef}
        role="dialog"
      >
        <form ref={formRef} onSubmit={(event) => void handleSubmit(event)}>
          <div className="unlock-icon" aria-hidden="true"><KeyRound size={21} /></div>
          <p className="eyebrow">Local operator check</p>
          <h2 id={titleId}>Unlock security actions</h2>
          <p id={descriptionId}>
            Your passphrase derives a one-time proof in this browser. The passphrase is never sent
            to the daemon, stored, or rendered back into the page.
          </p>
          <label htmlFor={passphraseId}>Control Room passphrase</label>
          <input
            autoComplete="off"
            id={passphraseId}
            minLength={12}
            name="verity-control-room-passphrase"
            ref={inputRef}
            required
            spellCheck={false}
            type="password"
          />
          <div className="secure-note">
            <LockKeyhole aria-hidden="true" size={16} />
            <span>PBKDF2-HMAC-SHA256 · 310,000 iterations · one-time nonce</span>
          </div>
          {error ? <p className="form-error" role="alert">{error}</p> : null}
          <div className="dialog__actions">
            <Button disabled={busy} onClick={close} variant="quiet">Cancel</Button>
            <Button disabled={busy} type="submit">
              {busy ? "Deriving proof…" : "Unlock actions"}
            </Button>
          </div>
        </form>
      </section>
    </div>
  );
}
