import { useEffect, type RefObject } from "react";

const focusableSelector = [
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "a[href]",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

export function useDialogFocusTrap(
  dialogRef: RefObject<HTMLElement | null>,
  active: boolean,
  onEscape: () => void,
  escapeDisabled = false,
): void {
  useEffect(() => {
    if (!active) return undefined;
    const dialog = dialogRef.current;
    const focusable = dialog
      ? Array.from(dialog.querySelectorAll<HTMLElement>(focusableSelector))
      : [];
    focusable[0]?.focus();

    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !escapeDisabled) {
        event.preventDefault();
        onEscape();
        return;
      }
      if (event.key !== "Tab" || focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };

    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [active, dialogRef, escapeDisabled, onEscape]);
}
