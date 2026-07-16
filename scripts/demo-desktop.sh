#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT_DIR"

export VERITY_DATA_DIR="${VERITY_DATA_DIR:-$ROOT_DIR/.verity-desktop-demo}"

if [[ "${VERITY_CONFIRM_HOOK_TRUST:-}" != "1" ]]; then
  echo "Refusing to assert hook trust implicitly." >&2
  echo "Start Codex CLI, use /hooks to review the exact Verity hook definitions and trust their current hashes, then exit the CLI." >&2
  echo "After that Codex-managed review, set VERITY_CONFIRM_HOOK_TRUST=1 for this preview; run full doctor after starting the daemon." >&2
  exit 2
fi

set +e
uv run verity demo desktop-setup \
  --source-root "$ROOT_DIR" \
  --confirm-hook-trust
preview_status=$?
set -e

if [[ $preview_status -ne 2 ]]; then
  echo "Desktop demo preview failed safely; resolve the reported readiness issue first." >&2
  if [[ $preview_status -eq 0 ]]; then
    exit 1
  fi
  exit "$preview_status"
fi

echo
echo "Preview only: no Desktop demo state was changed."
echo "When ready, run these explicit steps:"
echo "  # Close every ChatGPT Desktop task, exit Codex CLI/IDE sessions, and fully quit the ChatGPT desktop app."
echo '  export VERITY_DESKTOP_SETUP_DIGEST="<copy preview.preview_digest above>"'
echo "  uv run verity demo desktop-setup --source-root \"$ROOT_DIR\" --confirm-hook-trust --expected-preview-digest \"\$VERITY_DESKTOP_SETUP_DIGEST\" --yes"
echo "  # Terminal A (leave running):"
echo "  uv run verity serve"
echo "  # Terminal B:"
echo "  uv run verity doctor --confirm-hook-trust"
echo "  uv run verity demo desktop-status --source-root \"$ROOT_DIR\" --confirm-hook-trust"
echo
echo "Then restart Codex Desktop, open a new task, and follow specs/002-codex-desktop-subscription-defense/quickstart.md."
echo "Use docs/hackathon/DEMO_SCRIPT.md only as the timed recording narrative."
echo "After the rehearsal, preview and confirm teardown separately:"
echo "  # Close every ChatGPT Desktop task, exit Codex CLI/IDE sessions, and fully quit the ChatGPT desktop app."
echo "  uv run verity demo desktop-teardown --source-root \"$ROOT_DIR\" --confirm-hook-trust"
echo '  export VERITY_DESKTOP_TEARDOWN_DIGEST="<copy preview.preview_digest above>"'
echo "  uv run verity demo desktop-teardown --source-root \"$ROOT_DIR\" --confirm-hook-trust --expected-preview-digest \"\$VERITY_DESKTOP_TEARDOWN_DIGEST\" --yes"
