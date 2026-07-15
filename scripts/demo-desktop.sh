#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT_DIR"

export VERITY_DATA_DIR="${VERITY_DATA_DIR:-$ROOT_DIR/.verity-desktop-demo}"

if [[ "${VERITY_CONFIRM_HOOK_TRUST:-}" != "1" ]]; then
  echo "Refusing to assert hook trust implicitly." >&2
  echo "Review the normal Verity hook, run 'uv run verity doctor --confirm-hook-trust', then set VERITY_CONFIRM_HOOK_TRUST=1 for this preview." >&2
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
  exit "$preview_status"
fi

echo
echo "Preview only: no Desktop demo state was changed."
echo "When ready, run these explicit steps:"
echo '  export VERITY_DESKTOP_SETUP_DIGEST="<copy preview.preview_digest above>"'
echo "  uv run verity demo desktop-setup --source-root \"$ROOT_DIR\" --confirm-hook-trust --expected-preview-digest \"\$VERITY_DESKTOP_SETUP_DIGEST\" --yes"
echo "  # Terminal A (leave running):"
echo "  uv run verity serve"
echo "  # Terminal B:"
echo "  uv run verity demo desktop-status --source-root \"$ROOT_DIR\" --confirm-hook-trust"
echo
echo "Then restart Codex Desktop, open a new task, and follow docs/hackathon/DEMO_SCRIPT.md."
echo "After the rehearsal, preview and confirm teardown separately:"
echo "  uv run verity demo desktop-teardown --source-root \"$ROOT_DIR\" --confirm-hook-trust"
echo '  export VERITY_DESKTOP_TEARDOWN_DIGEST="<copy preview.preview_digest above>"'
echo "  uv run verity demo desktop-teardown --source-root \"$ROOT_DIR\" --confirm-hook-trust --expected-preview-digest \"\$VERITY_DESKTOP_TEARDOWN_DIGEST\" --yes"
