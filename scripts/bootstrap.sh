#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT_DIR"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required: https://docs.astral.sh/uv/getting-started/installation/" >&2
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "Node.js and npm are required for the Control Room." >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is required for the Control Room." >&2
  exit 1
fi
NODE_VERSION="$(node -p 'process.versions.node')"
if ! node -e '
const [major, minor] = process.versions.node.split(".").map(Number);
const supported = (major === 20 && minor >= 19) ||
  (major === 22 && minor >= 13) || major > 22;
process.exit(supported ? 0 : 1);
'; then
  echo "Unsupported Node.js ${NODE_VERSION}; expected ^20.19.0 or >=22.13.0." >&2
  exit 1
fi

uv sync --all-groups --frozen
if [[ "$(uname -s)" == "Darwin" ]]; then
  # macOS can mark underscore-prefixed editable-install .pth files as hidden.
  # Python's site loader then skips them, leaving the generated `verity`
  # entry point unable to import the project. Clear the flag before the CLI
  # smoke check; this changes only disposable virtual-environment metadata.
  chflags -R nohidden .venv 2>/dev/null || true
fi
env -u PYTHONPATH .venv/bin/python -c "import verity_cordon"
env -u PYTHONPATH .venv/bin/verity --help >/dev/null
npm ci --prefix apps/control-room
npm run build --prefix apps/control-room

echo "Bootstrap complete. No signing key, database, or credential was created."
