#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR/src"

if [[ ! -x .venv/bin/python ]]; then
  echo "Run ./scripts/bootstrap.sh before verification." >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "A supported Node.js release and npm are required for verification." >&2
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

if [[ "$(uname -s)" == "Darwin" ]]; then
  # uv can recreate the underscore-prefixed editable-install .pth file with
  # macOS's hidden flag after an earlier command. Python's site loader skips
  # that file, so normalize disposable virtual-environment metadata before
  # every standalone verification run as well as during bootstrap.
  chflags -R nohidden .venv 2>/dev/null || true
fi

env -u PYTHONPATH .venv/bin/python -c "import verity_cordon"
env -u PYTHONPATH .venv/bin/verity --help >/dev/null
.venv/bin/pip-audit --local --skip-editable
.venv/bin/ruff format --no-cache --check src tests evals
.venv/bin/ruff check --no-cache src tests evals
.venv/bin/mypy src
.venv/bin/python - <<'PY'
from pathlib import Path

import yaml
from openapi_spec_validator import validate

contract = Path("specs/001-codex-memory-firewall/contracts/verity-ipc.openapi.yaml")
validate(
    yaml.safe_load(contract.read_text(encoding="utf-8")),
    base_uri=contract.resolve().as_uri(),
)
PY
.venv/bin/pytest --cov=verity_cordon --cov-report=term-missing

PYTHONPATH="$ROOT_DIR/src:$ROOT_DIR/examples/poisoned-docs-mcp/src:$ROOT_DIR/examples/detector-plugin/src" \
  .venv/bin/pytest -q examples/poisoned-docs-mcp/tests examples/detector-plugin/tests

npm run typecheck --prefix apps/control-room
npm run lint --prefix apps/control-room
npm test --prefix apps/control-room
npm run build --prefix apps/control-room
npm audit --prefix apps/control-room --audit-level=high

if [[ -f evals/runners/run_fixture_evaluation.py ]]; then
  .venv/bin/python evals/runners/run_fixture_evaluation.py --check
fi

echo "All configured Verity Cordon verification gates passed."
