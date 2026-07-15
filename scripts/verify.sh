#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

env -u PYTHONPATH .venv/bin/python -c "import verity_cordon"
env -u PYTHONPATH .venv/bin/verity --help >/dev/null
uv run pip-audit --local --skip-editable
uv run ruff format --check src tests evals
uv run ruff check src tests evals
uv run mypy src
uv run python - <<'PY'
from pathlib import Path

import yaml
from openapi_spec_validator import validate

contract = Path("specs/001-codex-memory-firewall/contracts/verity-ipc.openapi.yaml")
validate(
    yaml.safe_load(contract.read_text(encoding="utf-8")),
    base_uri=contract.resolve().as_uri(),
)
PY
uv run pytest --cov=verity_cordon --cov-report=term-missing

PYTHONPATH="src:examples/poisoned-docs-mcp/src:examples/detector-plugin/src" \
  uv run pytest -q examples/poisoned-docs-mcp/tests examples/detector-plugin/tests

npm run typecheck --prefix apps/control-room
npm run lint --prefix apps/control-room
npm test --prefix apps/control-room
npm run build --prefix apps/control-room
npm audit --prefix apps/control-room --audit-level=high

if [[ -f evals/runners/run_fixture_evaluation.py ]]; then
  uv run python evals/runners/run_fixture_evaluation.py --check
fi

echo "All configured Verity Cordon verification gates passed."
