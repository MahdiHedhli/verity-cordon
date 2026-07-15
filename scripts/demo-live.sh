#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  echo "OPENAI_API_KEY must be set for explicit live mode; its value is never printed." >&2
  exit 1
fi
if [[ ! -x .venv/bin/verity || ! -f apps/control-room/dist/index.html ]]; then
  "$ROOT_DIR/scripts/bootstrap.sh"
fi

DEMO_DIR="${VERITY_LIVE_DEMO_DATA_DIR:-$ROOT_DIR/.verity-live-demo}"
if [[ "$DEMO_DIR" == "$ROOT_DIR/.verity-live-demo" ]]; then
  rm -rf -- "$DEMO_DIR"
fi

export VERITY_DATA_DIR="$DEMO_DIR"
export VERITY_SEMANTIC_PROVIDER="openai"
export VERITY_OPENAI_MODEL="${VERITY_OPENAI_MODEL:-gpt-5.6}"

if [[ -z "${VERITY_CONTROL_ROOM_PASSPHRASE:-}" ]]; then
  if [[ "${VERITY_DEMO_NO_SERVE:-0}" == "1" ]]; then
    VERITY_CONTROL_ROOM_PASSPHRASE="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(24))')"
  elif [[ -t 0 && -t 1 ]]; then
    read -r -s -p "Create a local Control Room passphrase (12+ characters): " VERITY_CONTROL_ROOM_PASSPHRASE
    echo >&2
  else
    echo "Set VERITY_CONTROL_ROOM_PASSPHRASE when starting the Control Room non-interactively." >&2
    exit 1
  fi
fi
if (( ${#VERITY_CONTROL_ROOM_PASSPHRASE} < 12 )); then
  echo "VERITY_CONTROL_ROOM_PASSPHRASE must contain at least 12 characters." >&2
  exit 1
fi
export VERITY_CONTROL_ROOM_PASSPHRASE

if [[ "${VERITY_DEMO_NO_SERVE:-0}" == "1" ]]; then
  uv run verity demo live --no-serve
else
  echo "Control Room: http://127.0.0.1:8765"
  echo "Use the passphrase you supplied to unlock trust-changing actions. It is not printed."
  echo "Live mode uses the configured OpenAI provider; no fixture fallback is allowed."
  uv run verity demo live --serve
fi
