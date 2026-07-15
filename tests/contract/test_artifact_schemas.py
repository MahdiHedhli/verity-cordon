"""Executable compatibility checks for the public JSON and OpenAPI contracts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from openapi_spec_validator import validate as validate_openapi

from tests.factories import make_candidate
from verity_cordon.core.models import (
    Actor,
    ActorType,
    EventInput,
    EventType,
    Mode,
)
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.detectors.builtin import PersistentInstructionDetector
from verity_cordon.ledger.store import SQLiteEventStore
from verity_cordon.policies.load import load_builtin_policy
from verity_cordon.semantic.fixture import FixtureSemanticAdjudicator

CONTRACTS = Path("specs/001-codex-memory-firewall/contracts")
JSON_SCHEMAS = tuple(sorted(CONTRACTS.glob("*.schema.json")))


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _validate(schema_name: str, instance: dict[str, Any]) -> None:
    schema = _load_json(CONTRACTS / schema_name)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(instance)


@pytest.mark.parametrize("schema_path", JSON_SCHEMAS, ids=lambda path: path.name)
def test_json_schema_is_valid_draft_2020_12(schema_path: Path) -> None:
    Draft202012Validator.check_schema(_load_json(schema_path))


def test_openapi_contract_is_structurally_valid() -> None:
    contract = CONTRACTS / "verity-ipc.openapi.yaml"
    document = yaml.safe_load(contract.read_text(encoding="utf-8"))
    validate_openapi(document, base_uri=contract.resolve().as_uri())


@pytest.mark.asyncio
async def test_runtime_models_validate_against_public_json_contracts(tmp_path: Path) -> None:
    candidate = make_candidate()
    detector = await PersistentInstructionDetector().inspect(candidate)
    semantic = await FixtureSemanticAdjudicator().assess(candidate)
    policy = load_builtin_policy(Mode.ENFORCE)

    key_provider = FileKeyProvider.generate(tmp_path / "signing-key.pem")
    store = SQLiteEventStore(
        tmp_path / "verity.sqlite3",
        key_provider,
        tmp_path / "ledger-head.json",
    )
    await store.initialize()
    (event,) = await store.append(
        [
            EventInput(
                stream_id=candidate.session_id,
                event_type=EventType.EVIDENCE_CAPTURED,
                actor=Actor(type=ActorType.SYSTEM, id="verity.system"),
                session_id=candidate.session_id,
                payload={"content_digest": candidate.content_digest},
            )
        ]
    )

    _validate("memory-candidate.schema.json", candidate.model_dump(mode="json"))
    _validate("detector-result.schema.json", detector.model_dump(mode="json"))
    _validate("semantic-assessment.schema.json", semantic.model_dump(mode="json"))
    _validate("policy.schema.json", policy.model_dump(mode="json"))
    _validate("event-envelope.schema.json", event.model_dump(mode="json"))
