"""Crash-safe reservation behavior for mutation idempotency keys."""

from __future__ import annotations

from pathlib import Path

import pytest

from verity_cordon.core.errors import ConflictError
from verity_cordon.crypto.canonical import canonical_json, canonical_sha256_hex
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.daemon.idempotency import IdempotencyStore
from verity_cordon.ledger.store import SQLiteEventStore


async def _store(tmp_path: Path) -> SQLiteEventStore:
    provider = FileKeyProvider.generate(tmp_path / "key.pem")
    store = SQLiteEventStore(
        tmp_path / "verity.sqlite3",
        provider,
        tmp_path / "ledger-head.json",
    )
    await store.initialize()
    return store


@pytest.mark.asyncio
async def test_failed_action_releases_reservation_for_safe_retry(tmp_path: Path) -> None:
    idempotency = IdempotencyStore(await _store(tmp_path))

    async def fail() -> dict[str, object]:
        raise RuntimeError("synthetic failure")

    async def succeed() -> dict[str, object]:
        return {"duplicate": False, "result": "safe"}

    with pytest.raises(RuntimeError, match="synthetic failure"):
        await idempotency.run(
            operation="test.operation",
            key="synthetic-key-0001",
            request_payload={"value": "same"},
            action=fail,
        )

    response = await idempotency.run(
        operation="test.operation",
        key="synthetic-key-0001",
        request_payload={"value": "same"},
        action=succeed,
    )
    assert response == {"duplicate": False, "result": "safe"}


@pytest.mark.asyncio
async def test_indeterminate_reservation_refuses_to_repeat_mutation(tmp_path: Path) -> None:
    store = await _store(tmp_path)
    idempotency = IdempotencyStore(store)
    operation = "test.operation"
    key = "synthetic-key-0002"
    request = {"value": "same"}
    digest = canonical_sha256_hex({"operation": operation, "request": request})
    connection = await store._connect()
    try:
        await connection.execute(
            """
            INSERT INTO idempotency_keys(
                operation, idempotency_key, request_digest, response_json, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                operation,
                key,
                digest,
                canonical_json({"_verity_state": "in_progress"}),
                "2026-07-15T00:00:00Z",
            ),
        )
        await connection.commit()
    finally:
        await connection.close()

    executed = False

    async def action() -> dict[str, object]:
        nonlocal executed
        executed = True
        return {"duplicate": False}

    with pytest.raises(ConflictError, match="indeterminate"):
        await idempotency.run(
            operation=operation,
            key=key,
            request_payload=request,
            action=action,
        )
    assert executed is False
