"""Persistent same-installation idempotency for authenticated mutations."""

from __future__ import annotations

import asyncio
import hmac
import re
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from verity_cordon.core.errors import ConflictError, LedgerError
from verity_cordon.core.models import format_utc
from verity_cordon.crypto.canonical import canonical_json, canonical_sha256_hex, parse_json_strict
from verity_cordon.ledger.store import SQLiteEventStore

_KEY = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
_IN_PROGRESS = canonical_json({"_verity_state": "in_progress"})


class IdempotencyStore:
    def __init__(self, store: SQLiteEventStore) -> None:
        self.store = store
        self._lock = asyncio.Lock()

    async def run(
        self,
        *,
        operation: str,
        key: str,
        request_payload: Mapping[str, Any],
        action: Callable[[], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        if not self.store.healthy:
            raise LedgerError("The ledger is unhealthy; mutations are disabled.")
        if _KEY.fullmatch(key) is None:
            raise ConflictError("The idempotency key format is invalid.")
        request_digest = canonical_sha256_hex(
            {"operation": operation, "request": dict(request_payload)}
        )
        async with self._lock:
            connection = await self.store._connect()
            try:
                await connection.execute("BEGIN IMMEDIATE")
                row = await (
                    await connection.execute(
                        "SELECT request_digest, response_json FROM idempotency_keys "
                        "WHERE operation = ? AND idempotency_key = ?",
                        (operation, key),
                    )
                ).fetchone()
                if row is None:
                    await connection.execute(
                        """
                        INSERT INTO idempotency_keys(
                            operation, idempotency_key, request_digest,
                            response_json, created_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (operation, key, request_digest, _IN_PROGRESS, format_utc()),
                    )
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise
            finally:
                await connection.close()
            if row is not None:
                if not hmac.compare_digest(str(row["request_digest"]), request_digest):
                    raise ConflictError(
                        "The idempotency key was already used for a different request."
                    )
                if hmac.compare_digest(str(row["response_json"]), _IN_PROGRESS):
                    raise ConflictError(
                        "The prior operation has an indeterminate completion state; "
                        "the mutation was not repeated."
                    )
                replay = parse_json_strict(str(row["response_json"]))
                if not isinstance(replay, dict):
                    raise ConflictError("The idempotency record is invalid.")
                response = dict(replay)
                if "duplicate" in response:
                    response["duplicate"] = True
                return response

            try:
                response = await action()
            except BaseException:
                await self._release_failed_reservation(operation, key, request_digest)
                raise
            connection = await self.store._connect()
            try:
                await connection.execute("BEGIN IMMEDIATE")
                cursor = await connection.execute(
                    """
                    UPDATE idempotency_keys
                    SET response_json = ?
                    WHERE operation = ? AND idempotency_key = ?
                      AND request_digest = ? AND response_json = ?
                    """,
                    (
                        canonical_json(response),
                        operation,
                        key,
                        request_digest,
                        _IN_PROGRESS,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ConflictError("The idempotency reservation changed unexpectedly.")
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise
            finally:
                await connection.close()
            return response

    async def _release_failed_reservation(
        self,
        operation: str,
        key: str,
        request_digest: str,
    ) -> None:
        connection = await self.store._connect()
        try:
            await connection.execute("BEGIN IMMEDIATE")
            await connection.execute(
                """
                DELETE FROM idempotency_keys
                WHERE operation = ? AND idempotency_key = ?
                  AND request_digest = ? AND response_json = ?
                """,
                (operation, key, request_digest, _IN_PROGRESS),
            )
            await connection.commit()
        except BaseException:
            await connection.rollback()
            raise
        finally:
            await connection.close()
