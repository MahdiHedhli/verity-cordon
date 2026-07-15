"""SQLite-backed rebuildable memory and quarantine projections."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from verity_cordon.core.errors import LedgerError
from verity_cordon.core.models import (
    Action,
    Identifier,
    MemoryKind,
    MemoryRecord,
    PolicyIdentifier,
    ProviderSummaryState,
    SourceClass,
    StrictModel,
)
from verity_cordon.crypto.canonical import parse_json_strict
from verity_cordon.ledger.store import SQLiteEventStore


class QuarantineRecord(StrictModel):
    candidate_id: Identifier
    decision_id: Identifier
    safe_statement: str = Field(min_length=1, max_length=8192)
    namespace: str
    kind: MemoryKind
    source_class: SourceClass
    risk_categories: list[str]
    policy_id: PolicyIdentifier
    policy_version: str
    quarantine_event_id: Identifier
    created_at: str
    actual_action: Literal[Action.QUARANTINE]
    would_have_action: Action
    semantic_provider: ProviderSummaryState
    resolution_event_id: Identifier | None = None


class SQLiteMemoryView:
    def __init__(self, event_store: SQLiteEventStore) -> None:
        self.event_store = event_store

    async def list_active(self) -> list[MemoryRecord]:
        connection = await self.event_store._connect()
        try:
            rows = await (
                await connection.execute(
                    "SELECT record_json FROM active_memories "
                    "ORDER BY namespace, memory_id"
                )
            ).fetchall()
        finally:
            await connection.close()
        try:
            return [
                MemoryRecord.model_validate(parse_json_strict(str(row["record_json"])))
                for row in rows
            ]
        except ValueError as exc:
            raise LedgerError("The active memory projection is invalid.") from exc

    async def list_quarantined(self) -> list[QuarantineRecord]:
        connection = await self.event_store._connect()
        try:
            rows = await (
                await connection.execute(
                    "SELECT record_json FROM quarantined_memories "
                    "WHERE resolution_event_id IS NULL ORDER BY candidate_id"
                )
            ).fetchall()
        finally:
            await connection.close()
        try:
            return [
                QuarantineRecord.model_validate(parse_json_strict(str(row["record_json"])))
                for row in rows
            ]
        except ValueError as exc:
            raise LedgerError("The quarantine projection is invalid.") from exc

    async def rebuild(self, *, dry_run: bool) -> dict[str, object]:
        del dry_run
        raise NotImplementedError("Deterministic replay is implemented with revocation support.")
