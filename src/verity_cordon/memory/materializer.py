"""SQLite-backed rebuildable memory and quarantine projections."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from verity_cordon.core.errors import LedgerError, LedgerIntegrityError
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
from verity_cordon.crypto.canonical import canonical_json, parse_json_strict
from verity_cordon.ledger.store import SQLiteEventStore
from verity_cordon.ledger.verify import LedgerVerifier


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
        chain = await self.event_store.verify(verify_view=False)
        if not chain.verified:
            raise LedgerIntegrityError("The signed history is not safe to replay.")
        events = await self.event_store.list_events()
        active, inventory, quarantine = LedgerVerifier.replay_memory_state(events)
        current_active = {
            item.memory_id: item.model_dump(mode="json")
            for item in await self.list_active()
        }
        current_quarantine = {
            item.candidate_id: item.model_dump(mode="json")
            for item in await self.list_quarantined()
        }
        changed = current_active != active or current_quarantine != quarantine
        if dry_run:
            return {
                "changed": changed,
                "active_count": len(active),
                "inventory_count": len(inventory),
                "quarantine_count": len(quarantine),
                "verified_history": True,
            }

        connection = await self.event_store._connect()
        try:
            await connection.execute("BEGIN IMMEDIATE")
            await connection.execute("DELETE FROM active_memories")
            await connection.execute("DELETE FROM memory_inventory")
            await connection.execute("DELETE FROM quarantined_memories")
            for record in active.values():
                await connection.execute(
                    """
                    INSERT INTO active_memories(
                        memory_id, candidate_id, namespace, kind, source_class,
                        status, record_json, last_event_sequence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["memory_id"],
                        record["candidate_id"],
                        record["namespace"],
                        record["kind"],
                        record["source_class"],
                        record["status"],
                        canonical_json(record),
                        record["last_event_sequence"],
                    ),
                )
            for record in inventory.values():
                await connection.execute(
                    """
                    INSERT INTO memory_inventory(
                        memory_id, candidate_id, namespace, kind, source_class,
                        status, record_json, last_event_sequence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["memory_id"],
                        record["candidate_id"],
                        record["namespace"],
                        record["kind"],
                        record["source_class"],
                        record["status"],
                        canonical_json(record),
                        record["last_event_sequence"],
                    ),
                )
            for record in quarantine.values():
                await connection.execute(
                    """
                    INSERT INTO quarantined_memories(
                        candidate_id, decision_id, namespace, kind, source_class,
                        record_json, quarantine_event_id, resolution_event_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        record["candidate_id"],
                        record["decision_id"],
                        record["namespace"],
                        record["kind"],
                        record["source_class"],
                        canonical_json(record),
                        record["quarantine_event_id"],
                    ),
                )
            await connection.commit()
        except BaseException:
            await connection.rollback()
            raise
        finally:
            await connection.close()
        verification = await self.event_store.verify()
        if not verification.verified:
            raise LedgerIntegrityError("The rebuilt memory view did not verify.")
        return {
            "changed": changed,
            "active_count": len(active),
            "inventory_count": len(inventory),
            "quarantine_count": len(quarantine),
            "verified_history": True,
            "verified_view": True,
        }
