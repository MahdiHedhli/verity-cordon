"""Append-only manual approval, block, revocation, preview, and replay actions."""

from __future__ import annotations

from typing import Any

import aiosqlite

from verity_cordon.core.errors import ConflictError, LedgerIntegrityError, NotFoundError
from verity_cordon.core.models import (
    Action,
    Actor,
    ActorType,
    EventEnvelope,
    EventInput,
    EventSourceClass,
    EventType,
    MemoryRecord,
    format_utc,
    new_id,
)
from verity_cordon.crypto.canonical import canonical_json, parse_json_strict
from verity_cordon.detectors.builtin import SecretSanitizer
from verity_cordon.ledger.store import SQLiteEventStore
from verity_cordon.memory.materializer import SQLiteMemoryView
from verity_cordon.telemetry.instrumentation import span


def _operator_actor(actor_id: str) -> Actor:
    safe = "".join(
        character if character.isalnum() or character in "._:-" else "-" for character in actor_id
    )
    if len(safe) < 8:
        safe = f"operator.{safe}"
    return Actor(type=ActorType.OPERATOR, id=safe[:128])


class TrustActions:
    def __init__(self, store: SQLiteEventStore, view: SQLiteMemoryView) -> None:
        self.store = store
        self.view = view
        self.sanitizer = SecretSanitizer()

    async def _require_verified_history(self) -> None:
        verification = await self.store.verify()
        if not verification.verified:
            raise LedgerIntegrityError("Trust actions require a verified ledger and memory view.")

    def _safe_reason(self, reason: str) -> str:
        normalized = self.sanitizer.sanitize(reason.strip()).text
        if not normalized:
            raise ConflictError("A non-empty reason is required.")
        return normalized[:500]

    async def preview_revocation(self, memory_id: str) -> dict[str, Any]:
        await self._require_verified_history()
        active = await self.view.list_active()
        target = next((item for item in active if item.memory_id == memory_id), None)
        if target is None:
            raise NotFoundError("The active memory was not found.")
        return {
            "memory_id": target.memory_id,
            "namespace": target.namespace,
            "kind": target.kind.value,
            "active_before": len(active),
            "active_after": len(active) - 1,
            "unrelated_preserved": len(active) - 1,
            "requires_confirmation": True,
        }

    async def revoke(
        self,
        memory_id: str,
        *,
        actor_id: str,
        reason: str,
        confirmed: bool,
    ) -> MemoryRecord:
        if not confirmed:
            raise ConflictError("Revocation requires explicit confirmation.")
        await self._require_verified_history()
        active = await self.view.list_active()
        target = next((item for item in active if item.memory_id == memory_id), None)
        if target is None:
            raise NotFoundError("The active memory was not found.")
        safe_reason = self._safe_reason(reason)
        event_id = new_id()
        occurred_at = format_utc()
        event = EventInput(
            event_id=event_id,
            stream_id=target.candidate_id,
            event_type=EventType.MEMORY_REVOKED,
            actor=_operator_actor(actor_id),
            session_id=target.session_id,
            source_class=EventSourceClass.OPERATOR_ACTION,
            memory_id=target.memory_id,
            policy_id=target.policy_id,
            policy_version=target.policy_version,
            payload={
                "memory_id": target.memory_id,
                "commit_event_id": target.commit_event_id,
                "reason": safe_reason,
                "previous_status": target.status,
            },
            occurred_at=occurred_at,
        )

        async def project(
            connection: aiosqlite.Connection,
            envelopes: list[EventEnvelope],
        ) -> None:
            sequence = envelopes[0].sequence_number
            revoked = target.model_copy(
                update={
                    "status": "revoked",
                    "last_event_id": event_id,
                    "last_event_sequence": sequence,
                }
            )
            await connection.execute(
                "DELETE FROM active_memories WHERE memory_id = ?",
                (target.memory_id,),
            )
            cursor = await connection.execute(
                """
                UPDATE memory_inventory
                SET status = 'revoked', record_json = ?, last_event_sequence = ?
                WHERE memory_id = ?
                """,
                (
                    canonical_json(revoked.model_dump(mode="json")),
                    sequence,
                    target.memory_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ConflictError("The memory inventory changed during revocation.")

        async with span(
            "verity.memory.revoke",
            memory_id=target.memory_id,
            action="revoke",
        ):
            await self.store.append_with_projection([event], project)
            verification = await self.store.verify()
        if not verification.verified:
            raise LedgerIntegrityError("Revocation committed but replay verification failed.")
        return target.model_copy(
            update={
                "status": "revoked",
                "last_event_id": event_id,
                "last_event_sequence": verification.observed_head_sequence,
            }
        )

    async def approve(
        self,
        candidate_id: str,
        *,
        actor_id: str,
        reason: str,
        confirmed: bool,
    ) -> MemoryRecord:
        if not confirmed:
            raise ConflictError("Approval requires explicit confirmation.")
        await self._require_verified_history()
        quarantined = await self.view.list_quarantined()
        target = next((item for item in quarantined if item.candidate_id == candidate_id), None)
        if target is None:
            raise NotFoundError("The quarantined candidate was not found.")
        safe_reason = self._safe_reason(reason)
        connection = await self.store._connect()
        try:
            row = await (
                await connection.execute(
                    "SELECT record_json FROM memory_candidates WHERE candidate_id = ?",
                    (candidate_id,),
                )
            ).fetchone()
        finally:
            await connection.close()
        if row is None:
            raise NotFoundError("The candidate record was not found.")
        candidate = parse_json_strict(str(row["record_json"]))
        memory_id = new_id()
        event_id = new_id()
        occurred_at = format_utc()
        payload = {
            "candidate_id": candidate_id,
            "decision_id": target.decision_id,
            "memory_id": memory_id,
            "safe_statement": target.safe_statement,
            "namespace": target.namespace,
            "kind": target.kind.value,
            "source_class": target.source_class.value,
            "actual_action": "allow",
            "would_have_action": target.would_have_action.value,
            "shadow_mode": False,
            "expires_at": None,
            "risk_categories": target.risk_categories,
            "semantic_provider": target.semantic_provider.value,
            "reason": safe_reason,
            "quarantine_event_id": target.quarantine_event_id,
        }
        event = EventInput(
            event_id=event_id,
            stream_id=candidate_id,
            event_type=EventType.MEMORY_APPROVED,
            actor=_operator_actor(actor_id),
            session_id=str(candidate["session_id"]),
            task_id=candidate.get("task_id"),
            source_class=EventSourceClass.OPERATOR_ACTION,
            memory_id=memory_id,
            policy_id=target.policy_id,
            policy_version=target.policy_version,
            payload=payload,
            occurred_at=occurred_at,
        )

        async def project(
            database: aiosqlite.Connection,
            envelopes: list[EventEnvelope],
        ) -> None:
            sequence = envelopes[0].sequence_number
            record = MemoryRecord(
                memory_id=memory_id,
                commit_event_id=event_id,
                candidate_id=candidate_id,
                session_id=str(candidate["session_id"]),
                safe_statement=target.safe_statement,
                namespace=target.namespace,
                kind=target.kind,
                source_class=target.source_class,
                status="active",
                trust_decision="manually_approved",
                policy_id=target.policy_id,
                policy_version=target.policy_version,
                actual_action=Action.ALLOW,
                would_have_action=target.would_have_action,
                committed_at=occurred_at,
                expires_at=None,
                shadow_admitted=False,
                manual_approval_event_id=event_id,
                risk_categories=target.risk_categories,
                semantic_provider=target.semantic_provider,
                last_event_id=event_id,
                last_event_sequence=sequence,
            )
            serialized = canonical_json(record.model_dump(mode="json"))
            parameters = (
                record.memory_id,
                record.candidate_id,
                record.namespace,
                record.kind.value,
                record.source_class.value,
                record.status,
                serialized,
                record.last_event_sequence,
            )
            await database.execute(
                """
                INSERT INTO active_memories(
                    memory_id, candidate_id, namespace, kind, source_class,
                    status, record_json, last_event_sequence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                parameters,
            )
            await database.execute(
                """
                INSERT INTO memory_inventory(
                    memory_id, candidate_id, namespace, kind, source_class,
                    status, record_json, last_event_sequence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                parameters,
            )
            await database.execute(
                "DELETE FROM quarantined_memories WHERE candidate_id = ?",
                (candidate_id,),
            )

        await self.store.append_with_projection([event], project)
        records = await self.view.list_active()
        return next(item for item in records if item.memory_id == memory_id)

    async def block(
        self,
        candidate_id: str,
        *,
        actor_id: str,
        reason: str,
        confirmed: bool,
    ) -> None:
        if not confirmed:
            raise ConflictError("Blocking requires explicit confirmation.")
        await self._require_verified_history()
        target = next(
            (
                item
                for item in await self.view.list_quarantined()
                if item.candidate_id == candidate_id
            ),
            None,
        )
        if target is None:
            raise NotFoundError("The quarantined candidate was not found.")
        event_id = new_id()
        event = EventInput(
            event_id=event_id,
            stream_id=candidate_id,
            event_type=EventType.MEMORY_BLOCKED,
            actor=_operator_actor(actor_id),
            source_class=EventSourceClass.OPERATOR_ACTION,
            payload={
                "candidate_id": candidate_id,
                "decision_id": target.decision_id,
                "reason": self._safe_reason(reason),
                "quarantine_event_id": target.quarantine_event_id,
            },
        )

        async def project(
            database: aiosqlite.Connection,
            _: list[EventEnvelope],
        ) -> None:
            await database.execute(
                "DELETE FROM quarantined_memories WHERE candidate_id = ?",
                (candidate_id,),
            )

        await self.store.append_with_projection([event], project)
