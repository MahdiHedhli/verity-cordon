"""Content-safe read projections for CLI and Control Room."""

from __future__ import annotations

from typing import Any

from verity_cordon.core.errors import NotFoundError
from verity_cordon.core.models import EventEnvelope, MemoryRecord
from verity_cordon.crypto.canonical import parse_json_strict
from verity_cordon.ledger.store import SQLiteEventStore


class LedgerQueries:
    def __init__(self, store: SQLiteEventStore) -> None:
        self.store = store

    async def list_memories(self) -> list[MemoryRecord]:
        connection = await self.store._connect()
        try:
            rows = await (
                await connection.execute(
                    "SELECT record_json FROM memory_inventory "
                    "ORDER BY last_event_sequence DESC"
                )
            ).fetchall()
        finally:
            await connection.close()
        return [
            MemoryRecord.model_validate(parse_json_strict(str(row["record_json"])))
            for row in rows
        ]

    async def get_memory(self, memory_id: str) -> MemoryRecord:
        items = await self.list_memories()
        match = next((item for item in items if item.memory_id == memory_id), None)
        if match is None:
            raise NotFoundError("The memory record was not found.")
        return match

    async def list_candidate_summaries(self) -> list[dict[str, Any]]:
        connection = await self.store._connect()
        try:
            rows = await (
                await connection.execute(
                    """
                    SELECT c.record_json AS candidate_json,
                           d.record_json AS decision_json,
                           s.record_json AS semantic_json,
                           CASE
                             WHEN q.candidate_id IS NOT NULL THEN 'quarantined'
                             WHEN a.candidate_id IS NOT NULL THEN a.status
                             WHEN EXISTS(
                               SELECT 1 FROM events e
                               WHERE e.stream_id = c.candidate_id
                                 AND e.event_type = 'MemoryBlocked'
                             ) THEN 'blocked'
                             ELSE 'unknown'
                           END AS status
                    FROM memory_candidates c
                    LEFT JOIN policy_decisions d ON d.candidate_id = c.candidate_id
                    LEFT JOIN semantic_assessments s ON s.candidate_id = c.candidate_id
                    LEFT JOIN quarantined_memories q
                      ON q.candidate_id = c.candidate_id AND q.resolution_event_id IS NULL
                    LEFT JOIN active_memories a ON a.candidate_id = c.candidate_id
                    ORDER BY c.rowid DESC
                    """
                )
            ).fetchall()
        finally:
            await connection.close()
        results: list[dict[str, Any]] = []
        for row in rows:
            candidate = parse_json_strict(str(row["candidate_json"]))
            decision = (
                parse_json_strict(str(row["decision_json"]))
                if row["decision_json"] is not None
                else None
            )
            semantic = (
                parse_json_strict(str(row["semantic_json"]))
                if row["semantic_json"] is not None
                else None
            )
            results.append(
                {
                    "candidate_id": candidate["candidate_id"],
                    "safe_statement": candidate["statement"],
                    "namespace": candidate["namespace"],
                    "kind": candidate["kind"],
                    "source_class": candidate["source_class"],
                    "session_id": candidate["session_id"],
                    "created_at": candidate["created_at"],
                    "status": str(row["status"]),
                    "policy_id": decision["policy_id"] if decision else None,
                    "policy_version": decision["policy_version"] if decision else None,
                    "actual_action": decision["actual_action"] if decision else None,
                    "would_have_action": (
                        decision["would_have_action"] if decision else None
                    ),
                    "shadow_mode": decision["shadow_mode"] if decision else False,
                    "risk_categories": semantic["categories"] if semantic else [],
                    "semantic_provider": (
                        semantic["provider_state"] if semantic else "deterministic_only"
                    ),
                }
            )
        return results

    async def get_candidate_detail(self, candidate_id: str) -> dict[str, Any]:
        connection = await self.store._connect()
        try:
            candidate_row = await (
                await connection.execute(
                    "SELECT record_json FROM memory_candidates WHERE candidate_id = ?",
                    (candidate_id,),
                )
            ).fetchone()
            if candidate_row is None:
                raise NotFoundError("The candidate record was not found.")
            detector_rows = await (
                await connection.execute(
                    "SELECT record_json FROM detector_results WHERE candidate_id = ? "
                    "ORDER BY rowid",
                    (candidate_id,),
                )
            ).fetchall()
            semantic_row = await (
                await connection.execute(
                    "SELECT record_json FROM semantic_assessments WHERE candidate_id = ? "
                    "ORDER BY rowid DESC LIMIT 1",
                    (candidate_id,),
                )
            ).fetchone()
            decision_row = await (
                await connection.execute(
                    "SELECT record_json FROM policy_decisions WHERE candidate_id = ? "
                    "ORDER BY rowid DESC LIMIT 1",
                    (candidate_id,),
                )
            ).fetchone()
        finally:
            await connection.close()
        events = [
            self._event_summary(event, chain_status="unverified")
            for event in await self.store.list_events()
            if event.stream_id == candidate_id
        ]
        return {
            "candidate": parse_json_strict(str(candidate_row["record_json"])),
            "detector_results": [
                parse_json_strict(str(row["record_json"])) for row in detector_rows
            ],
            "semantic_assessment": (
                parse_json_strict(str(semantic_row["record_json"]))
                if semantic_row is not None
                else None
            ),
            "policy_decision": (
                parse_json_strict(str(decision_row["record_json"]))
                if decision_row is not None
                else None
            ),
            "events": events,
        }

    def _event_summary(self, event: EventEnvelope, *, chain_status: str) -> dict[str, Any]:
        action = event.payload.get("actual_action")
        return {
            "event_id": event.event_id,
            "sequence_number": event.sequence_number,
            "event_type": event.event_type.value,
            "timestamp": event.occurred_at,
            "memory_id": event.memory_id,
            "source_class": event.source_class.value if event.source_class else None,
            "action": action if isinstance(action, str) else None,
            "policy_version": event.policy_version,
            "chain_status": chain_status,
        }

    async def list_event_summaries(self) -> list[dict[str, Any]]:
        verification = await self.store.verify()
        chain_status = "verified" if verification.verified else "failed"
        return [
            self._event_summary(event, chain_status=chain_status)
            for event in reversed(await self.store.list_events())
        ]

    async def statistics(self) -> dict[str, Any]:
        connection = await self.store._connect()
        try:
            decision_rows = await (
                await connection.execute("SELECT record_json FROM policy_decisions")
            ).fetchall()
            detector_failure_row = await (
                await connection.execute(
                    "SELECT COUNT(*) AS count FROM detector_results "
                    "WHERE json_extract(record_json, '$.status') != 'ok'"
                )
            ).fetchone()
            semantic_timeout_row = await (
                await connection.execute(
                    "SELECT COUNT(*) AS count FROM semantic_assessments "
                    "WHERE json_extract(record_json, '$.failure.class') = 'timeout'"
                )
            ).fetchone()
            revoked_row = await (
                await connection.execute(
                    "SELECT COUNT(*) AS count FROM memory_inventory WHERE status = 'revoked'"
                )
            ).fetchone()
            detector_failures = int(detector_failure_row["count"] if detector_failure_row else 0)
            semantic_timeouts = int(semantic_timeout_row["count"] if semantic_timeout_row else 0)
            revoked = int(revoked_row["count"] if revoked_row else 0)
        finally:
            await connection.close()
        decisions = [parse_json_strict(str(row["record_json"])) for row in decision_rows]
        counts = {
            "total_candidates": len(decisions),
            "allowed": sum(item["actual_action"] == "allow" for item in decisions),
            "redacted": sum(item["actual_action"] == "redact" for item in decisions),
            "quarantined": sum(
                item["actual_action"] == "quarantine" for item in decisions
            ),
            "blocked": sum(item["actual_action"] == "block" for item in decisions),
            "revoked": revoked,
        }
        verification = await self.store.verify()
        return {
            "schema_version": "1.0.0",
            "counts": counts,
            "semantic_timeouts": semantic_timeouts,
            "detector_failures": detector_failures,
            "average_evaluation_latency_ms": 0.0,
            "ledger_state": "verified" if verification.verified else "invalid",
        }
