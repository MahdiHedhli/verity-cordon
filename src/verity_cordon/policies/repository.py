"""Append-only activation and last-known-good SQLite policy repository."""

from __future__ import annotations

from typing import Any

import aiosqlite
from pydantic import ValidationError

from verity_cordon.core.errors import LedgerIntegrityError, PolicyValidationError
from verity_cordon.core.models import (
    Actor,
    ActorType,
    EventEnvelope,
    EventInput,
    EventSourceClass,
    EventType,
    format_utc,
    new_id,
)
from verity_cordon.crypto.canonical import canonical_json, canonical_sha256_hex, parse_json_strict
from verity_cordon.ledger.store import SQLiteEventStore
from verity_cordon.policies.models import PolicyDocument


class SQLitePolicyRepository:
    def __init__(self, store: SQLiteEventStore) -> None:
        self.store = store

    async def get_active(self) -> PolicyDocument | None:
        connection = await self.store._connect()
        try:
            row = await (
                await connection.execute(
                    "SELECT validated_json FROM policies WHERE active = 1 LIMIT 1"
                )
            ).fetchone()
        finally:
            await connection.close()
        if row is None:
            return None
        try:
            return PolicyDocument.model_validate(parse_json_strict(str(row["validated_json"])))
        except (ValueError, ValidationError) as exc:
            raise PolicyValidationError("The last-known-good policy record is invalid.") from exc

    async def ensure_initial(self, policy: PolicyDocument) -> PolicyDocument:
        active = await self.get_active()
        if active is not None:
            return active
        return await self.activate(policy, actor_id="verity.bootstrap")

    async def record_rejection(self, raw: dict[str, Any], *, actor_id: str) -> None:
        if not self.store.healthy:
            return
        try:
            proposed_digest = canonical_sha256_hex(raw)
        except (TypeError, ValueError):
            proposed_digest = None
        await self.store.append(
            [
                EventInput(
                    stream_id=new_id(),
                    event_type=EventType.POLICY_ACTIVATION_REJECTED,
                    actor=Actor(type=ActorType.OPERATOR, id=actor_id),
                    source_class=EventSourceClass.OPERATOR_ACTION,
                    payload={
                        "proposed_digest": proposed_digest,
                        "failure_class": "PolicyValidationError",
                    },
                )
            ]
        )

    async def activate_raw(
        self,
        raw: dict[str, Any],
        *,
        actor_id: str,
    ) -> PolicyDocument:
        try:
            policy = PolicyDocument.model_validate(raw)
        except ValidationError as exc:
            await self.record_rejection(raw, actor_id=actor_id)
            raise PolicyValidationError("The proposed policy is invalid.") from exc
        return await self.activate(policy, actor_id=actor_id)

    async def activate(
        self,
        policy: PolicyDocument,
        *,
        actor_id: str,
    ) -> PolicyDocument:
        verification = await self.store.verify()
        if not verification.verified:
            raise LedgerIntegrityError("Policy activation requires a verified ledger.")
        occurred_at = format_utc()
        event_id = new_id()
        validated = policy.model_dump(mode="json")
        event = EventInput(
            event_id=event_id,
            stream_id=f"policy.{policy.policy_id}.{policy.version}",
            event_type=EventType.POLICY_ACTIVATED,
            actor=Actor(type=ActorType.OPERATOR, id=actor_id),
            source_class=EventSourceClass.OPERATOR_ACTION,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            payload={
                "policy_id": policy.policy_id,
                "version": policy.version,
                "content_digest": policy.content_digest,
                "mode": policy.mode.value,
                "policy": validated,
            },
            occurred_at=occurred_at,
        )

        async def project(
            connection: aiosqlite.Connection,
            _: list[EventEnvelope],
        ) -> None:
            await connection.execute("UPDATE policies SET active = 0 WHERE active = 1")
            existing = await (
                await connection.execute(
                    "SELECT content_digest FROM policies WHERE policy_id = ? AND version = ?",
                    (policy.policy_id, policy.version),
                )
            ).fetchone()
            if existing is not None and str(existing["content_digest"]) != policy.content_digest:
                raise PolicyValidationError(
                    "A policy ID and version cannot be reused with different content."
                )
            if existing is None:
                await connection.execute(
                    """
                    INSERT INTO policies(
                        policy_id, version, content_digest, validated_json, source_yaml,
                        activation_event_id, active
                    ) VALUES (?, ?, ?, ?, NULL, ?, 1)
                    """,
                    (
                        policy.policy_id,
                        policy.version,
                        policy.content_digest,
                        canonical_json(validated),
                        event_id,
                    ),
                )
            else:
                await connection.execute(
                    "UPDATE policies SET active = 1, activation_event_id = ? "
                    "WHERE policy_id = ? AND version = ?",
                    (event_id, policy.policy_id, policy.version),
                )

        await self.store.append_with_projection([event], project)
        return policy
