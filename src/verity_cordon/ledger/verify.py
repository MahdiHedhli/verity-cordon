"""Independent signed-chain, expected-head, and materialized-view verification."""

from __future__ import annotations

import base64
import hmac
from dataclasses import dataclass
from typing import Any

import aiosqlite
from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError

from verity_cordon.core.errors import LedgerError
from verity_cordon.core.models import (
    Action,
    EventEnvelope,
    EventType,
    LedgerVerification,
    format_utc,
)
from verity_cordon.crypto.canonical import (
    canonical_json,
    canonical_json_bytes,
    canonical_sha256_hex,
    parse_json_strict,
    sha256_hex,
)
from verity_cordon.crypto.keys import decode_public_key
from verity_cordon.ledger.store import GENESIS_HASH, SQLiteEventStore


@dataclass(frozen=True, slots=True)
class _Failure:
    failure_class: str
    event_id: str | None = None


class LedgerVerifier:
    def __init__(self, store: SQLiteEventStore) -> None:
        self.store = store

    def _result(
        self,
        *,
        verified: bool,
        completeness_state: str,
        expected_head_source: str,
        expected_head_sequence: int | None,
        observed_head_sequence: int | None,
        total_events: int,
        failure: _Failure | None,
        view_consistent: bool,
    ) -> LedgerVerification:
        return LedgerVerification(
            verified=verified,
            completeness_state=completeness_state,
            expected_head_source=expected_head_source,
            expected_head_sequence=expected_head_sequence,
            observed_head_sequence=observed_head_sequence,
            total_events=total_events,
            first_invalid_event_id=failure.event_id if failure else None,
            failure_class=failure.failure_class if failure else None,
            signing_key_id=self.store.key_provider.key_id,
            public_key_fingerprint=self.store.key_provider.public_key_fingerprint,
            materialized_view_consistent=view_consistent,
            verified_at=format_utc(),
        )

    async def _load_rows(
        self, connection: aiosqlite.Connection
    ) -> tuple[list[aiosqlite.Row], dict[str, aiosqlite.Row], dict[str, aiosqlite.Row]]:
        events = await (
            await connection.execute(
                "SELECT * FROM events ORDER BY sequence_number ASC"
            )
        ).fetchall()
        payload_rows = await (
            await connection.execute("SELECT * FROM event_payloads")
        ).fetchall()
        key_rows = await (
            await connection.execute("SELECT * FROM signing_keys_public")
        ).fetchall()
        return (
            list(events),
            {str(row["payload_digest"]): row for row in payload_rows},
            {str(row["key_id"]): row for row in key_rows},
        )

    async def _verify_chain(
        self,
        connection: aiosqlite.Connection,
        rows: list[aiosqlite.Row],
        payloads: dict[str, aiosqlite.Row],
        keys: dict[str, aiosqlite.Row],
    ) -> tuple[list[EventEnvelope], _Failure | None]:
        del connection
        verified_events: list[EventEnvelope] = []
        expected_sequence = 1
        previous_hash = GENESIS_HASH
        for row in rows:
            raw_event_id = str(row["event_id"])
            if int(row["sequence_number"]) != expected_sequence:
                return verified_events, _Failure("noncontiguous_sequence", raw_event_id)
            try:
                parsed = parse_json_strict(str(row["envelope_json"]))
                if not isinstance(parsed, dict):
                    raise ValueError("event envelope is not an object")
                envelope = EventEnvelope.model_validate(parsed)
            except (ValueError, ValidationError):
                return verified_events, _Failure("invalid_event_envelope", raw_event_id)

            column_pairs = (
                (int(row["sequence_number"]), envelope.sequence_number),
                (str(row["event_id"]), envelope.event_id),
                (str(row["stream_id"]), envelope.stream_id),
                (str(row["event_type"]), envelope.event_type.value),
                (str(row["occurred_at"]), envelope.occurred_at),
                (str(row["payload_digest"]), envelope.payload_digest),
                (str(row["previous_event_hash"]), envelope.previous_event_hash),
                (str(row["event_hash"]), envelope.event_hash),
                (str(row["signature"]), envelope.signature),
                (str(row["signing_key_id"]), envelope.signing_key_id),
                (str(row["schema_version"]), envelope.schema_version),
            )
            if any(left != right for left, right in column_pairs):
                return verified_events, _Failure("column_envelope_mismatch", envelope.event_id)
            if not hmac.compare_digest(envelope.previous_event_hash, previous_hash):
                return verified_events, _Failure("previous_hash_mismatch", envelope.event_id)

            payload_row = payloads.get(envelope.payload_digest)
            if payload_row is None:
                return verified_events, _Failure("missing_payload", envelope.event_id)
            try:
                payload_bytes = bytes(payload_row["payload_bytes"])
                if int(payload_row["byte_length"]) != len(payload_bytes):
                    return verified_events, _Failure("payload_length_mismatch", envelope.event_id)
                parsed_payload = parse_json_strict(payload_bytes)
                canonical_payload = canonical_json_bytes(parsed_payload)
            except (ValueError, TypeError):
                return verified_events, _Failure("invalid_payload", envelope.event_id)
            if not hmac.compare_digest(sha256_hex(canonical_payload), envelope.payload_digest):
                return verified_events, _Failure("payload_digest_mismatch", envelope.event_id)
            if canonical_json(envelope.payload) != canonical_payload.decode("utf-8"):
                return verified_events, _Failure("payload_envelope_mismatch", envelope.event_id)

            event_body = envelope.model_dump(
                mode="json",
                exclude={"event_hash", "signature"},
            )
            computed_hash = canonical_sha256_hex(event_body)
            if not hmac.compare_digest(computed_hash, envelope.event_hash):
                return verified_events, _Failure("event_hash_mismatch", envelope.event_id)

            key_row = keys.get(envelope.signing_key_id)
            if key_row is None:
                return verified_events, _Failure("unknown_signing_key", envelope.event_id)
            try:
                raw_public = base64.b64decode(str(key_row["public_key"]), validate=True)
            except ValueError:
                return verified_events, _Failure("invalid_public_key", envelope.event_id)
            expected_key_id = f"vc-ed25519-{sha256_hex(raw_public)}"
            if (
                expected_key_id != envelope.signing_key_id
                or str(key_row["fingerprint"]) != sha256_hex(raw_public)
            ):
                return verified_events, _Failure("key_id_mismatch", envelope.event_id)
            try:
                signature = base64.b64decode(envelope.signature, validate=True)
                if base64.b64encode(signature).decode("ascii") != envelope.signature:
                    raise ValueError("noncanonical signature")
                public_key = decode_public_key(str(key_row["public_key"]))
                public_key.verify(signature, bytes.fromhex(envelope.event_hash))
            except InvalidSignature:
                return verified_events, _Failure("invalid_signature", envelope.event_id)
            except ValueError:
                return verified_events, _Failure("invalid_signature_encoding", envelope.event_id)

            verified_events.append(envelope)
            previous_hash = envelope.event_hash
            expected_sequence += 1
        return verified_events, None

    async def _verify_evidence_references(
        self,
        connection: aiosqlite.Connection,
        events: list[EventEnvelope],
    ) -> _Failure | None:
        rows = await (
            await connection.execute(
                "SELECT evidence_id, content_digest, protected_content, retention_state "
                "FROM evidence"
            )
        ).fetchall()
        evidence = {str(row["evidence_id"]): row for row in rows}
        for event in events:
            for reference in event.evidence_references:
                row = evidence.get(reference.evidence_id)
                if row is None:
                    return _Failure("missing_evidence_reference", event.event_id)
                if not hmac.compare_digest(str(row["content_digest"]), reference.digest):
                    return _Failure("evidence_digest_mismatch", event.event_id)
                protected = row["protected_content"]
                if protected is not None and not hmac.compare_digest(
                    sha256_hex(bytes(protected)), reference.digest
                ):
                    return _Failure("protected_evidence_tampered", event.event_id)
        return None

    @staticmethod
    def replay_memory_state(
        events: list[EventEnvelope],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        active: dict[str, dict[str, Any]] = {}
        inventory: dict[str, dict[str, Any]] = {}
        quarantine: dict[str, dict[str, Any]] = {}
        for event in events:
            payload = event.payload
            if event.event_type in {
                EventType.MEMORY_COMMITTED,
                EventType.MEMORY_REDACTED,
                EventType.MEMORY_APPROVED,
            }:
                memory_id = payload.get("memory_id")
                if not isinstance(memory_id, str) or event.session_id is None:
                    continue
                actual_action = str(payload["actual_action"])
                status = "redacted" if actual_action == Action.REDACT.value else "active"
                trust_decision = (
                    "manually_approved"
                    if event.event_type == EventType.MEMORY_APPROVED
                    else "shadow_admitted"
                    if bool(payload["shadow_mode"])
                    else "redacted"
                    if actual_action == Action.REDACT.value
                    else "allowed"
                )
                record = {
                    "memory_id": memory_id,
                    "commit_event_id": event.event_id,
                    "candidate_id": str(payload["candidate_id"]),
                    "session_id": event.session_id,
                    "safe_statement": str(payload["safe_statement"]),
                    "namespace": str(payload["namespace"]),
                    "kind": str(payload["kind"]),
                    "source_class": str(payload["source_class"]),
                    "status": status,
                    "trust_decision": trust_decision,
                    "policy_id": event.policy_id,
                    "policy_version": event.policy_version,
                    "actual_action": actual_action,
                    "would_have_action": str(payload["would_have_action"]),
                    "committed_at": event.occurred_at,
                    "expires_at": payload.get("expires_at"),
                    "shadow_admitted": bool(payload["shadow_mode"]),
                    "manual_approval_event_id": (
                        event.event_id
                        if event.event_type == EventType.MEMORY_APPROVED
                        else None
                    ),
                    "risk_categories": list(payload.get("risk_categories", [])),
                    "semantic_provider": str(payload["semantic_provider"]),
                    "last_event_id": event.event_id,
                    "last_event_sequence": event.sequence_number,
                }
                active[memory_id] = record
                inventory[memory_id] = record.copy()
                if event.event_type == EventType.MEMORY_APPROVED:
                    quarantine.pop(str(payload["candidate_id"]), None)
            elif event.event_type == EventType.MEMORY_QUARANTINED:
                candidate_id = str(payload["candidate_id"])
                quarantine[candidate_id] = {
                    "candidate_id": candidate_id,
                    "decision_id": str(payload["decision_id"]),
                    "safe_statement": str(payload["safe_statement"]),
                    "namespace": str(payload["namespace"]),
                    "kind": str(payload["kind"]),
                    "source_class": str(payload["source_class"]),
                    "risk_categories": list(payload.get("risk_categories", [])),
                    "policy_id": event.policy_id,
                    "policy_version": event.policy_version,
                    "quarantine_event_id": event.event_id,
                    "created_at": event.occurred_at,
                    "actual_action": "quarantine",
                    "would_have_action": str(payload["would_have_action"]),
                    "semantic_provider": str(payload["semantic_provider"]),
                    "resolution_event_id": None,
                }
            elif event.event_type == EventType.MEMORY_BLOCKED:
                blocked_candidate_id = payload.get("candidate_id")
                if isinstance(blocked_candidate_id, str):
                    quarantine.pop(blocked_candidate_id, None)
            elif event.event_type in {
                EventType.MEMORY_REVOKED,
                EventType.MEMORY_EXPIRED,
                EventType.MEMORY_SUPERSEDED,
            }:
                memory_id = event.memory_id or payload.get("memory_id")
                if not isinstance(memory_id, str):
                    continue
                active.pop(memory_id, None)
                if memory_id in inventory:
                    status = {
                        EventType.MEMORY_REVOKED: "revoked",
                        EventType.MEMORY_EXPIRED: "expired",
                        EventType.MEMORY_SUPERSEDED: "superseded",
                    }[event.event_type]
                    inventory[memory_id]["status"] = status
                    inventory[memory_id]["last_event_id"] = event.event_id
                    inventory[memory_id]["last_event_sequence"] = event.sequence_number
        return active, inventory, quarantine

    async def _stored_projection(
        self,
        connection: aiosqlite.Connection,
        table: str,
        key: str,
        *,
        where: str = "",
    ) -> dict[str, dict[str, Any]]:
        query = f"SELECT {key}, record_json FROM {table} {where}"  # noqa: S608
        rows = await (await connection.execute(query)).fetchall()
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            parsed = parse_json_strict(str(row["record_json"]))
            if not isinstance(parsed, dict):
                raise ValueError("projection record is not an object")
            result[str(row[key])] = parsed
        return result

    async def _verify_view(
        self,
        connection: aiosqlite.Connection,
        events: list[EventEnvelope],
    ) -> bool:
        expected_active, expected_inventory, expected_quarantine = self.replay_memory_state(events)
        try:
            stored_active = await self._stored_projection(
                connection, "active_memories", "memory_id"
            )
            stored_inventory = await self._stored_projection(
                connection, "memory_inventory", "memory_id"
            )
            stored_quarantine = await self._stored_projection(
                connection,
                "quarantined_memories",
                "candidate_id",
                where="WHERE resolution_event_id IS NULL",
            )
        except ValueError:
            return False
        return bool(
            expected_active == stored_active
            and expected_inventory == stored_inventory
            and expected_quarantine == stored_quarantine
        )

    async def verify(self, *, verify_view: bool = True) -> LedgerVerification:
        connection = await self.store._connect()
        try:
            rows, payloads, keys = await self._load_rows(connection)
            events, failure = await self._verify_chain(connection, rows, payloads, keys)
            observed_sequence = events[-1].sequence_number if events else 0
            if failure is not None:
                result = self._result(
                    verified=False,
                    completeness_state="invalid",
                    expected_head_source=(
                        "local_sidecar" if self.store.head_path.exists() else "none"
                    ),
                    expected_head_sequence=None,
                    observed_head_sequence=observed_sequence,
                    total_events=len(rows),
                    failure=failure,
                    view_consistent=False,
                )
                self.store._mark_unhealthy(failure.failure_class)
                return result

            evidence_failure = await self._verify_evidence_references(connection, events)
            if evidence_failure is not None:
                result = self._result(
                    verified=False,
                    completeness_state="invalid",
                    expected_head_source="local_sidecar",
                    expected_head_sequence=None,
                    observed_head_sequence=observed_sequence,
                    total_events=len(rows),
                    failure=evidence_failure,
                    view_consistent=False,
                )
                self.store._mark_unhealthy(evidence_failure.failure_class)
                return result

            view_consistent = await self._verify_view(connection, events) if verify_view else True
            if not view_consistent:
                failure = _Failure("materialized_view_drift")
                result = self._result(
                    verified=False,
                    completeness_state="invalid",
                    expected_head_source="local_sidecar",
                    expected_head_sequence=None,
                    observed_head_sequence=observed_sequence,
                    total_events=len(rows),
                    failure=failure,
                    view_consistent=False,
                )
                self.store._mark_unhealthy(failure.failure_class)
                return result

            if not self.store.head_path.exists():
                self.store._mark_unhealthy("expected_head_missing")
                return self._result(
                    verified=False,
                    completeness_state="tail_unproven",
                    expected_head_source="none",
                    expected_head_sequence=None,
                    observed_head_sequence=observed_sequence,
                    total_events=len(rows),
                    failure=_Failure("expected_head_missing"),
                    view_consistent=True,
                )
            try:
                head = await self.store.read_head()
            except LedgerError:
                failure = _Failure("expected_head_invalid")
                self.store._mark_unhealthy(failure.failure_class)
                return self._result(
                    verified=False,
                    completeness_state="invalid",
                    expected_head_source="local_sidecar",
                    expected_head_sequence=None,
                    observed_head_sequence=observed_sequence,
                    total_events=len(rows),
                    failure=failure,
                    view_consistent=True,
                )
            observed_hash = events[-1].event_hash if events else GENESIS_HASH
            if head.sequence_number != observed_sequence or not hmac.compare_digest(
                head.event_hash, observed_hash
            ):
                failure = _Failure(
                    "expected_head_mismatch",
                    events[-1].event_id if events else None,
                )
                self.store._mark_unhealthy(failure.failure_class)
                return self._result(
                    verified=False,
                    completeness_state="invalid",
                    expected_head_source="local_sidecar",
                    expected_head_sequence=head.sequence_number,
                    observed_head_sequence=observed_sequence,
                    total_events=len(rows),
                    failure=failure,
                    view_consistent=True,
                )

            self.store.healthy = True
            self.store.health_error = None
            return self._result(
                verified=True,
                completeness_state="anchored_complete",
                expected_head_source="local_sidecar",
                expected_head_sequence=head.sequence_number,
                observed_head_sequence=observed_sequence,
                total_events=len(rows),
                failure=None,
                view_consistent=True,
            )
        finally:
            await connection.close()
