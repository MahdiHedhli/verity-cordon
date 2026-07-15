"""Async signed append-only SQLite event store."""

from __future__ import annotations

import asyncio
import base64
import hmac
import os
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from verity_cordon.core.errors import LedgerError
from verity_cordon.core.models import (
    EventEnvelope,
    EventInput,
    LedgerVerification,
    format_utc,
    new_id,
)
from verity_cordon.crypto.canonical import (
    canonical_json,
    canonical_json_bytes,
    canonical_sha256_hex,
    parse_json_strict,
    sha256_bytes,
)
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.ledger.schema import SCHEMA_SQL, SCHEMA_VERSION

GENESIS_HASH = "0" * 64

ProjectionWriter = Callable[
    [aiosqlite.Connection, list[EventEnvelope]], Awaitable[None]
]


class _HeadBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(pattern=r"^1\.0\.0$")
    sequence_number: int = Field(ge=0)
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    signing_key_id: str = Field(pattern=r"^vc-ed25519-[0-9a-f]{64}$")


class _SignedHead(_HeadBody):
    signature: str = Field(pattern=r"^[A-Za-z0-9+/]{86}==$")


def _normalize_timestamp(value: str | None) -> str:
    if value is None:
        return format_utc()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LedgerError("An event timestamp is invalid.") from exc
    if parsed.tzinfo is None:
        raise LedgerError("An event timestamp must include a UTC offset.")
    return format_utc(parsed)


class SQLiteEventStore:
    def __init__(
        self,
        database_path: Path,
        key_provider: FileKeyProvider,
        head_path: Path,
    ) -> None:
        self.database_path = database_path
        self.key_provider = key_provider
        self.head_path = head_path
        self._write_lock = asyncio.Lock()
        self.healthy = True
        self.health_error: str | None = None

    async def _connect(self) -> aiosqlite.Connection:
        connection = await aiosqlite.connect(self.database_path)
        connection.row_factory = aiosqlite.Row
        await connection.execute("PRAGMA foreign_keys = ON")
        await connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    async def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.database_path.parent.chmod(0o700)
        connection = await self._connect()
        try:
            await connection.executescript(SCHEMA_SQL)
            await connection.execute(
                "INSERT OR IGNORE INTO schema_metadata(version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, format_utc()),
            )
            exported = await self.key_provider.export_public()
            await connection.execute(
                """
                INSERT OR IGNORE INTO signing_keys_public(
                    key_id, algorithm, public_key, fingerprint, created_at, status
                ) VALUES (?, ?, ?, ?, ?, 'active')
                """,
                (
                    exported["key_id"],
                    exported["algorithm"],
                    exported["public_key"],
                    exported["public_key_fingerprint"],
                    format_utc(),
                ),
            )
            row = await (
                await connection.execute(
                    "SELECT sequence_number, event_hash, signing_key_id "
                    "FROM events ORDER BY sequence_number DESC LIMIT 1"
                )
            ).fetchone()
            await connection.commit()
        finally:
            await connection.close()

        if row is None and not self.head_path.exists():
            await self._write_head(0, GENESIS_HASH)
        elif not self.head_path.exists():
            self._mark_unhealthy("expected_head_missing")
        else:
            try:
                head = await self.read_head()
                observed_sequence = int(row["sequence_number"]) if row is not None else 0
                observed_hash = str(row["event_hash"]) if row is not None else GENESIS_HASH
                if (
                    head.sequence_number != observed_sequence
                    or not hmac.compare_digest(head.event_hash, observed_hash)
                ):
                    self._mark_unhealthy("expected_head_mismatch")
                elif row is not None and str(row["signing_key_id"]) != self.key_provider.key_id:
                    self._mark_unhealthy("signing_key_mismatch")
            except LedgerError:
                self._mark_unhealthy("expected_head_invalid")

    def _mark_unhealthy(self, reason: str) -> None:
        self.healthy = False
        self.health_error = reason

    async def _build_head(self, sequence: int, event_hash: str) -> _SignedHead:
        body = _HeadBody(
            schema_version="1.0.0",
            sequence_number=sequence,
            event_hash=event_hash,
            signing_key_id=self.key_provider.key_id,
        )
        digest = sha256_bytes(canonical_json_bytes(body.model_dump(mode="json")))
        signature = await self.key_provider.sign(digest)
        return _SignedHead(
            **body.model_dump(mode="json"),
            signature=base64.b64encode(signature).decode("ascii"),
        )

    async def _write_head(self, sequence: int, event_hash: str) -> None:
        head = await self._build_head(sequence, event_hash)
        self.head_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.head_path.parent.chmod(0o700)
        temporary = self.head_path.with_name(f".{self.head_path.name}.{new_id()}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(canonical_json_bytes(head.model_dump(mode="json")))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.head_path)
            directory_descriptor = os.open(self.head_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    async def read_head(self) -> _SignedHead:
        if self.head_path.is_symlink():
            raise LedgerError("The expected ledger head must not be a symbolic link.")
        try:
            metadata = self.head_path.stat()
            if metadata.st_mode & 0o077:
                raise LedgerError("The expected ledger head has unsafe permissions.")
            raw = self.head_path.read_bytes()
            head = _SignedHead.model_validate(parse_json_strict(raw))
        except (OSError, ValueError, ValidationError) as exc:
            raise LedgerError("The expected ledger head is invalid.") from exc
        if head.signing_key_id != self.key_provider.key_id:
            raise LedgerError("The expected ledger head names an unknown key.")
        body = _HeadBody.model_validate(head.model_dump(exclude={"signature"}))
        digest = sha256_bytes(canonical_json_bytes(body.model_dump(mode="json")))
        try:
            signature = base64.b64decode(head.signature, validate=True)
            await self.key_provider.verify(digest, signature)
        except ValueError as exc:
            raise LedgerError("The expected ledger head signature is invalid.") from exc
        return head

    def decode_signature(self, event: EventEnvelope) -> bytes:
        try:
            signature = base64.b64decode(event.signature, validate=True)
        except ValueError as exc:
            raise LedgerError("An event signature encoding is invalid.") from exc
        if len(signature) != 64:
            raise LedgerError("An event signature length is invalid.")
        return signature

    async def append(self, events: Sequence[EventInput]) -> list[EventEnvelope]:
        return await self.append_with_projection(events, None)

    async def append_with_projection(
        self,
        events: Sequence[EventInput],
        projector: ProjectionWriter | None,
    ) -> list[EventEnvelope]:
        if not events:
            return []
        async with self._write_lock:
            if not self.healthy:
                raise LedgerError("The ledger is unhealthy; signed appends are disabled.")
            connection = await self._connect()
            committed = False
            envelopes: list[EventEnvelope] = []
            try:
                await connection.execute("BEGIN IMMEDIATE")
                row = await (
                    await connection.execute(
                        "SELECT sequence_number, event_hash FROM events "
                        "ORDER BY sequence_number DESC LIMIT 1"
                    )
                ).fetchone()
                sequence = int(row["sequence_number"]) if row is not None else 0
                previous_hash = str(row["event_hash"]) if row is not None else GENESIS_HASH

                for event_input in events:
                    sequence += 1
                    payload_bytes = canonical_json_bytes(event_input.payload)
                    payload_digest = canonical_sha256_hex(event_input.payload)
                    existing = await (
                        await connection.execute(
                            "SELECT payload_bytes FROM event_payloads WHERE payload_digest = ?",
                            (payload_digest,),
                        )
                    ).fetchone()
                    if existing is not None and not hmac.compare_digest(
                        bytes(existing["payload_bytes"]), payload_bytes
                    ):
                        raise LedgerError("A payload digest collision was detected.")
                    if existing is None:
                        await connection.execute(
                            """
                            INSERT INTO event_payloads(
                                payload_digest, payload_bytes, byte_length, created_at
                            ) VALUES (?, ?, ?, ?)
                            """,
                            (payload_digest, payload_bytes, len(payload_bytes), format_utc()),
                        )

                    body: dict[str, Any] = {
                        "schema_version": "1.0.0",
                        "event_id": event_input.event_id or new_id(),
                        "stream_id": event_input.stream_id,
                        "sequence_number": sequence,
                        "event_type": event_input.event_type.value,
                        "occurred_at": _normalize_timestamp(event_input.occurred_at),
                        "actor": event_input.actor.model_dump(mode="json"),
                        "session_id": event_input.session_id,
                        "task_id": event_input.task_id,
                        "source_class": (
                            event_input.source_class.value if event_input.source_class else None
                        ),
                        "memory_id": event_input.memory_id,
                        "evidence_references": [
                            reference.model_dump(mode="json")
                            for reference in event_input.evidence_references
                        ],
                        "policy_id": event_input.policy_id,
                        "policy_version": event_input.policy_version,
                        "detector_bundle_version": event_input.detector_bundle_version,
                        "semantic_model_identifier": event_input.semantic_model_identifier,
                        "payload": event_input.payload,
                        "payload_digest": payload_digest,
                        "previous_event_hash": previous_hash,
                        "canonicalization_algorithm": "VC-CJ-1",
                        "digest_algorithm": "SHA-256",
                        "signature_algorithm": "Ed25519",
                        "signing_key_id": self.key_provider.key_id,
                    }
                    event_hash = canonical_sha256_hex(body)
                    signature = await self.key_provider.sign(bytes.fromhex(event_hash))
                    envelope = EventEnvelope.model_validate(
                        {
                            **body,
                            "event_hash": event_hash,
                            "signature": base64.b64encode(signature).decode("ascii"),
                        }
                    )
                    envelope_json = canonical_json(envelope.model_dump(mode="json"))
                    await connection.execute(
                        """
                        INSERT INTO events(
                            sequence_number, event_id, stream_id, event_type, occurred_at,
                            envelope_json, payload_digest, previous_event_hash, event_hash,
                            signature, signing_key_id, schema_version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            envelope.sequence_number,
                            envelope.event_id,
                            envelope.stream_id,
                            envelope.event_type.value,
                            envelope.occurred_at,
                            envelope_json,
                            envelope.payload_digest,
                            envelope.previous_event_hash,
                            envelope.event_hash,
                            envelope.signature,
                            envelope.signing_key_id,
                            envelope.schema_version,
                        ),
                    )
                    envelopes.append(envelope)
                    previous_hash = event_hash

                if projector is not None:
                    await projector(connection, envelopes)
                await connection.commit()
                committed = True
            except LedgerError:
                if not committed:
                    await connection.rollback()
                raise
            except (aiosqlite.IntegrityError, ValueError, ValidationError, TypeError) as exc:
                if not committed:
                    await connection.rollback()
                raise LedgerError("The event batch was rejected atomically.") from exc
            except BaseException:
                if not committed:
                    await connection.rollback()
                raise
            finally:
                await connection.close()

            try:
                await self._write_head(envelopes[-1].sequence_number, envelopes[-1].event_hash)
            except OSError as exc:
                self._mark_unhealthy("expected_head_update_failed")
                raise LedgerError(
                    "The event committed, but the expected-head update failed; ledger is unhealthy."
                ) from exc
            return envelopes

    async def list_events(self) -> list[EventEnvelope]:
        connection = await self._connect()
        try:
            rows = await (
                await connection.execute(
                    "SELECT envelope_json FROM events ORDER BY sequence_number ASC"
                )
            ).fetchall()
        finally:
            await connection.close()
        try:
            return [
                EventEnvelope.model_validate(parse_json_strict(str(row["envelope_json"])))
                for row in rows
            ]
        except (ValueError, ValidationError) as exc:
            raise LedgerError("A stored event envelope is invalid.") from exc

    async def verify(self, *, verify_view: bool = True) -> LedgerVerification:
        from verity_cordon.ledger.verify import LedgerVerifier

        return await LedgerVerifier(self).verify(verify_view=verify_view)
