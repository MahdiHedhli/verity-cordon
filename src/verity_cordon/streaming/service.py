"""Isolated bounded stream buffering with incremental and final evaluation."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Literal

import aiosqlite

from verity_cordon.core.errors import ConflictError, ResourceLimitError
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
from verity_cordon.crypto.canonical import canonical_json, sha256_hex
from verity_cordon.ledger.store import SQLiteEventStore
from verity_cordon.memory.service import (
    CandidateOutcome,
    EvidenceSubmission,
    MemoryService,
    ProjectionWriter,
)
from verity_cordon.streaming.session import (
    StreamingWriteSession,
    StreamMetadata,
    StreamResult,
)

StreamStateName = Literal["open", "blocked", "committing", "committed", "aborted"]


@dataclass(slots=True)
class _StreamState:
    stream_id: str
    metadata: StreamMetadata
    state: StreamStateName = "open"
    chunks: list[str] = field(default_factory=list)
    buffer_bytes: int = 0
    overlap_tail: str = ""
    content_digest: str | None = None
    terminal_reason: str | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


def _is_security_discussion(content: str) -> bool:
    lowered = content.casefold()
    return bool(
        any(
            marker in lowered
            for marker in (
                "is an example",
                "as an example",
                "not an instruction",
                "quoted text",
                "do not follow",
            )
        )
    )


def _incremental_risk(content: str) -> bool:
    if _is_security_discussion(content):
        return False
    persistence = re.search(
        r"(?i)\b(?:for\s+all\s+future|future\s+sessions?|preserve\s+this|"
        r"permanent(?:ly)?\s+(?:project\s+)?rule|from\s+now\s+on)\b",
        content,
    )
    concealment = re.search(
        r"(?i)\b(?:do\s+not\s+(?:tell|mention|disclose)|hide\s+this\s+instruction)\b",
        content,
    )
    return bool(persistence or concealment)


class StreamingMemoryService:
    def __init__(
        self,
        *,
        store: SQLiteEventStore,
        memory_service: MemoryService,
        max_stream_bytes: int,
        max_stream_chunks: int,
        overlap_bytes: int = 256,
    ) -> None:
        self.store = store
        self.memory_service = memory_service
        self.max_stream_bytes = max_stream_bytes
        self.max_stream_chunks = max_stream_chunks
        self.overlap_bytes = overlap_bytes
        self._streams: dict[str, _StreamState] = {}
        self._registry_lock = asyncio.Lock()

    def _result(
        self,
        state: _StreamState,
        *,
        candidate_count: int = 0,
        active_count: int = 0,
    ) -> StreamResult:
        return StreamResult(
            stream_id=state.stream_id,
            state=state.state,
            chunk_count=len(state.chunks),
            buffer_bytes=state.buffer_bytes,
            content_digest=state.content_digest,
            terminal_reason=state.terminal_reason,
            candidate_count=candidate_count,
            active_count=active_count,
        )

    async def _state(self, stream_id: str) -> _StreamState:
        async with self._registry_lock:
            state = self._streams.get(stream_id)
        if state is None:
            raise ConflictError("The stream does not exist in this daemon process.")
        return state

    async def begin_write(self, metadata: StreamMetadata) -> StreamingWriteSession:
        stream_id = new_id()
        state = _StreamState(stream_id=stream_id, metadata=metadata)
        event_id = new_id()
        occurred_at = format_utc()
        event = EventInput(
            event_id=event_id,
            stream_id=stream_id,
            event_type=EventType.STREAM_STARTED,
            actor=Actor(type=ActorType.SYSTEM, id="verity.streaming"),
            session_id=metadata.session_id,
            task_id=metadata.task_id,
            source_class=EventSourceClass(metadata.source_class.value),
            payload={
                "stream_id": stream_id,
                "source_class": metadata.source_class.value,
                "source_name": metadata.source_name,
                "namespace_hint": metadata.namespace_hint,
                "max_stream_bytes": self.max_stream_bytes,
                "max_stream_chunks": self.max_stream_chunks,
            },
            occurred_at=occurred_at,
        )

        async def project(
            connection: aiosqlite.Connection,
            _: list[EventEnvelope],
        ) -> None:
            await connection.execute(
                """
                INSERT INTO streams(
                    stream_id, state, metadata_json, buffer_bytes, chunk_count,
                    content_digest, started_at, updated_at, terminal_reason
                ) VALUES (?, 'open', ?, 0, 0, NULL, ?, ?, NULL)
                """,
                (
                    stream_id,
                    canonical_json(metadata.model_dump(mode="json")),
                    occurred_at,
                    occurred_at,
                ),
            )

        await self.store.append_with_projection([event], project)
        async with self._registry_lock:
            self._streams[stream_id] = state
        return StreamingWriteSession(self, stream_id)

    async def _record_abort(self, state: _StreamState) -> None:
        event = EventInput(
            stream_id=state.stream_id,
            event_type=EventType.STREAM_ABORTED,
            actor=Actor(type=ActorType.SYSTEM, id="verity.streaming"),
            session_id=state.metadata.session_id,
            task_id=state.metadata.task_id,
            source_class=EventSourceClass(state.metadata.source_class.value),
            payload={
                "stream_id": state.stream_id,
                "terminal_state": state.state,
                "reason": state.terminal_reason,
                "buffer_bytes": state.buffer_bytes,
                "chunk_count": len(state.chunks),
                "content_digest": state.content_digest,
            },
        )

        async def project(
            connection: aiosqlite.Connection,
            _: list[EventEnvelope],
        ) -> None:
            await connection.execute(
                """
                UPDATE streams
                SET state = ?, buffer_bytes = ?, chunk_count = ?, content_digest = ?,
                    updated_at = ?, terminal_reason = ?
                WHERE stream_id = ?
                """,
                (
                    state.state,
                    state.buffer_bytes,
                    len(state.chunks),
                    state.content_digest,
                    format_utc(),
                    state.terminal_reason,
                    state.stream_id,
                ),
            )

        await self.store.append_with_projection([event], project)

    async def append(
        self,
        stream_id: str,
        chunk: str,
        *,
        chunk_sequence: int | None = None,
    ) -> StreamResult:
        state = await self._state(stream_id)
        if not isinstance(chunk, str) or not chunk:
            raise ResourceLimitError("A stream chunk must be a non-empty text value.")
        limit_error: ResourceLimitError | None = None
        blocked = False
        async with state.lock:
            if state.state != "open":
                raise ConflictError("The stream is terminal or currently committing.")
            if chunk_sequence is not None and chunk_sequence != len(state.chunks) + 1:
                raise ConflictError("The stream chunk sequence is not the next expected value.")
            chunk_bytes = len(chunk.encode("utf-8"))
            if len(state.chunks) + 1 > self.max_stream_chunks:
                state.state = "aborted"
                state.terminal_reason = "chunk_limit_exceeded"
                limit_error = ResourceLimitError("The stream chunk limit was exceeded.")
            elif state.buffer_bytes + chunk_bytes > self.max_stream_bytes:
                state.state = "aborted"
                state.terminal_reason = "byte_limit_exceeded"
                limit_error = ResourceLimitError("The stream byte limit was exceeded.")
            else:
                scan_window = state.overlap_tail + chunk
                state.chunks.append(chunk)
                state.buffer_bytes += chunk_bytes
                state.overlap_tail = scan_window[-self.overlap_bytes :]
                if _incremental_risk(scan_window):
                    state.state = "blocked"
                    state.terminal_reason = "incremental_persistence_risk"
                    state.content_digest = sha256_hex("".join(state.chunks).encode("utf-8"))
                    blocked = True
        if limit_error is not None:
            await self._record_abort(state)
            raise limit_error
        if blocked:
            await self._record_abort(state)
        return self._result(state)

    async def abort(self, stream_id: str, reason: str) -> StreamResult:
        state = await self._state(stream_id)
        async with state.lock:
            if state.state != "open":
                raise ConflictError("The stream is terminal or currently committing.")
            state.state = "aborted"
            raw_reason = reason.strip() if reason else "operator_aborted"
            safe_reason = self.memory_service.sanitizer.sanitize(raw_reason).text
            state.terminal_reason = safe_reason[:128] or "operator_aborted"
            state.content_digest = sha256_hex("".join(state.chunks).encode("utf-8"))
        await self._record_abort(state)
        return self._result(state)

    async def commit(
        self,
        stream_id: str,
        *,
        expected_chunk_count: int | None = None,
    ) -> StreamResult:
        state = await self._state(stream_id)
        async with state.lock:
            if state.state != "open":
                raise ConflictError("The stream is terminal or currently committing.")
            if expected_chunk_count is not None and expected_chunk_count != len(state.chunks):
                raise ConflictError("The stream chunk count does not match the commit request.")
            content = "".join(state.chunks)
            if not content:
                raise ConflictError("An empty stream cannot be committed.")
            state.state = "committing"
            state.content_digest = sha256_hex(content.encode("utf-8"))
        if _incremental_risk(content):
            async with state.lock:
                state.state = "blocked"
                state.terminal_reason = "final_persistence_risk"
            await self._record_abort(state)
            return self._result(state)

        def terminal_factory(
            outcomes: list[CandidateOutcome],
            accepted: bool,
        ) -> tuple[EventInput, ProjectionWriter]:
            terminal_state: StreamStateName = "committed" if accepted else "blocked"
            terminal_reason = None if accepted else "final_policy_rejection"
            event_type = EventType.STREAM_COMMITTED if accepted else EventType.STREAM_ABORTED
            payload = {
                "stream_id": state.stream_id,
                "content_digest": state.content_digest,
                "buffer_bytes": state.buffer_bytes,
                "chunk_count": len(state.chunks),
                "candidate_ids": [outcome.candidate.candidate_id for outcome in outcomes],
                "actual_actions": [outcome.decision.actual_action.value for outcome in outcomes],
                "terminal_state": terminal_state,
                "reason": terminal_reason,
            }
            event = EventInput(
                stream_id=state.stream_id,
                event_type=event_type,
                actor=Actor(type=ActorType.SYSTEM, id="verity.streaming"),
                session_id=state.metadata.session_id,
                task_id=state.metadata.task_id,
                source_class=EventSourceClass(state.metadata.source_class.value),
                payload=payload,
            )

            async def project(
                connection: aiosqlite.Connection,
                _: list[EventEnvelope],
            ) -> None:
                cursor = await connection.execute(
                    """
                    UPDATE streams
                    SET state = ?, buffer_bytes = ?, chunk_count = ?,
                        content_digest = ?, updated_at = ?, terminal_reason = ?
                    WHERE stream_id = ? AND state = 'open'
                    """,
                    (
                        terminal_state,
                        state.buffer_bytes,
                        len(state.chunks),
                        state.content_digest,
                        format_utc(),
                        terminal_reason,
                        state.stream_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ConflictError("The persisted stream state changed during commit.")

            return event, project

        try:
            evaluation, accepted = await self.memory_service.evaluate_transactional_stream(
                EvidenceSubmission(
                    session_id=state.metadata.session_id,
                    task_id=state.metadata.task_id,
                    source_class=state.metadata.source_class,
                    source_name=state.metadata.source_name,
                    content=content,
                    metadata={"stream_id": state.stream_id},
                ),
                terminal_factory=terminal_factory,
            )
        except asyncio.CancelledError:
            async with state.lock:
                state.state = "aborted"
                state.terminal_reason = "commit_cancelled"
            if self.store.healthy:
                await asyncio.shield(self._record_abort(state))
            raise
        except Exception:
            async with state.lock:
                state.state = "aborted"
                state.terminal_reason = "evaluation_failed"
            if self.store.healthy:
                await self._record_abort(state)
            raise

        active_count = sum(
            outcome.status in {"active", "redacted"} for outcome in evaluation.outcomes
        )
        async with state.lock:
            state.state = "committed" if accepted else "blocked"
            state.terminal_reason = None if accepted else "final_policy_rejection"
        return self._result(
            state,
            candidate_count=len(evaluation.outcomes),
            active_count=active_count,
        )
