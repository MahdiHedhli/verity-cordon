"""Public transactional streaming session contract."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import Field

from verity_cordon.core.models import SourceClass, StrictModel

if TYPE_CHECKING:
    from verity_cordon.streaming.service import StreamingMemoryService


class StreamMetadata(StrictModel):
    session_id: str = Field(min_length=8, max_length=128)
    task_id: str | None = Field(default=None, min_length=8, max_length=128)
    source_class: SourceClass
    source_name: str | None = Field(default=None, max_length=256)
    namespace_hint: str | None = Field(default=None, max_length=160)


class StreamResult(StrictModel):
    stream_id: str
    state: Literal["open", "blocked", "committing", "committed", "aborted"]
    chunk_count: int = Field(ge=0)
    buffer_bytes: int = Field(ge=0)
    content_digest: str | None = None
    terminal_reason: str | None = None
    candidate_count: int = Field(default=0, ge=0)
    active_count: int = Field(default=0, ge=0)


class StreamingWriteSession:
    def __init__(self, service: StreamingMemoryService, stream_id: str) -> None:
        self._service = service
        self.stream_id = stream_id

    async def append(self, chunk: str) -> StreamResult:
        return await self._service.append(self.stream_id, chunk)

    async def commit(self) -> StreamResult:
        return await self._service.commit(self.stream_id)

    async def abort(self, reason: str) -> StreamResult:
        return await self._service.abort(self.stream_id, reason)
