"""Bounded background processing for durably captured hook evidence."""

from __future__ import annotations

import asyncio
from contextlib import suppress

from verity_cordon.memory.service import MemoryService


class EvidenceQueueWorker:
    """Drain sanitized durable queue entries without extending the hook deadline."""

    def __init__(
        self,
        service: MemoryService,
        *,
        poll_interval_seconds: float = 1.0,
        batch_size: int = 25,
    ) -> None:
        if poll_interval_seconds <= 0:
            raise ValueError("The evidence queue poll interval must be positive.")
        if not 1 <= batch_size <= 100:
            raise ValueError("The evidence queue batch size must be between 1 and 100.")
        self.service = service
        self.poll_interval_seconds = poll_interval_seconds
        self.batch_size = batch_size
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._run(), name="verity-evidence-queue")

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    def notify(self) -> None:
        self._wake.set()

    async def drain_once(self) -> int:
        return await self.service.process_pending_evidence(limit=self.batch_size)

    async def _run(self) -> None:
        while True:
            if not self.service.event_store.healthy:
                return
            self._wake.clear()
            try:
                processed = await self.drain_once()
            except Exception:
                # Queue rows remain durable. Public/log output intentionally omits
                # exception text; the worker retries after the bounded poll delay.
                processed = 0
            if processed >= self.batch_size:
                continue
            try:
                await asyncio.wait_for(
                    self._wake.wait(),
                    timeout=self.poll_interval_seconds,
                )
            except TimeoutError:
                pass
