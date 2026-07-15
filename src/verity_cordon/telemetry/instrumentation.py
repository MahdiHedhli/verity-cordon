"""Privacy-safe OpenTelemetry spans and in-process aggregate statistics."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from time import perf_counter
from typing import Any

from opentelemetry import trace

_ALLOWED_ATTRIBUTES = {
    "event_id",
    "memory_id",
    "candidate_id",
    "detector_id",
    "policy_version",
    "source_class",
    "action",
    "shadow_mode",
    "latency_ms",
    "error_class",
    "content_length",
    "content_digest_prefix",
    "semantic_provider",
}


def safe_attributes(values: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if key in _ALLOWED_ATTRIBUTES}


@asynccontextmanager
async def span(name: str, **attributes: Any) -> AsyncIterator[dict[str, float]]:
    tracer = trace.get_tracer("verity_cordon")
    started = perf_counter()
    with tracer.start_as_current_span(name, attributes=safe_attributes(attributes)) as current:
        state: dict[str, float] = {}
        try:
            yield state
        except Exception as exc:
            current.set_attribute("error_class", type(exc).__name__)
            raise
        finally:
            latency = (perf_counter() - started) * 1000
            state["latency_ms"] = latency
            current.set_attribute("latency_ms", latency)


class Statistics:
    def __init__(self) -> None:
        self._counts: defaultdict[str, int] = defaultdict(int)
        self._latencies: list[float] = []
        self._lock = asyncio.Lock()

    async def increment(self, name: str, amount: int = 1) -> None:
        async with self._lock:
            self._counts[name] += amount

    async def observe_evaluation(self, latency_ms: float) -> None:
        async with self._lock:
            self._latencies.append(latency_ms)
            if len(self._latencies) > 10_000:
                self._latencies = self._latencies[-5_000:]

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            average = sum(self._latencies) / len(self._latencies) if self._latencies else 0.0
            return {"counts": dict(self._counts), "average_evaluation_latency_ms": average}

