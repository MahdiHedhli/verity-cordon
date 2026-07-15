"""Strict request contracts for the loopback IPC API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from verity_cordon.core.models import SourceClass, StrictModel


class ControlRoomSessionRequest(StrictModel):
    challenge_id: str = Field(min_length=8, max_length=128)
    proof: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")


class HookEvidenceRequest(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    hook_event: Literal["UserPromptSubmit", "PostToolUse", "PreCompact", "PostCompact", "Stop"]
    session_id: str = Field(min_length=8, max_length=128)
    turn_id: str = Field(min_length=8, max_length=128)
    cwd: str = Field(min_length=1, max_length=4096)
    model: str = Field(min_length=1, max_length=128)
    permission_mode: str | None = Field(default=None, max_length=64)
    captured_at: str
    payload: dict[str, Any]


class SessionStartRequest(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    hook_event: Literal["SessionStart"]
    session_id: str = Field(min_length=8, max_length=128)
    source: Literal["startup", "resume", "clear", "compact"]
    cwd: str = Field(min_length=1, max_length=4096)
    model: str = Field(min_length=1, max_length=128)
    permission_mode: str = Field(min_length=1, max_length=64)
    requested_at: str


class CandidateReviewRequest(StrictModel):
    actor_id: str = Field(min_length=8, max_length=128)
    reason: str = Field(min_length=1, max_length=1000)
    confirmed: Literal[True]
    disposition: Literal["approve", "block", "leave_quarantined"]


class OperatorActionRequest(StrictModel):
    actor_id: str = Field(min_length=8, max_length=128)
    reason: str = Field(min_length=1, max_length=1000)
    confirmed: Literal[True]


class RebuildRequest(StrictModel):
    dry_run: bool


class PolicyActivationRequest(StrictModel):
    policy: dict[str, Any]
    actor_id: str = Field(min_length=8, max_length=128)
    reason: str = Field(min_length=1, max_length=1000)
    confirmed: Literal[True]


class LedgerVerifyRequest(StrictModel):
    verify_materialized_view: bool = True
    require_anchored_completeness: bool = True


class StreamBeginRequest(StrictModel):
    session_id: str = Field(min_length=8, max_length=128)
    task_id: str | None = Field(default=None, min_length=8, max_length=128)
    source_class: SourceClass
    namespace: str = Field(min_length=1, max_length=160)
    kind: str = Field(min_length=1, max_length=64)


class StreamAppendRequest(StrictModel):
    chunk_sequence: int = Field(ge=1)
    chunk: str = Field(min_length=1, max_length=262_144)


class StreamCommitRequest(StrictModel):
    expected_chunk_count: int = Field(ge=1, le=10_000)


class StreamAbortRequest(StrictModel):
    reason: str = Field(min_length=1, max_length=1000)
