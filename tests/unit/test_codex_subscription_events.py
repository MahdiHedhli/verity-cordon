"""Fail-closed JSONL event-gate tests for subscription execution."""

from __future__ import annotations

import json
from typing import Any

import pytest

from verity_cordon.core.errors import SemanticProviderError
from verity_cordon.semantic.codex_subscription import CodexSubscriptionRunner


def _stream(events: list[dict[str, Any]]) -> bytes:
    return b"".join(
        json.dumps(event, separators=(",", ":")).encode("utf-8") + b"\n" for event in events
    )


def _benign_events() -> list[dict[str, Any]]:
    return [
        {"type": "thread.started", "thread_id": "thread-synthetic-001"},
        {"type": "turn.started"},
        {
            "type": "item.started",
            "item": {"id": "item-synthetic-001", "type": "reasoning", "text": ""},
        },
        {
            "type": "item.completed",
            "item": {
                "id": "item-synthetic-001",
                "type": "reasoning",
                "text": "Synthetic reasoning.",
            },
        },
        {
            "type": "item.completed",
            "item": {
                "id": "item-synthetic-002",
                "type": "agent_message",
                "text": "Synthetic response.",
            },
        },
        {
            "type": "turn.completed",
            "usage": {"input_tokens": 3, "cached_input_tokens": 0, "output_tokens": 2},
        },
    ]


def test_benign_lifecycle_and_reasoning_message_items_are_allowed() -> None:
    assert CodexSubscriptionRunner.validate_event_stream(_stream(_benign_events())) is None


@pytest.mark.parametrize(
    "item_type",
    [
        "command_execution",
        "file_change",
        "mcp_tool_call",
        "web_search",
        "browser_use",
        "computer_use",
        "image_generation",
        "plan_update",
        "collaboration_tool_call",
        "function_call",
        "shell_command",
        "tool_call",
    ],
)
def test_every_known_tool_item_invalidates_the_complete_result(item_type: str) -> None:
    events = _benign_events()
    events.insert(
        -1,
        {
            "type": "item.completed",
            "item": {"id": "item-tool-synthetic", "type": item_type, "status": "denied"},
        },
    )

    with pytest.raises(SemanticProviderError, match="tool activity"):
        CodexSubscriptionRunner.validate_event_stream(_stream(events))


def test_unknown_item_type_is_treated_as_tool_activity() -> None:
    events = _benign_events()
    events.insert(
        -1,
        {
            "type": "item.completed",
            "item": {"id": "item-future-synthetic", "type": "future_unknown_item"},
        },
    )

    with pytest.raises(SemanticProviderError, match="tool activity"):
        CodexSubscriptionRunner.validate_event_stream(_stream(events))


@pytest.mark.parametrize(
    "event",
    [
        {"type": "future.lifecycle"},
        {"type": "turn.failed", "error": {"message": "synthetic"}},
        {"type": "error", "message": "synthetic"},
    ],
)
def test_unknown_and_failure_events_fail_closed(event: dict[str, Any]) -> None:
    events = _benign_events()
    events.insert(-1, event)

    with pytest.raises(SemanticProviderError):
        CodexSubscriptionRunner.validate_event_stream(_stream(events))


def test_duplicate_top_level_key_is_rejected() -> None:
    raw = b'{"type":"thread.started","type":"turn.completed","thread_id":"thread-synthetic-001"}\n'

    with pytest.raises(SemanticProviderError):
        CodexSubscriptionRunner.validate_event_stream(raw)


def test_duplicate_nested_key_is_rejected() -> None:
    raw = (
        _stream(_benign_events()[:-2])
        + (
            b'{"type":"item.completed","item":{"id":"item-synthetic-002",'
            b'"type":"agent_message","type":"reasoning","text":"synthetic"}}\n'
        )
        + _stream(_benign_events()[-1:])
    )

    with pytest.raises(SemanticProviderError):
        CodexSubscriptionRunner.validate_event_stream(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json\n",
        b"[]\n",
        b'{"type":NaN}\n',
        b'{"type":"turn.completed"',
        b"\xff\n",
        b"\n",
    ],
)
def test_malformed_non_object_nonfinite_partial_and_invalid_utf8_are_rejected(
    raw: bytes,
) -> None:
    with pytest.raises(SemanticProviderError):
        CodexSubscriptionRunner.validate_event_stream(raw)


def test_partial_final_line_is_rejected_even_when_json_is_complete() -> None:
    raw = _stream(_benign_events()).rstrip(b"\n")

    with pytest.raises(SemanticProviderError):
        CodexSubscriptionRunner.validate_event_stream(raw)


def test_missing_or_multiple_terminal_turn_is_rejected() -> None:
    missing = _stream(_benign_events()[:-1])
    duplicate = _stream([*_benign_events(), _benign_events()[-1]])

    with pytest.raises(SemanticProviderError):
        CodexSubscriptionRunner.validate_event_stream(missing)
    with pytest.raises(SemanticProviderError):
        CodexSubscriptionRunner.validate_event_stream(duplicate)


@pytest.mark.parametrize(
    "event",
    [
        {"type": "thread.started"},
        {"type": "item.completed", "item": {"type": "reasoning"}},
        {"type": "item.completed", "item": "not-an-object"},
        {"item": {"id": "item-synthetic", "type": "reasoning"}},
    ],
)
def test_missing_required_event_fields_are_rejected(event: dict[str, Any]) -> None:
    events = _benign_events()
    events.insert(-1, event)

    with pytest.raises(SemanticProviderError):
        CodexSubscriptionRunner.validate_event_stream(_stream(events))


def test_per_line_limit_is_enforced_before_json_use() -> None:
    raw = b'{"type":"thread.started","thread_id":"' + b"x" * 100 + b'"}\n'

    with pytest.raises(SemanticProviderError, match="limit"):
        CodexSubscriptionRunner.validate_event_stream(
            raw,
            max_total_bytes=1_000,
            max_line_bytes=64,
        )


def test_aggregate_limit_is_enforced() -> None:
    raw = _stream(_benign_events())

    with pytest.raises(SemanticProviderError, match="limit"):
        CodexSubscriptionRunner.validate_event_stream(
            raw,
            max_total_bytes=len(raw) - 1,
            max_line_bytes=len(raw),
        )


def test_raw_event_content_is_never_echoed_in_gate_errors() -> None:
    marker = "SYNTHETIC-EVENT-CONTENT-MUST-NOT-ECHO"
    raw = json.dumps({"type": "unknown", "detail": marker}).encode() + b"\n"

    with pytest.raises(SemanticProviderError) as captured:
        CodexSubscriptionRunner.validate_event_stream(raw)

    assert marker not in str(captured.value)
