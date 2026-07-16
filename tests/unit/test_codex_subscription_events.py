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
            "usage": {
                "input_tokens": 3,
                "cached_input_tokens": 0,
                "output_tokens": 2,
                "reasoning_output_tokens": 1,
            },
        },
    ]


def test_benign_lifecycle_and_reasoning_message_items_are_allowed() -> None:
    assert CodexSubscriptionRunner.validate_event_stream(_stream(_benign_events())) is None


def test_documented_completion_only_safe_item_is_allowed() -> None:
    events = [
        {"type": "thread.started", "thread_id": "thread-synthetic-001"},
        {"type": "turn.started"},
        {
            "type": "item.completed",
            "item": {
                "id": "item-synthetic-001",
                "type": "agent_message",
                "text": "Synthetic response.",
            },
        },
        {"type": "turn.completed", "usage": {}},
    ]

    assert CodexSubscriptionRunner.validate_event_stream(_stream(events)) is None


def test_documented_failure_lifecycle_maps_to_content_safe_process_exit() -> None:
    marker = "SYNTHETIC-ERROR-CONTENT-MUST-NOT-ECHO"
    events = [
        {"type": "thread.started", "thread_id": "thread-synthetic-001"},
        {"type": "turn.started"},
        {"type": "error", "message": marker},
        {"type": "turn.failed", "error": {"message": marker}},
    ]

    with pytest.raises(SemanticProviderError) as captured:
        CodexSubscriptionRunner.validate_event_stream(_stream(events))

    assert captured.value.failure_class == "process_exit"
    assert captured.value.retryable is True
    assert marker not in str(captured.value)


@pytest.mark.parametrize(
    "failure_event",
    [
        {"type": "error", "message": "synthetic", "future": True},
        {"type": "error", "message": None},
        {"type": "turn.failed", "error": "synthetic"},
        {
            "type": "turn.failed",
            "error": {"message": "synthetic", "future": True},
        },
        {"type": "turn.failed", "error": {"message": ""}},
    ],
)
def test_malformed_failure_event_shapes_remain_invalid_response(
    failure_event: dict[str, Any],
) -> None:
    events = [
        {"type": "thread.started", "thread_id": "thread-synthetic-001"},
        {"type": "turn.started"},
        failure_event,
    ]

    with pytest.raises(SemanticProviderError) as captured:
        CodexSubscriptionRunner.validate_event_stream(_stream(events))

    assert captured.value.failure_class == "invalid_response"


def test_tool_bearing_failure_event_still_maps_to_tool_activity() -> None:
    events = [
        {"type": "thread.started", "thread_id": "thread-synthetic-001"},
        {"type": "turn.started"},
        {
            "type": "turn.failed",
            "error": {
                "message": "synthetic",
                "tool_call": {"name": "synthetic"},
            },
        },
    ]

    with pytest.raises(SemanticProviderError) as captured:
        CodexSubscriptionRunner.validate_event_stream(_stream(events))

    assert captured.value.failure_class == "tool_activity"


@pytest.mark.parametrize(
    "events",
    [
        [
            {"type": "turn.completed", "usage": {}},
            {"type": "thread.started", "thread_id": "thread-synthetic-001"},
            {"type": "turn.started"},
        ],
        [
            {"type": "thread.started", "thread_id": "thread-synthetic-001"},
            {
                "type": "item.completed",
                "item": {"id": "item-synthetic-001", "type": "agent_message"},
            },
            {"type": "turn.started"},
            {"type": "turn.completed", "usage": {}},
        ],
        [
            *_benign_events(),
            {
                "type": "item.completed",
                "item": {"id": "item-after-terminal", "type": "agent_message"},
            },
        ],
    ],
    ids=["terminal-first", "item-before-turn", "event-after-terminal"],
)
def test_reordered_and_post_terminal_events_are_rejected(
    events: list[dict[str, Any]],
) -> None:
    with pytest.raises(SemanticProviderError):
        CodexSubscriptionRunner.validate_event_stream(_stream(events))


@pytest.mark.parametrize(
    "events",
    [
        [*_benign_events()[:3], *_benign_events()[4:]],
        [*_benign_events()[:3], _benign_events()[2], *_benign_events()[3:]],
        [*_benign_events()[:4], _benign_events()[3], *_benign_events()[4:]],
        [
            *_benign_events()[:2],
            _benign_events()[3],
            _benign_events()[2],
            *_benign_events()[4:],
        ],
        [
            *_benign_events()[:3],
            {
                "type": "item.completed",
                "item": {
                    "id": "item-synthetic-001",
                    "type": "agent_message",
                    "text": "Mismatched synthetic response.",
                },
            },
            *_benign_events()[4:],
        ],
    ],
    ids=[
        "unmatched-start",
        "duplicate-start",
        "duplicate-completion",
        "completion-before-start",
        "type-mismatch",
    ],
)
def test_started_item_pairing_and_id_reuse_are_enforced(
    events: list[dict[str, Any]],
) -> None:
    with pytest.raises(SemanticProviderError):
        CodexSubscriptionRunner.validate_event_stream(_stream(events))


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
    ("location", "field"),
    [
        ("event", "tool_call"),
        ("event", "tool_calls"),
        ("item", "command"),
        ("item", "function_call"),
        ("usage", "mcp_tool_call"),
    ],
)
def test_tool_bearing_extra_fields_in_otherwise_allowed_events_fail_closed(
    location: str,
    field: str,
) -> None:
    events = _benign_events()
    target: dict[str, Any]
    if location == "event":
        target = events[2]
    elif location == "item":
        target = events[2]["item"]
    else:
        target = events[-1]["usage"]
    target[field] = {"synthetic": True}

    with pytest.raises(SemanticProviderError) as captured:
        CodexSubscriptionRunner.validate_event_stream(_stream(events))

    assert captured.value.failure_class == "tool_activity"


@pytest.mark.parametrize(
    ("event_index", "location"),
    [
        (0, "event"),
        (1, "event"),
        (2, "event"),
        (2, "item"),
        (-1, "event"),
        (-1, "usage"),
    ],
)
def test_unknown_fields_are_rejected_at_every_allowed_event_boundary(
    event_index: int,
    location: str,
) -> None:
    events = _benign_events()
    target: dict[str, Any]
    if location == "item":
        target = events[event_index]["item"]
    elif location == "usage":
        target = events[event_index]["usage"]
    else:
        target = events[event_index]
    target["future_metadata"] = "synthetic"

    with pytest.raises(SemanticProviderError) as captured:
        CodexSubscriptionRunner.validate_event_stream(_stream(events))

    assert captured.value.failure_class == "invalid_response"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda events: events[2]["item"].update(text=1),
        lambda events: events[-1]["usage"].update(input_tokens=True),
        lambda events: events[-1]["usage"].update(output_tokens=-1),
        lambda events: events[-1].update(usage=[]),
    ],
)
def test_allowed_field_values_are_strictly_typed(mutation: Any) -> None:
    events = _benign_events()
    mutation(events)

    with pytest.raises(SemanticProviderError) as captured:
        CodexSubscriptionRunner.validate_event_stream(_stream(events))

    assert captured.value.failure_class == "invalid_response"


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
