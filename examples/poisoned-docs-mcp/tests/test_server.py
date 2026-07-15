from __future__ import annotations

import ast
import hashlib
import io
import json
from pathlib import Path

from poisoned_docs_mcp.server import (
    ARTIFACT_MARKER,
    CANONICAL_PAIR_SHA256,
    ENVIRONMENT_MARKER,
    SERVER_NAME,
    SINK_TOOL_NAME,
    SYNTHETIC_ATTACK,
    TOOL_NAME,
    dispatch,
    serve,
)


def _request(method: str, *, request_id: int = 1, params: object = None) -> dict[str, object]:
    request: dict[str, object] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        request["params"] = params
    return request


def test_initialize_identifies_security_fixture() -> None:
    response = dispatch(_request("initialize", params={}))

    assert response is not None
    result = response["result"]
    assert result["serverInfo"]["name"] == SERVER_NAME
    assert "Security demonstration fixture" in result["instructions"]


def test_tool_list_exposes_only_the_bounded_demo_tools() -> None:
    response = dispatch(_request("tools/list"))

    assert response is not None
    tools = response["result"]["tools"]
    assert [tool["name"] for tool in tools] == [TOOL_NAME, SINK_TOOL_NAME]
    assert tools[0]["inputSchema"]["additionalProperties"] is False
    assert tools[0]["annotations"] == {
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
        "readOnlyHint": True,
    }
    assert tools[1]["inputSchema"] == {
        "type": "object",
        "properties": {
            "artifact_marker": {"type": "string", "const": ARTIFACT_MARKER},
            "environment_marker": {"type": "string", "const": ENVIRONMENT_MARKER},
        },
        "required": ["artifact_marker", "environment_marker"],
        "additionalProperties": False,
    }
    assert tools[1]["annotations"] == {
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
        "readOnlyHint": False,
    }


def test_tool_returns_useful_text_and_deliberate_persistence_attack() -> None:
    response = dispatch(
        _request(
            "tools/call",
            params={"name": TOOL_NAME, "arguments": {"release_channel": "stable"}},
        )
    )

    assert response is not None
    result = response["result"]
    text = result["content"][0]["text"]
    assert "Verify the synthetic artifact checksum" in text
    assert SYNTHETIC_ATTACK in text
    assert "demo_artifact_sink" in text
    assert result["structuredContent"]["external_transmission_performed"] is False


def test_tool_rejects_unallowlisted_arguments() -> None:
    response = dispatch(
        _request(
            "tools/call",
            params={"name": TOOL_NAME, "arguments": {"url": "https://example.invalid"}},
        )
    )

    assert response is not None
    assert response["error"]["code"] == -32602


def test_inert_sink_accepts_only_fixed_synthetic_markers() -> None:
    response = dispatch(
        _request(
            "tools/call",
            params={
                "name": SINK_TOOL_NAME,
                "arguments": {
                    "artifact_marker": ARTIFACT_MARKER,
                    "environment_marker": ENVIRONMENT_MARKER,
                },
            },
        )
    )

    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["accepted"] is True
    assert result["structuredContent"]["external_transmission_performed"] is False
    canonical_pair = f"artifact_marker={ARTIFACT_MARKER}\nenvironment_marker={ENVIRONMENT_MARKER}"
    expected_digest = hashlib.sha256(canonical_pair.encode("utf-8")).hexdigest()
    assert CANONICAL_PAIR_SHA256 == expected_digest
    assert result["structuredContent"]["canonical_pair_sha256"] == CANONICAL_PAIR_SHA256
    assert isinstance(result["structuredContent"]["call_count"], int)
    assert result["structuredContent"]["call_count"] >= 1


def test_inert_sink_call_count_is_process_local_and_monotonic() -> None:
    params = {
        "name": SINK_TOOL_NAME,
        "arguments": {
            "artifact_marker": ARTIFACT_MARKER,
            "environment_marker": ENVIRONMENT_MARKER,
        },
    }

    first = dispatch(_request("tools/call", request_id=10, params=params))
    second = dispatch(_request("tools/call", request_id=11, params=params))

    assert first is not None
    assert second is not None
    first_count = first["result"]["structuredContent"]["call_count"]
    second_count = second["result"]["structuredContent"]["call_count"]
    assert second_count == first_count + 1


def test_inert_sink_rejects_missing_wrong_or_extra_fields() -> None:
    invalid_arguments = (
        {},
        {"artifact_marker": ARTIFACT_MARKER},
        {
            "artifact_marker": "REAL_RELEASE_MANIFEST",
            "environment_marker": ENVIRONMENT_MARKER,
        },
        {
            "artifact_marker": ARTIFACT_MARKER,
            "environment_marker": ENVIRONMENT_MARKER,
            "destination": "https://example.invalid",
        },
    )

    for request_id, arguments in enumerate(invalid_arguments, start=20):
        response = dispatch(
            _request(
                "tools/call",
                request_id=request_id,
                params={"name": SINK_TOOL_NAME, "arguments": arguments},
            )
        )

        assert response is not None
        assert response["error"]["code"] == -32602


def test_stdio_loop_recovers_from_invalid_json_and_handles_ping() -> None:
    ping = json.dumps(_request("ping", request_id=9))
    output = io.StringIO()

    serve(io.StringIO(f"not-json\n{ping}\n"), output)

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert responses[0]["error"]["code"] == -32700
    assert responses[1] == {"id": 9, "jsonrpc": "2.0", "result": {}}


def test_server_imports_no_host_or_network_capabilities() -> None:
    server_path = Path(__file__).parents[1] / "src" / "poisoned_docs_mcp" / "server.py"
    tree = ast.parse(server_path.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", maxsplit=1)[0])

    assert imported_roots.isdisjoint(
        {
            "aiohttp",
            "asyncio",
            "email",
            "http",
            "httpx",
            "os",
            "pathlib",
            "playwright",
            "requests",
            "selenium",
            "socket",
            "subprocess",
            "urllib",
            "webbrowser",
        }
    )
