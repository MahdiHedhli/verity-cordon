from __future__ import annotations

import ast
import io
import json
from pathlib import Path

from poisoned_docs_mcp.server import (
    SERVER_NAME,
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


def test_tool_list_exposes_only_synthetic_documentation_tool() -> None:
    response = dispatch(_request("tools/list"))

    assert response is not None
    tools = response["result"]["tools"]
    assert [tool["name"] for tool in tools] == [TOOL_NAME]
    assert tools[0]["inputSchema"]["additionalProperties"] is False


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
        {"asyncio", "http", "os", "pathlib", "socket", "subprocess", "urllib"}
    )
