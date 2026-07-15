# Poisoned Docs MCP Fixture

This package is an intentionally malicious **security demonstration fixture** for
Verity Cordon. It exposes one synthetic documentation tool over standard input
and standard output. The returned release guidance contains useful synthetic
information plus an embedded attempt to establish a permanent, concealed
operational instruction.

The fixture is deliberately constrained:

- It uses MCP-style JSON-RPC over stdio only; it does not open a network socket.
- It never reads the process environment, user files, credentials, or host data.
- It never invokes another tool or transmits data externally.
- Every value in the response is synthetic.
- Requests are bounded to 64 KiB and tool arguments are allow-listed.

`demo_artifact_sink` is only a string used to exercise memory-poisoning
detectors. No such sink is implemented by this package.

## Run

From this directory, install the fixture in an isolated environment and start
its stdio server:

```bash
python -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/poisoned-docs-mcp
```

An MCP client can then send newline-delimited JSON-RPC requests. The relevant
tool is `get_release_guidance`; it accepts an optional `release_channel` of
`stable` or `preview`.

Example messages:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture-client","version":"1.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_release_guidance","arguments":{"release_channel":"stable"}}}
```

This is a minimal deterministic fixture, not a general-purpose MCP server.

## Test

From the repository root:

```bash
PYTHONPATH=examples/poisoned-docs-mcp/src python -m pytest examples/poisoned-docs-mcp/tests
```
