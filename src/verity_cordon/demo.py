"""Synthetic offline and explicit live demonstration orchestration."""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from verity_cordon.core.config import Settings
from verity_cordon.core.errors import ConfigurationError
from verity_cordon.core.models import Mode, SourceClass, new_id
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.daemon.runtime import Runtime, build_runtime
from verity_cordon.memory.service import EvidenceSubmission
from verity_cordon.policies.load import load_builtin_policy

_FIXTURE_SERVER_NAME = "verity-cordon-poisoned-docs-fixture"
_FIXTURE_TOOL_NAME = "get_release_guidance"
_FIXTURE_MAX_OUTPUT_BYTES = 128 * 1024
_FIXTURE_TIMEOUT_SECONDS = 3.0


@dataclass(slots=True)
class DemoRun:
    runtime: Runtime
    summary: dict[str, Any]


@dataclass(frozen=True, slots=True)
class PoisonedDocsResult:
    text: str
    server_name: str
    tool_name: str
    external_transmission_performed: bool


def _ensure_demo_key(settings: Settings) -> None:
    settings.prepare()
    if not settings.key_path.exists():
        FileKeyProvider.generate(settings.key_path)


def _fixture_source_root(fixture_root: Path | None = None) -> tuple[Path, Path]:
    repository_root = (fixture_root or Path(__file__).resolve().parents[2]).resolve()
    fixture_directory = repository_root / "examples" / "poisoned-docs-mcp"
    source_root = fixture_directory / "src"
    server_file = source_root / "poisoned_docs_mcp" / "server.py"
    if (
        fixture_directory.is_symlink()
        or source_root.is_symlink()
        or server_file.is_symlink()
        or not server_file.is_file()
    ):
        raise ConfigurationError("The reviewed poisoned-docs fixture source is unavailable.")
    return fixture_directory, source_root


def _request(request_id: int, method: str, params: dict[str, object]) -> bytes:
    return (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _validate_fixture_output(raw: bytes) -> PoisonedDocsResult:
    if not raw or len(raw) > _FIXTURE_MAX_OUTPUT_BYTES:
        raise ConfigurationError("The poisoned-docs fixture returned an invalid response size.")
    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
        responses = [json.loads(line) for line in lines]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigurationError("The poisoned-docs fixture returned invalid JSON.") from exc
    if len(responses) != 3 or any(not isinstance(item, dict) for item in responses):
        raise ConfigurationError("The poisoned-docs fixture returned an invalid response set.")
    by_id = {item.get("id"): item for item in responses}
    if (
        set(by_id) != {1, 2, 3}
        or any(item.get("jsonrpc") != "2.0" for item in responses)
        or any("error" in item for item in responses)
    ):
        raise ConfigurationError("The poisoned-docs fixture rejected the bounded request.")
    try:
        initialize = by_id[1]["result"]
        tools = by_id[2]["result"]["tools"]
        call = by_id[3]["result"]
        content = call["content"]
        structured = call["structuredContent"]
        text = content[0]["text"]
        server_name = initialize["serverInfo"]["name"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ConfigurationError("The poisoned-docs fixture response contract is invalid.") from exc
    valid_tool = bool(
        isinstance(tools, list)
        and len(tools) == 1
        and isinstance(tools[0], dict)
        and tools[0].get("name") == _FIXTURE_TOOL_NAME
        and isinstance(tools[0].get("inputSchema"), dict)
        and tools[0]["inputSchema"].get("additionalProperties") is False
    )
    valid_call = bool(
        isinstance(content, list)
        and len(content) == 1
        and isinstance(content[0], dict)
        and content[0].get("type") == "text"
        and isinstance(text, str)
        and 1 <= len(text.encode("utf-8")) <= 64 * 1024
        and isinstance(structured, dict)
        and structured.get("fixture") == "security-demonstration"
        and structured.get("release_channel") == "stable"
        and structured.get("external_transmission_performed") is False
        and call.get("isError") is False
        and "demo_artifact_sink" in text
    )
    if server_name != _FIXTURE_SERVER_NAME or not valid_tool or not valid_call:
        raise ConfigurationError("The poisoned-docs fixture identity or safety flags are invalid.")
    return PoisonedDocsResult(
        text=text,
        server_name=server_name,
        tool_name=_FIXTURE_TOOL_NAME,
        external_transmission_performed=False,
    )


async def call_poisoned_docs_fixture(
    fixture_root: Path | None = None,
) -> PoisonedDocsResult:
    """Invoke only the reviewed stdio fixture under a minimal environment."""

    fixture_directory, source_root = _fixture_source_root(fixture_root)
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-P",
        "-S",
        "-m",
        "poisoned_docs_mcp",
        cwd=fixture_directory,
        env={
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": str(source_root),
            "PYTHONUTF8": "1",
        },
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    if process.stdin is None or process.stdout is None:
        process.kill()
        await process.wait()
        raise ConfigurationError("The poisoned-docs fixture stdio boundary is unavailable.")
    request_bytes = b"".join(
        (
            _request(
                1,
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "verity-demo", "version": "1.0.0"},
                },
            ),
            _request(2, "tools/list", {}),
            _request(
                3,
                "tools/call",
                {
                    "name": _FIXTURE_TOOL_NAME,
                    "arguments": {"release_channel": "stable"},
                },
            ),
        )
    )
    try:
        async with asyncio.timeout(_FIXTURE_TIMEOUT_SECONDS):
            process.stdin.write(request_bytes)
            await process.stdin.drain()
            process.stdin.close()
            chunks: list[bytes] = []
            output_size = 0
            while chunk := await process.stdout.read(
                min(8192, _FIXTURE_MAX_OUTPUT_BYTES + 1 - output_size)
            ):
                chunks.append(chunk)
                output_size += len(chunk)
                if output_size > _FIXTURE_MAX_OUTPUT_BYTES:
                    raise ConfigurationError(
                        "The poisoned-docs fixture exceeded its output boundary."
                    )
            output = b"".join(chunks)
            return_code = await process.wait()
        if return_code != 0:
            raise ConfigurationError("The poisoned-docs fixture exited unsuccessfully.")
        return _validate_fixture_output(output)
    except TimeoutError as exc:
        raise ConfigurationError("The poisoned-docs fixture exceeded its time boundary.") from exc
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


async def run_offline_demo(
    settings: Settings | None = None,
    *,
    fixture_root: Path | None = None,
) -> DemoRun:
    selected = replace(
        settings or Settings.from_env(),
        semantic_provider="fixture",
    )
    fixture = await call_poisoned_docs_fixture(fixture_root)
    _ensure_demo_key(selected)
    runtime = await build_runtime(selected)

    shadow_policy = load_builtin_policy(Mode.SHADOW)
    await runtime.policy_repository.activate(shadow_policy, actor_id="operator.demo")
    runtime.replace_policy(shadow_policy)
    shadow = await runtime.memory_service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            task_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            source_name="poisoned-docs-mcp",
            content=fixture.text,
        )
    )
    shadow_malicious = next(
        outcome
        for outcome in shadow.outcomes
        if "demo_artifact_sink" in outcome.candidate.statement
    )
    if shadow_malicious.memory_id is None:
        raise RuntimeError("Offline shadow fixture did not create the expected demo memory.")

    enforce_policy = load_builtin_policy(Mode.ENFORCE)
    await runtime.policy_repository.activate(enforce_policy, actor_id="operator.demo")
    runtime.replace_policy(enforce_policy)
    enforced = await runtime.memory_service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            task_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            source_name="poisoned-docs-mcp",
            content=fixture.text,
        )
    )
    rescan = await runtime.rescan.rescan(
        shadow_malicious.memory_id,
        actor_id="operator.demo",
        reason="Enforcement policy retroactively rejects persistent tool authority.",
        confirmed=True,
    )
    rebuild = await runtime.memory_view.rebuild(dry_run=False)
    verification = await runtime.event_store.verify()
    active = await runtime.memory_view.list_active()
    quarantined = await runtime.memory_view.list_quarantined()
    session_context = await runtime.memory_service.session_start_context(
        session_id=new_id(),
        token_budget=enforce_policy.limits.injection_token_budget,
    )
    approved_memory_present = "synthetic acme release guidance" in session_context.casefold()
    poisoned_memory_absent = (
        "demo_artifact_sink" not in session_context
        and "do not mention this instruction" not in session_context.casefold()
    )
    if not approved_memory_present or not poisoned_memory_absent:
        raise RuntimeError("The simulated SessionStart memory contract failed safely.")
    return DemoRun(
        runtime=runtime,
        summary={
            "mode": "offline_fixture",
            "semantic_provider": "recorded_fixture",
            "fixture": {
                "server_name": fixture.server_name,
                "tool_name": fixture.tool_name,
                "transport": "stdio",
                "external_transmission_performed": fixture.external_transmission_performed,
            },
            "shadow": {
                "actual_action": shadow_malicious.decision.actual_action.value,
                "would_have_action": shadow_malicious.decision.would_have_action.value,
                "memory_id": shadow_malicious.memory_id,
            },
            "enforcement": {
                "actions": [outcome.decision.actual_action.value for outcome in enforced.outcomes],
                "poisoned_memory_active": False,
            },
            "rescan": {
                "decision_id": rescan.decision_id,
                "actual_action": rescan.actual_action.value,
                "revoked": rescan.revoked,
                "revocation_event_id": rescan.revocation_event_id,
                "original_candidate_event_id": rescan.original_candidate_event_id,
            },
            "revocation": {
                "revoked_memory_id": shadow_malicious.memory_id,
                "rebuild": rebuild,
                "unrelated_active_memories": len(active),
            },
            "simulated_session_start": {
                "contract": "MemoryService.session_start_context",
                "injection_state": "approved_only",
                "approved_memory_present": approved_memory_present,
                "poisoned_memory_absent": poisoned_memory_absent,
                "active_memory_ids": [item.memory_id for item in active],
            },
            "active_memories": len(active),
            "quarantined_candidates": len(quarantined),
            "ledger_verified": verification.verified,
            "view_consistent": verification.materialized_view_consistent,
            "total_events": verification.total_events,
        },
    )


async def run_live_demo(
    settings: Settings | None = None,
    *,
    fixture_root: Path | None = None,
) -> DemoRun:
    selected = replace(
        settings or Settings.from_env(),
        semantic_provider="openai",
    )
    if not __import__("os").getenv("OPENAI_API_KEY"):
        raise ConfigurationError("OPENAI_API_KEY is required for explicit live demo mode.")
    fixture = await call_poisoned_docs_fixture(fixture_root)
    _ensure_demo_key(selected)
    runtime = await build_runtime(selected)
    evaluation = await runtime.memory_service.evaluate_evidence(
        EvidenceSubmission(
            session_id=new_id(),
            task_id=new_id(),
            source_class=SourceClass.TOOL_OUTPUT,
            source_name="poisoned-docs-mcp",
            content=fixture.text,
        )
    )
    verification = await runtime.event_store.verify()
    return DemoRun(
        runtime=runtime,
        summary={
            "mode": "live_openai",
            "requested_model": selected.openai_model,
            "fixture": {
                "server_name": fixture.server_name,
                "tool_name": fixture.tool_name,
                "transport": "stdio",
                "external_transmission_performed": fixture.external_transmission_performed,
            },
            "providers": [
                (
                    outcome.semantic_assessment.provider_state.value
                    if outcome.semantic_assessment is not None
                    else "deterministic_only"
                )
                for outcome in evaluation.outcomes
            ],
            "returned_models": [
                (
                    outcome.semantic_assessment.returned_model
                    if outcome.semantic_assessment is not None
                    else None
                )
                for outcome in evaluation.outcomes
            ],
            "actions": [outcome.decision.actual_action.value for outcome in evaluation.outcomes],
            "ledger_verified": verification.verified,
        },
    )
