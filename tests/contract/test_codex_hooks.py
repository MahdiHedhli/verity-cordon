"""Contract tests for the documented Codex hook and installation boundary."""

from __future__ import annotations

import io
import json
import os
import shutil
import threading
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

import verity_cordon.codex.hooks as hooks_module
import verity_cordon.codex.installer as installer_module
from verity_cordon.codex.hooks import (
    END_DELIMITER,
    MAX_STDIN_BYTES,
    START_DELIMITER,
    WARNING,
    HookAdapter,
    HookInputError,
    HookTransportError,
    HttpResponse,
    normalize_hook_input,
    parse_one_object,
    read_bounded_stdin,
    read_capability,
)
from verity_cordon.codex.installer import (
    MARKETPLACE_NAME,
    PLUGIN_NAME,
    CodexIntegrationError,
    CommandResult,
    doctor_codex,
    install_codex,
    uninstall_codex,
)

REPOSITORY_ROOT = Path(__file__).parents[2]
INSTALLED_HOOK_EVENTS = tuple(
    json.loads((REPOSITORY_ROOT / "hooks/hooks.json").read_text(encoding="utf-8"))["hooks"]
)
SESSION_ID = "session-demo-001"
TURN_ID = "turn-demo-001"
TOOL_USE_ID = "tool-use-demo-001"
CAPABILITY = "synthetic-local-capability-value-that-is-long-enough"


def _event(name: str, **extra: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "session_id": SESSION_ID,
        "transcript_path": None,
        "cwd": "/safe/demo/project",
        "hook_event_name": name,
        "model": "configured-codex-model",
        **extra,
    }
    if name in {"SessionStart", "UserPromptSubmit", "PostToolUse", "Stop"}:
        value["permission_mode"] = "default"
    return value


def _encoded(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _capability_file(tmp_path: Path) -> Path:
    path = tmp_path / "mutation-capability"
    path.write_text(CAPABILITY, encoding="ascii")
    path.chmod(0o600)
    return path


def _evidence_response(*, duplicate: bool = False) -> HttpResponse:
    body = {
        "schema_version": "1.0.0",
        "evidence_id": "evidence-demo-001",
        "status": "queued",
        "duplicate": duplicate,
    }
    return HttpResponse(202, _encoded(body), "application/json; charset=utf-8")


def _approved_context() -> str:
    return "\n".join(
        (
            START_DELIMITER,
            "This block contains policy-approved durable memory.",
            "",
            "Memory ID: memory-demo-001",
            "Type: fact",
            "Namespace: project.release",
            "Trust decision: allowed",
            "Source class: user_input",
            'Statement: "Use signed release artifacts."',
            "",
            END_DELIMITER,
        )
    )


def _session_response(
    *,
    state: str = "ready",
    context: str | None = None,
    ledger_verified: bool = True,
    view_consistent: bool = True,
    warning_code: str | None = None,
) -> HttpResponse:
    if state == "ready":
        context = context if context is not None else _approved_context()
        memory_ids = ["memory-demo-001"]
    else:
        context = None
        memory_ids = []
    body = {
        "schema_version": "1.0.0",
        "injection_state": state,
        "additional_context": context,
        "memory_ids": memory_ids,
        "token_estimate": 64 if context else 0,
        "ledger_verified": ledger_verified,
        "view_consistent": view_consistent,
        "warning_code": warning_code,
    }
    return HttpResponse(200, _encoded(body), "application/json")


class RecordingTransport:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def __call__(self, **kwargs: Any) -> HttpResponse:
        with self._lock:
            self.calls.append(kwargs)
        return self.response


@pytest.mark.parametrize("event_name", INSTALLED_HOOK_EVENTS)
def test_semantic_child_short_circuits_every_installed_hook_before_input_or_io(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    event_name: str,
) -> None:
    calls: list[str] = []

    def recording_stdin_read() -> bytes:
        calls.append("stdin")
        return b'{"content":"must not be read"}'

    class RecordingAdapter:
        def __init__(self, **_: Any) -> None:
            calls.append("adapter")

        def process(self, expected_event: str, raw: bytes) -> dict[str, Any]:
            del expected_event, raw
            calls.append("daemon")
            return {"continue": True, "systemMessage": "unexpected adapter call"}

    monkeypatch.setenv("VERITY_SEMANTIC_CHILD", "1")
    monkeypatch.setattr(hooks_module, "read_bounded_stdin", recording_stdin_read)
    monkeypatch.setattr(hooks_module, "HookAdapter", RecordingAdapter)

    assert hooks_module.main([event_name]) == 0

    captured = capsys.readouterr()
    assert captured.out == '{"continue":true}\n'
    assert captured.err == ""
    assert calls == []


def test_only_exact_semantic_child_marker_short_circuits(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []

    def recording_stdin_read() -> bytes:
        calls.append("stdin")
        return b"{}"

    class RecordingAdapter:
        def __init__(self, **_: Any) -> None:
            calls.append("adapter")

        def process(self, expected_event: str, raw: bytes) -> dict[str, Any]:
            del expected_event, raw
            calls.append("daemon")
            return {"continue": True}

    monkeypatch.setenv("VERITY_SEMANTIC_CHILD", "true")
    monkeypatch.setattr(hooks_module, "read_bounded_stdin", recording_stdin_read)
    monkeypatch.setattr(hooks_module, "HookAdapter", RecordingAdapter)

    assert hooks_module.main(["Stop"]) == 0

    captured = capsys.readouterr()
    assert captured.out == '{"continue":true}\n'
    assert captured.err == ""
    assert calls == ["stdin", "adapter", "daemon"]


@pytest.mark.parametrize("source", ["startup", "resume", "clear", "compact"])
def test_session_start_sources_request_only_approved_context(tmp_path: Path, source: str) -> None:
    transport = RecordingTransport(_session_response())
    adapter = HookAdapter(
        capability_path=_capability_file(tmp_path),
        transport=transport,
    )

    output = adapter.process("SessionStart", _encoded(_event("SessionStart", source=source)))

    assert output == {
        "continue": True,
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": _approved_context(),
        },
    }
    assert transport.calls[0]["path"] == "/api/v1/hooks/session-start"
    request = parse_one_object(transport.calls[0]["body"])
    assert request["source"] == source
    assert request["permission_mode"] == "default"
    assert "transcript_path" not in request
    assert "Idempotency-Key" not in transport.calls[0]["headers"]


@pytest.mark.parametrize("source", [None, "unknown", 7])
def test_malformed_session_source_never_reaches_daemon(tmp_path: Path, source: Any) -> None:
    transport = RecordingTransport(_session_response())
    adapter = HookAdapter(capability_path=_capability_file(tmp_path), transport=transport)
    value = _event("SessionStart")
    if source is not None:
        value["source"] = source

    assert adapter.process("SessionStart", _encoded(value)) == {
        "continue": True,
        "systemMessage": WARNING,
    }
    assert transport.calls == []


@pytest.mark.parametrize("name", ["PreCompact", "PostCompact"])
@pytest.mark.parametrize("trigger", ["manual", "auto"])
def test_every_supported_compaction_trigger_is_preserved(name: str, trigger: str) -> None:
    _, request, idempotency_key = normalize_hook_input(
        _event(name, turn_id=TURN_ID, trigger=trigger),
        name,
    )

    assert request["payload"] == {"trigger": trigger}
    assert idempotency_key is not None


@pytest.mark.parametrize(
    ("name", "extra", "payload"),
    [
        (
            "UserPromptSubmit",
            {"turn_id": TURN_ID, "prompt": "Remember the supported release channel."},
            {"prompt": "Remember the supported release channel."},
        ),
        (
            "PostToolUse",
            {
                "turn_id": TURN_ID,
                "tool_name": "mock_docs",
                "tool_use_id": TOOL_USE_ID,
                "tool_input": {"topic": "release"},
                "tool_response": {"guidance": "Synthetic documentation."},
            },
            {
                "tool_name": "mock_docs",
                "tool_use_id": TOOL_USE_ID,
                "tool_input": {"topic": "release"},
                "tool_response": {"guidance": "Synthetic documentation."},
            },
        ),
        (
            "PreCompact",
            {"turn_id": TURN_ID, "trigger": "manual"},
            {"trigger": "manual"},
        ),
        (
            "PostCompact",
            {"turn_id": TURN_ID, "trigger": "auto"},
            {"trigger": "auto"},
        ),
        (
            "Stop",
            {
                "turn_id": TURN_ID,
                "stop_hook_active": False,
                "last_assistant_message": "The synthetic task is complete.",
            },
            {
                "stop_hook_active": False,
                "last_assistant_message": "The synthetic task is complete.",
            },
        ),
    ],
)
def test_selected_evidence_events_forward_only_contracted_fields(
    tmp_path: Path,
    name: str,
    extra: dict[str, Any],
    payload: dict[str, Any],
) -> None:
    transport = RecordingTransport(_evidence_response())
    adapter = HookAdapter(capability_path=_capability_file(tmp_path), transport=transport)
    value = _event(name, **extra, unexpected_field="must-not-forward")

    assert adapter.process(name, _encoded(value)) == {"continue": True}

    call = transport.calls[0]
    request = parse_one_object(call["body"])
    assert call["path"] == "/api/v1/hooks/evidence"
    assert request["hook_event"] == name
    assert request["payload"] == payload
    assert "unexpected_field" not in request
    assert call["headers"]["Authorization"] == f"Bearer {CAPABILITY}"
    assert call["headers"]["Idempotency-Key"].startswith("vc-hook-")
    assert call["timeout"] < 3


@pytest.mark.parametrize(
    "name",
    ["UserPromptSubmit", "PostToolUse", "PreCompact", "PostCompact", "Stop"],
)
def test_missing_required_event_field_fails_without_forwarding(tmp_path: Path, name: str) -> None:
    transport = RecordingTransport(_evidence_response())
    adapter = HookAdapter(capability_path=_capability_file(tmp_path), transport=transport)
    value = _event(name, turn_id=TURN_ID)

    output = adapter.process(name, _encoded(value))

    assert output == {"continue": True, "systemMessage": WARNING}
    assert transport.calls == []


def test_unexpected_event_name_fails_without_forwarding(tmp_path: Path) -> None:
    transport = RecordingTransport(_evidence_response())
    adapter = HookAdapter(capability_path=_capability_file(tmp_path), transport=transport)
    raw = _encoded(
        _event(
            "Stop",
            turn_id=TURN_ID,
            stop_hook_active=False,
            last_assistant_message=None,
        )
    )

    assert adapter.process("UserPromptSubmit", raw) == {
        "continue": True,
        "systemMessage": WARNING,
    }
    assert transport.calls == []


def test_duplicate_keys_are_rejected_before_forwarding(tmp_path: Path) -> None:
    transport = RecordingTransport(_evidence_response())
    adapter = HookAdapter(capability_path=_capability_file(tmp_path), transport=transport)
    raw = (
        b'{"session_id":"session-demo-001","session_id":"session-other-001",'
        b'"cwd":"/safe","hook_event_name":"UserPromptSubmit","model":"codex",'
        b'"permission_mode":"default","turn_id":"turn-demo-001","prompt":"safe"}'
    )

    assert adapter.process("UserPromptSubmit", raw)["systemMessage"] == WARNING
    assert transport.calls == []


def test_json_size_and_single_object_bounds() -> None:
    with pytest.raises(HookInputError):
        parse_one_object(b"{}{}")
    with pytest.raises(HookInputError):
        parse_one_object(b"[1,2,3]")
    with pytest.raises(HookInputError):
        parse_one_object(b"{" + b" " * MAX_STDIN_BYTES + b"}")
    with pytest.raises(HookInputError):
        read_bounded_stdin(io.BytesIO(b"x" * (MAX_STDIN_BYTES + 1)))


def test_idempotency_key_is_stable_across_time_and_retries() -> None:
    value = _event(
        "PostToolUse",
        turn_id=TURN_ID,
        tool_name="mock_docs",
        tool_use_id=TOOL_USE_ID,
        tool_input={"topic": "release"},
        tool_response={"answer": "Synthetic output."},
    )
    _, first_body, first_key = normalize_hook_input(
        value,
        "PostToolUse",
        now=lambda: "2026-01-01T00:00:00.000Z",
    )
    _, second_body, second_key = normalize_hook_input(
        value,
        "PostToolUse",
        now=lambda: "2026-01-02T00:00:00.000Z",
    )

    assert first_key == second_key
    assert first_body["captured_at"] != second_body["captured_at"]

    changed = dict(value)
    changed["tool_response"] = {"answer": "Different synthetic output."}
    assert normalize_hook_input(changed, "PostToolUse")[2] != first_key


def test_concurrent_retries_emit_one_stable_idempotency_key(tmp_path: Path) -> None:
    transport = RecordingTransport(_evidence_response(duplicate=True))
    adapter = HookAdapter(capability_path=_capability_file(tmp_path), transport=transport)
    raw = _encoded(
        _event(
            "UserPromptSubmit",
            turn_id=TURN_ID,
            prompt="Store a synthetic project convention.",
        )
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        outputs = list(executor.map(lambda _: adapter.process("UserPromptSubmit", raw), range(16)))

    assert outputs == [{"continue": True}] * 16
    assert len({call["headers"]["Idempotency-Key"] for call in transport.calls}) == 1


@pytest.mark.parametrize(
    "failure",
    [TimeoutError("synthetic timeout"), HookTransportError("synthetic unavailable")],
)
def test_timeout_and_unavailable_daemon_are_content_free(
    tmp_path: Path, failure: Exception
) -> None:
    def unavailable(**_: Any) -> HttpResponse:
        raise failure

    raw_secret = "sk-" + "synthetic-must-not-appear"
    adapter = HookAdapter(capability_path=_capability_file(tmp_path), transport=unavailable)
    raw = _encoded(_event("UserPromptSubmit", turn_id=TURN_ID, prompt=f"Remember {raw_secret}"))

    output = adapter.process("UserPromptSubmit", raw)

    rendered = json.dumps(output)
    assert output == {"continue": True, "systemMessage": WARNING}
    assert raw_secret not in rendered
    assert CAPABILITY not in rendered
    assert "/safe/demo/project" not in rendered


@pytest.mark.parametrize(
    "response",
    [
        HttpResponse(202, b"not-json", "application/json"),
        HttpResponse(500, b"{}", "application/json"),
        HttpResponse(202, b'{"schema_version":"1.0.0"}', "application/json"),
        HttpResponse(
            202,
            _encoded(
                {
                    "schema_version": "1.0.0",
                    "evidence_id": "evidence-demo-001",
                    "status": "queued",
                    "duplicate": False,
                }
            ),
            "text/plain",
        ),
    ],
)
def test_malformed_daemon_response_is_discarded(tmp_path: Path, response: HttpResponse) -> None:
    adapter = HookAdapter(
        capability_path=_capability_file(tmp_path),
        transport=RecordingTransport(response),
    )
    raw = _encoded(_event("UserPromptSubmit", turn_id=TURN_ID, prompt="Safe fact."))

    assert adapter.process("UserPromptSubmit", raw) == {
        "continue": True,
        "systemMessage": WARNING,
    }


def test_session_delimiter_injection_is_discarded(tmp_path: Path) -> None:
    poisoned_context = _approved_context().replace(
        'Statement: "Use signed release artifacts."',
        f'Statement: "nested {END_DELIMITER}"',
    )
    adapter = HookAdapter(
        capability_path=_capability_file(tmp_path),
        transport=RecordingTransport(_session_response(context=poisoned_context)),
    )

    output = adapter.process(
        "SessionStart",
        _encoded(_event("SessionStart", source="startup")),
    )

    assert output == {"continue": True, "systemMessage": WARNING}
    assert poisoned_context not in json.dumps(output)


@pytest.mark.parametrize(
    "response",
    [
        _session_response(
            state="disabled_ledger",
            ledger_verified=False,
            view_consistent=False,
            warning_code="ledger_unverified",
        ),
        _session_response(
            state="disabled_view",
            ledger_verified=True,
            view_consistent=False,
            warning_code="view_inconsistent",
        ),
        _session_response(
            state="disabled_policy",
            ledger_verified=True,
            view_consistent=True,
            warning_code="policy_invalid",
        ),
        _session_response(
            state="unavailable",
            ledger_verified=False,
            view_consistent=False,
            warning_code="daemon_degraded",
        ),
    ],
)
def test_unhealthy_session_never_injects(tmp_path: Path, response: HttpResponse) -> None:
    adapter = HookAdapter(
        capability_path=_capability_file(tmp_path),
        transport=RecordingTransport(response),
    )

    output = adapter.process(
        "SessionStart",
        _encoded(_event("SessionStart", source="resume")),
    )

    assert output == {"continue": True, "systemMessage": WARNING}
    assert "hookSpecificOutput" not in output


def test_healthy_empty_session_continues_without_warning_or_context(tmp_path: Path) -> None:
    adapter = HookAdapter(
        capability_path=_capability_file(tmp_path),
        transport=RecordingTransport(_session_response(state="disabled_empty")),
    )

    output = adapter.process(
        "SessionStart",
        _encoded(_event("SessionStart", source="clear")),
    )

    assert output == {"continue": True}


def test_capability_file_must_be_private_and_not_a_symlink(tmp_path: Path) -> None:
    capability = _capability_file(tmp_path)
    if os.name != "nt":
        capability.chmod(0o644)
        with pytest.raises(HookInputError):
            read_capability(capability)
        capability.chmod(0o600)
    symlink = tmp_path / "linked-capability"
    symlink.symlink_to(capability)
    with pytest.raises(HookInputError):
        read_capability(symlink)


def test_plugin_manifest_uses_only_bounded_supported_command_hooks() -> None:
    manifest = json.loads((REPOSITORY_ROOT / ".codex-plugin/plugin.json").read_text())
    hooks = json.loads((REPOSITORY_ROOT / "hooks/hooks.json").read_text())["hooks"]

    assert manifest["name"] == PLUGIN_NAME
    assert manifest["hooks"] == "./hooks/hooks.json"
    assert set(hooks) == {
        "SessionStart",
        "UserPromptSubmit",
        "PostToolUse",
        "PreCompact",
        "PostCompact",
        "Stop",
    }
    for groups in hooks.values():
        for group in groups:
            for handler in group["hooks"]:
                assert handler["type"] == "command"
                assert handler["timeout"] == 3
                assert handler.get("async") is None
                assert handler["command"].startswith("__VERITY_INSTALLER_PINS_PYTHON_3_12__")
                assert "python3" not in handler["command"]
                assert "$PLUGIN_ROOT/src/verity_cordon/codex/hooks.py" in handler["command"]


class SuccessfulCodexRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.installed = False
        self.enabled = True
        self.effective_features = True
        self.marketplace_root: Path | None = None
        self.source_override: Path | None = None

    def __call__(
        self,
        argv: list[str],
        *,
        environment: dict[str, str],
        timeout: float,
    ) -> CommandResult:
        assert environment["CODEX_HOME"]
        assert "OPENAI_API_KEY" not in environment
        assert timeout <= 20
        self.commands.append(tuple(argv))
        codex_home = Path(environment["CODEX_HOME"])
        if argv[1:4] == ["plugin", "marketplace", "add"]:
            self.marketplace_root = Path(argv[4]).resolve()
        if argv[1:3] == ["plugin", "add"]:
            assert self.marketplace_root is not None
            self.installed = True
            cache = codex_home / "plugins" / "cache" / MARKETPLACE_NAME / PLUGIN_NAME / "0.1.0"
            cache.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(
                self.marketplace_root / "plugins" / PLUGIN_NAME,
                cache,
                dirs_exist_ok=True,
            )
        if argv[1:3] == ["plugin", "remove"]:
            self.installed = False
        if argv[1:3] == ["features", "list"]:
            return CommandResult(
                0,
                (
                    b"hooks stable true\nmemories experimental false\n"
                    if self.effective_features
                    else b"hooks stable true\nmemories experimental true\n"
                ),
            )
        if argv[1:3] == ["plugin", "list"]:
            body = {
                "plugins": (
                    [
                        {
                            "name": PLUGIN_NAME,
                            "marketplaceName": MARKETPLACE_NAME,
                            "version": "0.1.0",
                            "installed": True,
                            "enabled": self.enabled,
                            "source": {
                                "source": "local",
                                "path": str(
                                    self.source_override
                                    or self.marketplace_root / "plugins" / PLUGIN_NAME
                                ),
                            },
                        }
                    ]
                    if self.installed
                    else []
                )
            }
            return CommandResult(0, _encoded(body))
        return CommandResult(0, b'{"ok":true}')


def test_installer_previews_backs_up_and_changes_only_required_toml_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codex_home = tmp_path / "codex-home"
    data_dir = tmp_path / "verity-data"
    codex_home.mkdir()
    config = codex_home / "config.toml"
    original = (
        'model = "configured-model"\n\n'
        "[features]\n"
        "hooks = false\n"
        "memories = true\n\n"
        "[memories]\n"
        "generate_memories = true\n"
        "use_memories = true\n"
        "disable_on_external_context = false\n"
        "min_rate_limit_remaining_percent = 20\n"
    )
    config.write_text(original)
    runner = SuccessfulCodexRunner()
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-key-must-not-reach-plugin-cli")

    preview = install_codex(
        REPOSITORY_ROOT,
        codex_home=codex_home,
        data_dir=data_dir,
        confirmed=False,
        runner=runner,
    )

    assert not preview.applied
    assert config.read_text() == original
    assert runner.commands == []
    assert {change.dotted_key for change in preview.changes} == {
        "features.hooks",
        "features.memories",
        "memories.generate_memories",
        "memories.use_memories",
        "memories.disable_on_external_context",
    }

    result = install_codex(
        REPOSITORY_ROOT,
        codex_home=codex_home,
        data_dir=data_dir,
        confirmed=True,
        runner=runner,
    )

    assert result.applied and result.plugin_installed and result.marketplace_registered
    assert result.backup_path is not None
    assert result.backup_path.read_text() == original
    updated = tomllib.loads(config.read_text())
    assert updated["model"] == "configured-model"
    assert updated["features"] == {"hooks": True, "memories": False}
    assert updated["memories"]["generate_memories"] is False
    assert updated["memories"]["use_memories"] is False
    assert updated["memories"]["disable_on_external_context"] is True
    assert updated["memories"]["min_rate_limit_remaining_percent"] == 20
    assert (result.marketplace_root / ".agents/plugins/marketplace.json").is_file()
    assert (result.marketplace_root / "plugins/verity-cordon/hooks/hooks.json").is_file()

    first_receipt = json.loads((data_dir / "codex-integration-receipt.json").read_text())
    repeated = install_codex(
        REPOSITORY_ROOT,
        codex_home=codex_home,
        data_dir=data_dir,
        confirmed=True,
        runner=runner,
    )
    repeated_receipt = json.loads((data_dir / "codex-integration-receipt.json").read_text())
    assert repeated.backup_path == result.backup_path
    assert repeated_receipt["required_config"] == first_receipt["required_config"]

    doctor = doctor_codex(codex_home=codex_home, data_dir=data_dir, runner=runner)
    assert doctor.mechanically_ready
    assert not doctor.ready
    assert doctor.trust_review_required
    trusted_doctor = doctor_codex(
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=True,
    )
    assert trusted_doctor.ready
    assert not trusted_doctor.trust_review_required

    removed = uninstall_codex(
        codex_home=codex_home,
        data_dir=data_dir,
        confirmed=True,
        runner=runner,
    )
    assert removed.applied
    restored = tomllib.loads(config.read_text())
    assert restored["features"] == {"hooks": False, "memories": True}
    assert restored["memories"]["generate_memories"] is True
    assert restored["memories"]["use_memories"] is True
    assert restored["memories"]["disable_on_external_context"] is False
    assert restored["memories"]["min_rate_limit_remaining_percent"] == 20


def test_uninstaller_refuses_config_drift_and_preserves_installed_plugin(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    data_dir = tmp_path / "verity-data"
    runner = SuccessfulCodexRunner()
    install_codex(
        REPOSITORY_ROOT,
        codex_home=codex_home,
        data_dir=data_dir,
        confirmed=True,
        runner=runner,
    )
    config = codex_home / "config.toml"
    content = config.read_text().replace("hooks = true", "hooks = false")
    config.write_text(content)

    result = uninstall_codex(
        codex_home=codex_home,
        data_dir=data_dir,
        confirmed=True,
        runner=runner,
    )

    assert not result.applied
    assert result.issues == ("codex_config_drift_requires_review",)
    assert runner.installed
    assert (data_dir / "codex-integration-receipt.json").exists()
    doctor = doctor_codex(codex_home=codex_home, data_dir=data_dir, runner=runner)
    assert not doctor.ready
    assert "required_codex_config_drift" in doctor.issues


def test_doctor_detects_staged_hook_drift(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    data_dir = tmp_path / "verity-data"
    runner = SuccessfulCodexRunner()
    installed = install_codex(
        REPOSITORY_ROOT,
        codex_home=codex_home,
        data_dir=data_dir,
        confirmed=True,
        runner=runner,
    )
    staged_hooks = installed.marketplace_root / "plugins/verity-cordon/hooks/hooks.json"
    staged_hooks.write_text("{}\n")

    doctor = doctor_codex(codex_home=codex_home, data_dir=data_dir, runner=runner)

    assert not doctor.ready
    assert not doctor.staged_files_intact
    assert "staged_plugin_drift" in doctor.issues


def test_doctor_never_executes_receipt_selected_interpreter(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    data_dir = tmp_path / "verity-data"
    runner = SuccessfulCodexRunner()
    install_codex(
        REPOSITORY_ROOT,
        codex_home=codex_home,
        data_dir=data_dir,
        confirmed=True,
        runner=runner,
    )
    receipt_path = data_dir / "codex-integration-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["hook_python"] = "/bin/sh"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    doctor = doctor_codex(
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=True,
    )

    assert doctor.ready is False
    assert doctor.hook_runtime_verified is False
    assert "integration_receipt_invalid" in doctor.issues


def test_doctor_rejects_disabled_plugin_and_source_drift(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    data_dir = tmp_path / "verity-data"
    runner = SuccessfulCodexRunner()
    install_codex(
        REPOSITORY_ROOT,
        codex_home=codex_home,
        data_dir=data_dir,
        confirmed=True,
        runner=runner,
    )
    runner.enabled = False

    disabled = doctor_codex(
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=True,
    )

    assert not disabled.ready
    assert not disabled.plugin_enabled
    assert "verity_plugin_disabled" in disabled.issues

    runner.enabled = True
    runner.source_override = tmp_path / "different-source"
    drifted = doctor_codex(
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=True,
    )
    assert not drifted.ready
    assert "verity_plugin_source_drift" in drifted.issues

    runner.source_override = None
    runner.effective_features = False
    feature_drift = doctor_codex(
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=True,
    )
    assert not feature_drift.ready
    assert not feature_drift.effective_features_valid
    assert "effective_codex_feature_drift" in feature_drift.issues


def test_doctor_hashes_and_executes_installed_cached_hook(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    data_dir = tmp_path / "verity-data"
    runner = SuccessfulCodexRunner()
    install_codex(
        REPOSITORY_ROOT,
        codex_home=codex_home,
        data_dir=data_dir,
        confirmed=True,
        runner=runner,
    )
    cache_hook = (
        codex_home
        / "plugins/cache"
        / MARKETPLACE_NAME
        / PLUGIN_NAME
        / "0.1.0/src/verity_cordon/codex/hooks.py"
    )
    cache_hook.write_text("raise SystemExit(7)\n")

    doctor = doctor_codex(
        codex_home=codex_home,
        data_dir=data_dir,
        runner=runner,
        operator_confirmed_hook_trust=True,
    )

    assert not doctor.ready
    assert not doctor.installed_cache_intact
    assert not doctor.hook_runtime_verified
    assert "installed_plugin_cache_drift" in doctor.issues


def test_installer_rejects_non_boolean_security_controls(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    (codex_home / "config.toml").write_text('[features]\nhooks = "sometimes"\n')

    with pytest.raises(CodexIntegrationError):
        install_codex(
            REPOSITORY_ROOT,
            codex_home=codex_home,
            data_dir=tmp_path / "data",
        )


def test_receipt_failure_occurs_before_config_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codex_home = tmp_path / "codex-home"
    data_dir = tmp_path / "verity-data"
    codex_home.mkdir()
    config = codex_home / "config.toml"
    original = "[features]\nhooks = false\nmemories = true\n"
    config.write_text(original)

    def fail_receipt(*_: Any, **__: Any) -> None:
        raise OSError("synthetic receipt failure")

    monkeypatch.setattr(installer_module, "_write_receipt", fail_receipt)
    with pytest.raises(OSError, match="synthetic receipt failure"):
        install_codex(
            REPOSITORY_ROOT,
            codex_home=codex_home,
            data_dir=data_dir,
            confirmed=True,
            run_codex_commands=False,
        )

    assert config.read_text() == original


def test_prepared_receipt_preserves_original_values_across_config_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codex_home = tmp_path / "codex-home"
    data_dir = tmp_path / "verity-data"
    codex_home.mkdir()
    config = codex_home / "config.toml"
    original = "[features]\nhooks = false\nmemories = true\n"
    config.write_text(original)
    real_atomic_write = installer_module._atomic_write

    def fail_config(path: Path, content: bytes, *, mode: int = 0o600) -> None:
        if path == config:
            raise OSError("synthetic config write failure")
        real_atomic_write(path, content, mode=mode)

    with monkeypatch.context() as scoped:
        scoped.setattr(installer_module, "_atomic_write", fail_config)
        with pytest.raises(OSError, match="synthetic config write failure"):
            install_codex(
                REPOSITORY_ROOT,
                codex_home=codex_home,
                data_dir=data_dir,
                confirmed=True,
                run_codex_commands=False,
            )

    receipt = json.loads((data_dir / "codex-integration-receipt.json").read_text())
    assert config.read_text() == original
    assert any(
        item["dotted_key"] == "features.hooks"
        and item["previous"] is False
        and item["previous_present"] is True
        for item in receipt["required_config"]
    )

    runner = SuccessfulCodexRunner()
    installed = install_codex(
        REPOSITORY_ROOT,
        codex_home=codex_home,
        data_dir=data_dir,
        confirmed=True,
        runner=runner,
    )
    assert installed.applied
    removed = uninstall_codex(
        codex_home=codex_home,
        data_dir=data_dir,
        confirmed=True,
        runner=runner,
    )
    assert removed.applied
    assert tomllib.loads(config.read_text())["features"] == {
        "hooks": False,
        "memories": True,
    }
