"""Process-boundary tests for the Codex subscription semantic runner.

The executable used here is a local synthetic script. It never invokes Codex,
opens authentication files, or uses network access. The monitor records only
test sentinels and process metadata so the security boundary can be asserted.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import stat
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from verity_cordon.core.errors import ConfigurationError, SemanticProviderError
from verity_cordon.semantic import codex_subscription as subscription_module
from verity_cordon.semantic.codex_subscription import CodexSubscriptionRunner

_SIMPLE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"ok": {"type": "boolean"}},
    "required": ["ok"],
    "additionalProperties": False,
}
_PLATFORM_INJECTED_ENV = {"__CF_USER_TEXT_ENCODING"} if sys.platform == "darwin" else set()
_RESOURCE_LIMIT_MAXIMA = {
    "max_input_bytes": 1_048_576,
    "max_jsonl_bytes": 4_194_304,
    "max_jsonl_line_bytes": 1_048_576,
    "max_stderr_bytes": 1_048_576,
    "max_final_bytes": 262_144,
}


def _allowed_events() -> list[dict[str, Any]]:
    return [
        {"type": "thread.started", "thread_id": "thread-synthetic-001"},
        {"type": "turn.started"},
        {
            "type": "item.completed",
            "item": {
                "id": "item-synthetic-001",
                "type": "reasoning",
                "text": "Synthetic reasoning event.",
            },
        },
        {
            "type": "item.completed",
            "item": {
                "id": "item-synthetic-002",
                "type": "agent_message",
                "text": "Synthetic final event.",
            },
        },
        {
            "type": "turn.completed",
            "usage": {
                "input_tokens": 1,
                "cached_input_tokens": 0,
                "output_tokens": 1,
                "reasoning_output_tokens": 0,
            },
        },
    ]


@contextmanager
def _secure_tree() -> Iterator[Path]:
    """Create a private test tree below the repository's trusted ancestors.

    Pytest's ordinary temporary directory is below world-writable ``/tmp`` on
    many systems, which the production path validator must correctly reject.
    """

    container = Path.cwd() / ".verity"
    parent = container / "subscription-provider-tests"
    remove_container = not container.exists()
    remove_parent = not parent.exists()
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    root = parent / uuid.uuid4().hex
    root.mkdir(mode=0o700)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)
        if remove_parent:
            try:
                parent.rmdir()
            except OSError:
                pass
        if remove_container:
            try:
                container.rmdir()
            except OSError:
                pass


def _fake_codex(
    root: Path,
    *,
    version: str = "codex-cli 0.144.4\n",
    version_stderr: str = "",
    version_exit: int = 0,
    status: str = "Logged in using ChatGPT\n",
    status_stderr: str = "",
    status_exit: int = 0,
    status_sleep: float = 0.0,
    events: list[dict[str, Any] | str] | None = None,
    final: dict[str, Any] | str | None = None,
    exec_stderr: str = "",
    exec_exit: int = 0,
    exec_sleep: float = 0.0,
    post_events_sleep: float = 0.0,
    stdin_read_delay: float = 0.0,
    spawn_descendant: bool = False,
    detach_descendant_stdio: bool = False,
    replace_final_with_symlink: bool = False,
    final_mode: int | None = None,
) -> tuple[Path, Path, Path]:
    """Write a deterministic fake executable and return it plus monitor paths."""

    bin_dir = root / "bin"
    bin_dir.mkdir(mode=0o700)
    executable = bin_dir / "codex"
    monitor = root / "monitor.jsonl"
    descendant_pid = root / "descendant.pid"
    config = {
        "monitor": str(monitor),
        "descendant_pid": str(descendant_pid),
        "version": version,
        "version_stderr": version_stderr,
        "version_exit": version_exit,
        "status": status,
        "status_stderr": status_stderr,
        "status_exit": status_exit,
        "status_sleep": status_sleep,
        "events": events if events is not None else _allowed_events(),
        "final": final if final is not None else {"ok": True},
        "exec_stderr": exec_stderr,
        "exec_exit": exec_exit,
        "exec_sleep": exec_sleep,
        "post_events_sleep": post_events_sleep,
        "stdin_read_delay": stdin_read_delay,
        "spawn_descendant": spawn_descendant,
        "detach_descendant_stdio": detach_descendant_stdio,
        "replace_final_with_symlink": replace_final_with_symlink,
        "final_mode": final_mode,
        "external_final": str(root / "external-final.json"),
    }
    encoded = base64.b64encode(json.dumps(config).encode("utf-8")).decode("ascii")
    script = f"""#!{sys.executable}
import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

CONFIG = json.loads(base64.b64decode({encoded!r}).decode("utf-8"))
MONITOR = Path(CONFIG["monitor"])

def append_record(value):
    with MONITOR.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\\n")

if sys.argv[1:] == ["--version"]:
    sys.stdout.write(CONFIG["version"])
    sys.stderr.write(CONFIG["version_stderr"])
    raise SystemExit(CONFIG["version_exit"])

if sys.argv[1:] == ["login", "status"]:
    append_record({{"kind": "status", "argv": sys.argv[1:], "env": dict(os.environ)}})
    time.sleep(CONFIG["status_sleep"])
    sys.stdout.write(CONFIG["status"])
    sys.stderr.write(CONFIG["status_stderr"])
    raise SystemExit(CONFIG["status_exit"])

time.sleep(CONFIG["stdin_read_delay"])
stdin = sys.stdin.read()
args = sys.argv[1:]
def value_after(flag):
    return args[args.index(flag) + 1]

work = Path(value_after("--cd"))
schema = Path(value_after("--output-schema"))
final = Path(value_after("--output-last-message"))
tmpdir = Path(os.environ["TMPDIR"])
record = {{
    "kind": "exec",
    "argv": args,
    "stdin": stdin,
    "cwd": os.getcwd(),
    "env": dict(os.environ),
    "tmp_root": str(tmpdir),
    "work": str(work),
    "schema": str(schema),
    "final": str(final),
    "modes": {{
        "tmp_root": stat.S_IMODE(tmpdir.stat().st_mode),
        "work": stat.S_IMODE(work.stat().st_mode),
        "io": stat.S_IMODE(schema.parent.stat().st_mode),
        "schema": stat.S_IMODE(schema.stat().st_mode),
        "final": stat.S_IMODE(final.stat().st_mode),
    }},
    "schema_document": json.loads(schema.read_text(encoding="utf-8")),
}}
append_record(record)

if CONFIG["spawn_descendant"]:
    code = "import time;time.sleep(60)"
    child_stdio = subprocess.DEVNULL if CONFIG["detach_descendant_stdio"] else None
    descendant = subprocess.Popen(
        [sys.executable, "-c", code],
        stdin=child_stdio,
        stdout=child_stdio,
        stderr=child_stdio,
    )
    Path(CONFIG["descendant_pid"]).write_text(str(descendant.pid), encoding="ascii")

time.sleep(CONFIG["exec_sleep"])
payload = CONFIG["final"]
rendered = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
if CONFIG["replace_final_with_symlink"]:
    external = Path(CONFIG["external_final"])
    external.write_text(rendered, encoding="utf-8")
    final.unlink()
    final.symlink_to(external)
else:
    final.write_text(rendered, encoding="utf-8")
if CONFIG["final_mode"] is not None and not final.is_symlink():
    final.chmod(CONFIG["final_mode"])
for event in CONFIG["events"]:
    if isinstance(event, str):
        sys.stdout.write(event)
    else:
        sys.stdout.write(json.dumps(event, separators=(",", ":")) + "\\n")
    sys.stdout.flush()
time.sleep(CONFIG["post_events_sleep"])
sys.stderr.write(CONFIG["exec_stderr"])
raise SystemExit(CONFIG["exec_exit"])
"""
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o700)
    return executable, monitor, descendant_pid


def _homes(root: Path) -> tuple[Path, Path]:
    home = root / "home"
    codex_home = home / ".codex"
    home.mkdir(mode=0o700)
    codex_home.mkdir(mode=0o700)
    return home, codex_home


def _runner(
    root: Path,
    executable: Path,
    **overrides: Any,
) -> CodexSubscriptionRunner:
    home, codex_home = _homes(root)
    values: dict[str, Any] = {
        "executable": executable,
        "model": "gpt-5.6",
        "home": home,
        "codex_home": codex_home,
    }
    values.update(overrides)
    return CodexSubscriptionRunner(**values)


def _records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _path_exists(path: str | Path) -> bool:
    return Path(path).exists()


def _fail_cleanup_after_removal(
    monkeypatch: pytest.MonkeyPatch,
    *,
    prefix: str,
) -> None:
    original_rmtree = subscription_module.shutil.rmtree

    def remove_then_fail(path: str | os.PathLike[str], *args: Any, **kwargs: Any) -> None:
        original_rmtree(path, *args, **kwargs)
        if Path(path).name.startswith(prefix):
            raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(subscription_module.shutil, "rmtree", remove_then_fail)


def _bypass_subscription_auth(
    monkeypatch: pytest.MonkeyPatch,
    runner: CodexSubscriptionRunner,
) -> None:
    ready = AsyncMock(return_value="ready_chatgpt")
    monkeypatch.setattr(runner, "_check_chatgpt_auth_locked", ready, raising=False)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (field, boundary)
        for field, maximum in _RESOURCE_LIMIT_MAXIMA.items()
        for boundary in (1, maximum)
    ],
)
def test_runner_accepts_documented_resource_limit_boundaries(field: str, value: int) -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)

        runner = _runner(root, executable, **{field: value})

        assert getattr(runner, field) == value


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (field, invalid)
        for field, maximum in _RESOURCE_LIMIT_MAXIMA.items()
        for invalid in (-1, 0, maximum + 1)
    ],
)
def test_runner_rejects_resource_limits_outside_documented_bounds(
    field: str,
    value: int,
) -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)

        with pytest.raises(ConfigurationError, match="resource bounds"):
            _runner(root, executable, **{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [(field, invalid) for field in _RESOURCE_LIMIT_MAXIMA for invalid in (True, 1.5, "1024")],
)
def test_runner_rejects_non_integer_resource_limits(field: str, value: Any) -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)

        with pytest.raises(ConfigurationError, match="resource bounds must be integers"):
            _runner(root, executable, **{field: value})


@pytest.mark.asyncio
async def test_temp_root_setup_failure_removes_partially_created_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable)
        original_mkdtemp = subscription_module.tempfile.mkdtemp
        original_chmod = Path.chmod
        created: list[Path] = []

        def create_in_test_root(*args: Any, **kwargs: Any) -> str:
            kwargs["dir"] = root
            path = Path(original_mkdtemp(*args, **kwargs))
            created.append(path)
            return str(path)

        def fail_setup_chmod(path: Path, mode: int, *args: Any, **kwargs: Any) -> None:
            if path.name.startswith("verity-codex-auth-"):
                raise OSError("synthetic setup failure")
            original_chmod(path, mode, *args, **kwargs)

        monkeypatch.setattr(subscription_module.tempfile, "mkdtemp", create_in_test_root)
        monkeypatch.setattr(Path, "chmod", fail_setup_chmod)

        with pytest.raises(SemanticProviderError) as captured:
            await runner.check_chatgpt_auth()

        assert captured.value.failure_class == "internal_error"
        assert runner.last_cleanup_failure is None
        assert runner.last_auth_state == "status_failed"
        assert _records(monitor) == []
        assert len(created) == 1
        assert not created[0].exists()
        assert "synthetic setup failure" not in str(captured.value)


@pytest.mark.asyncio
async def test_temp_root_setup_cleanup_failure_is_sticky_and_content_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable)
        original_mkdtemp = subscription_module.tempfile.mkdtemp
        original_chmod = Path.chmod
        original_rmtree = subscription_module.shutil.rmtree
        created: list[Path] = []

        def create_in_test_root(*args: Any, **kwargs: Any) -> str:
            kwargs["dir"] = root
            path = Path(original_mkdtemp(*args, **kwargs))
            created.append(path)
            return str(path)

        def fail_setup_chmod(path: Path, mode: int, *args: Any, **kwargs: Any) -> None:
            if path.name.startswith("verity-codex-auth-"):
                raise OSError("synthetic setup failure")
            original_chmod(path, mode, *args, **kwargs)

        def fail_setup_cleanup(
            path: str | os.PathLike[str],
            *args: Any,
            **kwargs: Any,
        ) -> None:
            if Path(path).name.startswith("verity-codex-auth-"):
                raise OSError("synthetic setup cleanup failure")
            original_rmtree(path, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(subscription_module.tempfile, "mkdtemp", create_in_test_root)
            patch.setattr(Path, "chmod", fail_setup_chmod)
            patch.setattr(subscription_module.shutil, "rmtree", fail_setup_cleanup)

            with pytest.raises(SemanticProviderError) as captured:
                await runner.check_chatgpt_auth()

            assert captured.value.failure_class == "cleanup_failure"
            assert runner.last_cleanup_failure == "temporary_artifacts"
            assert runner.last_auth_state == "status_failed"
            assert runner.last_failure_class == "cleanup_failure"
            assert _records(monitor) == []
            assert len(created) == 1
            assert created[0].exists()
            assert "synthetic setup cleanup failure" not in str(captured.value)

            with pytest.raises(SemanticProviderError) as repeated:
                await runner.check_chatgpt_auth()
            assert repeated.value.failure_class == "cleanup_failure"
            assert len(created) == 1

        original_rmtree(created[0])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_point",
    ["work_mkdir", "schema_open", "schema_write", "final_open", "final_identity"],
)
async def test_post_root_semantic_setup_failures_are_content_safe_and_cleaned(
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable)
        _bypass_subscription_auth(monkeypatch, runner)
        original_private_temp_root = subscription_module._private_temp_root
        original_mkdir = Path.mkdir
        original_open = subscription_module.os.open
        original_write = subscription_module.os.write
        original_path_identity = subscription_module.path_identity
        semantic_roots: list[Path] = []
        leak_marker = f"SYNTHETIC-PRIVATE-PATH:{root}"

        def record_private_root(prefix: str) -> Path:
            created = original_private_temp_root(prefix)
            if prefix.startswith("verity-codex-semantic-"):
                semantic_roots.append(created)
            return created

        def controlled_mkdir(path: Path, *args: Any, **kwargs: Any) -> None:
            if failure_point == "work_mkdir" and path.name == "work":
                raise OSError(leak_marker)
            original_mkdir(path, *args, **kwargs)

        def controlled_open(
            path: str | os.PathLike[str],
            flags: int,
            mode: int = 0o777,
            **kwargs: Any,
        ) -> int:
            name = Path(path).name
            if failure_point == "schema_open" and name == "schema.json":
                raise OSError(leak_marker)
            if failure_point == "final_open" and name == "final.json":
                raise OSError(leak_marker)
            return original_open(path, flags, mode, **kwargs)

        def controlled_write(descriptor: int, data: bytes) -> int:
            if failure_point == "schema_write":
                raise OSError(leak_marker)
            return original_write(descriptor, data)

        def controlled_path_identity(path: Path) -> Any:
            if failure_point == "final_identity" and path.name == "final.json":
                raise OSError(leak_marker)
            return original_path_identity(path)

        monkeypatch.setattr(subscription_module, "_private_temp_root", record_private_root)
        monkeypatch.setattr(Path, "mkdir", controlled_mkdir)
        monkeypatch.setattr(subscription_module.os, "open", controlled_open)
        monkeypatch.setattr(subscription_module.os, "write", controlled_write)
        monkeypatch.setattr(subscription_module, "path_identity", controlled_path_identity)

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert captured.value.failure_class == "internal_error"
        assert runner.last_failure_class == "internal_error"
        assert runner.last_cleanup_failure is None
        assert _records(monitor) == []
        assert len(semantic_roots) == 1
        assert not semantic_roots[0].exists()
        assert leak_marker not in str(captured.value)
        assert str(semantic_roots[0]) not in str(captured.value)


@pytest.mark.asyncio
async def test_post_root_setup_failure_preserves_sticky_cleanup_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable)
        _bypass_subscription_auth(monkeypatch, runner)
        original_mkdir = Path.mkdir

        def fail_work_mkdir(path: Path, *args: Any, **kwargs: Any) -> None:
            if path.name == "work":
                raise OSError(f"SYNTHETIC-PRIVATE-PATH:{path}")
            original_mkdir(path, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", fail_work_mkdir)
        _fail_cleanup_after_removal(monkeypatch, prefix="verity-codex-semantic-")

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert captured.value.failure_class == "internal_error"
        assert runner.last_failure_class == "internal_error"
        assert runner.last_cleanup_failure == "temporary_artifacts"
        assert _records(monitor) == []
        assert str(root) not in str(captured.value)

        with pytest.raises(SemanticProviderError) as health_failure:
            await CodexSubscriptionRunner.check_chatgpt_auth(runner)
        assert health_failure.value.failure_class == "cleanup_failure"


@pytest.mark.asyncio
async def test_post_root_setup_cancellation_is_preserved_after_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable)
        _bypass_subscription_auth(monkeypatch, runner)
        original_private_temp_root = subscription_module._private_temp_root
        semantic_roots: list[Path] = []

        def record_private_root(prefix: str) -> Path:
            created = original_private_temp_root(prefix)
            if prefix.startswith("verity-codex-semantic-"):
                semantic_roots.append(created)
            return created

        def cancel_during_setup(path: Path, *args: Any, **kwargs: Any) -> None:
            del path, args, kwargs
            raise asyncio.CancelledError

        monkeypatch.setattr(subscription_module, "_private_temp_root", record_private_root)
        monkeypatch.setattr(Path, "mkdir", cancel_during_setup)

        with pytest.raises(asyncio.CancelledError):
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert runner.last_cleanup_failure is None
        assert _records(monitor) == []
        assert len(semantic_roots) == 1
        assert not semantic_roots[0].exists()


@pytest.mark.asyncio
async def test_post_root_setup_cancellation_preserves_sticky_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable)
        _bypass_subscription_auth(monkeypatch, runner)
        original_mkdir = Path.mkdir

        def cancel_work_setup(path: Path, *args: Any, **kwargs: Any) -> None:
            if path.name == "work":
                raise asyncio.CancelledError
            original_mkdir(path, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", cancel_work_setup)
        _fail_cleanup_after_removal(monkeypatch, prefix="verity-codex-semantic-")

        with pytest.raises(asyncio.CancelledError):
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert runner.last_cleanup_failure == "temporary_artifacts"
        assert _records(monitor) == []
        with pytest.raises(SemanticProviderError) as health_failure:
            await CodexSubscriptionRunner.check_chatgpt_auth(runner)
        assert health_failure.value.failure_class == "cleanup_failure"


@pytest.mark.asyncio
async def test_semantic_child_uses_exact_argv_stdin_only_and_private_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-SYNTHETICONLY1234567890")
        monkeypatch.setenv("VERITY_TEST_SECRET", "must-not-cross-boundary")
        sentinel = "untrusted-content-sentinel"

        assert await runner.run_json(prompt=sentinel, output_schema=_SIMPLE_SCHEMA) == {"ok": True}

        status_record, exec_record = _records(monitor)
        work = exec_record["work"]
        schema = exec_record["schema"]
        final = exec_record["final"]
        assert exec_record["argv"] == [
            "--ask-for-approval",
            "untrusted",
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--disable",
            "plugins",
            "--disable",
            "remote_plugin",
            "--disable",
            "apps",
            "--disable",
            "hooks",
            "--disable",
            "memories",
            "--disable",
            "shell_tool",
            "--disable",
            "browser_use",
            "--disable",
            "browser_use_external",
            "--disable",
            "computer_use",
            "--disable",
            "in_app_browser",
            "--disable",
            "multi_agent",
            "--disable",
            "goals",
            "--config",
            'web_search="disabled"',
            "--config",
            'shell_environment_policy.inherit="none"',
            "--model",
            "gpt-5.6",
            "--cd",
            work,
            "--output-schema",
            schema,
            "--output-last-message",
            final,
            "--color",
            "never",
            "--json",
            "-",
        ]
        assert sentinel not in exec_record["argv"]
        assert exec_record["stdin"] == sentinel
        assert exec_record["modes"] == {
            "tmp_root": 0o700,
            "work": 0o700,
            "io": 0o700,
            "schema": 0o600,
            "final": 0o600,
        }
        assert exec_record["schema_document"] == _SIMPLE_SCHEMA
        assert Path(work).parent == Path(exec_record["tmp_root"])
        assert exec_record["cwd"] == work
        assert Path(schema).parent.name == "io"
        assert Path(final).parent == Path(schema).parent
        assert not _path_exists(exec_record["tmp_root"])
        assert status_record["argv"] == ["login", "status"]


@pytest.mark.asyncio
async def test_semantic_temp_cleanup_failure_prevents_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable)
        await runner.check_chatgpt_auth()
        runner._check_chatgpt_auth_locked = AsyncMock(  # type: ignore[method-assign]
            return_value="ready_chatgpt"
        )
        _fail_cleanup_after_removal(monkeypatch, prefix="verity-codex-semantic-")

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert captured.value.failure_class == "cleanup_failure"
        assert runner.last_cleanup_failure == "temporary_artifacts"
        assert not _path_exists(_records(monitor)[1]["tmp_root"])
        assert "synthetic cleanup failure" not in str(captured.value)


@pytest.mark.asyncio
async def test_semantic_temp_cleanup_failure_does_not_mask_provider_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        events = [
            {"type": "turn.completed", "usage": {}},
            {"type": "thread.started", "thread_id": "thread-synthetic-001"},
            {"type": "turn.started"},
        ]
        executable, monitor, _ = _fake_codex(root, events=events)
        runner = _runner(root, executable)
        await runner.check_chatgpt_auth()
        runner._check_chatgpt_auth_locked = AsyncMock(  # type: ignore[method-assign]
            return_value="ready_chatgpt"
        )
        _fail_cleanup_after_removal(monkeypatch, prefix="verity-codex-semantic-")

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert captured.value.failure_class == "invalid_response"
        assert runner.last_cleanup_failure == "temporary_artifacts"
        assert not _path_exists(_records(monitor)[1]["tmp_root"])
        assert "synthetic cleanup failure" not in str(captured.value)


@pytest.mark.asyncio
async def test_child_environment_is_an_exact_allow_list_without_parent_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-SYNTHETICONLY1234567890")
        monkeypatch.setenv("CODEX_ACCESS_TOKEN", "synthetic-bearer-must-not-cross")
        monkeypatch.setenv("HTTPS_PROXY", "https://synthetic-user:synthetic-pass@example.invalid")
        monkeypatch.setenv("ARBITRARY_PARENT_VALUE", "must-not-cross")

        await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        status_record, exec_record = _records(monitor)
        assert set(status_record["env"]) - _PLATFORM_INJECTED_ENV == {
            "CODEX_HOME",
            "HOME",
            "LANG",
            "LC_ALL",
            "NO_COLOR",
            "TMPDIR",
        }
        assert set(exec_record["env"]) - _PLATFORM_INJECTED_ENV == {
            "CODEX_HOME",
            "HOME",
            "LANG",
            "LC_ALL",
            "NO_COLOR",
            "TMPDIR",
            "VERITY_SEMANTIC_CHILD",
        }
        assert set(status_record["env"]) <= {
            "CODEX_HOME",
            "HOME",
            "LANG",
            "LC_ALL",
            "NO_COLOR",
            "TMPDIR",
            *_PLATFORM_INJECTED_ENV,
        }
        assert set(exec_record["env"]) <= {
            "CODEX_HOME",
            "HOME",
            "LANG",
            "LC_ALL",
            "NO_COLOR",
            "TMPDIR",
            "VERITY_SEMANTIC_CHILD",
            *_PLATFORM_INJECTED_ENV,
        }
        assert exec_record["env"]["VERITY_SEMANTIC_CHILD"] == "1"
        assert exec_record["env"]["HOME"] == str(runner.home)
        assert exec_record["env"]["CODEX_HOME"] == str(runner.codex_home)


@pytest.mark.asyncio
async def test_oversized_stdin_is_rejected_before_auth_or_semantic_launch() -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable, max_input_bytes=32)

        with pytest.raises(SemanticProviderError, match="limit"):
            await runner.run_json(prompt="x" * 33, output_schema=_SIMPLE_SCHEMA)

        assert _records(monitor) == []


def test_explicit_executable_must_be_absolute_regular_and_not_writable() -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        home, codex_home = _homes(root)

        with pytest.raises(ConfigurationError):
            CodexSubscriptionRunner(
                executable=Path("relative/codex"),
                model="gpt-5.6",
                home=home,
                codex_home=codex_home,
            )

        executable.chmod(0o722)
        with pytest.raises(ConfigurationError):
            CodexSubscriptionRunner(
                executable=executable,
                model="gpt-5.6",
                home=home,
                codex_home=codex_home,
            )

        executable.unlink()
        executable.mkdir(mode=0o700)
        with pytest.raises(ConfigurationError):
            CodexSubscriptionRunner(
                executable=executable,
                model="gpt-5.6",
                home=home,
                codex_home=codex_home,
            )


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode contract")
def test_executable_ancestor_permissions_are_validated() -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        home, codex_home = _homes(root)
        bin_dir = executable.parent
        bin_dir.chmod(0o720)
        try:
            with pytest.raises(ConfigurationError):
                CodexSubscriptionRunner(
                    executable=executable,
                    model="gpt-5.6",
                    home=home,
                    codex_home=codex_home,
                )
        finally:
            bin_dir.chmod(0o700)


@pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0,
    reason="non-root POSIX ownership contract",
)
def test_executable_home_and_codex_home_must_be_owned_by_effective_user_or_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        home, codex_home = _homes(root)
        monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 10_000)

        with pytest.raises(ConfigurationError):
            CodexSubscriptionRunner(
                executable=executable,
                model="gpt-5.6",
                home=home,
                codex_home=codex_home,
            )


def test_executable_symlink_is_resolved_after_both_paths_are_validated() -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        link_dir = root / "links"
        link_dir.mkdir(mode=0o700)
        link = link_dir / "codex"
        link.symlink_to(executable)
        runner = _runner(root, link)

        assert runner.executable_path == executable.resolve()


def test_path_search_rejects_empty_or_relative_entries_instead_of_skipping_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        home, codex_home = _homes(root)
        for unsafe_path in (f":{executable.parent}", f"relative/bin:{executable.parent}"):
            monkeypatch.setenv("PATH", unsafe_path)
            with pytest.raises(ConfigurationError):
                CodexSubscriptionRunner(
                    executable=None,
                    model="gpt-5.6",
                    home=home,
                    codex_home=codex_home,
                )


def test_path_search_resolves_one_safe_absolute_executable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        home, codex_home = _homes(root)
        monkeypatch.setenv("PATH", str(executable.parent))

        runner = CodexSubscriptionRunner(
            executable=None,
            model="gpt-5.6",
            home=home,
            codex_home=codex_home,
        )

        assert runner.executable_path == executable.resolve()


def test_unset_codex_home_derives_existing_private_directory_under_home() -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        home, codex_home = _homes(root)

        runner = CodexSubscriptionRunner(
            executable=executable,
            model="gpt-5.6",
            home=home,
            codex_home=None,
        )

        assert runner.codex_home == codex_home


@pytest.mark.asyncio
@pytest.mark.parametrize("replacement", ["inode", "digest"])
async def test_executable_replacement_or_digest_drift_fails_before_launch(
    replacement: str,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable)
        original = executable.read_text(encoding="utf-8")
        if replacement == "inode":
            moved = executable.with_suffix(".old")
            executable.replace(moved)
            executable.write_text(original, encoding="utf-8")
            executable.chmod(0o700)
        else:
            executable.write_text(original + "\n# digest drift\n", encoding="utf-8")
            executable.chmod(0o700)

        with pytest.raises(SemanticProviderError, match=r"changed|drift"):
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert _records(monitor) == []


def test_home_and_codex_home_must_be_private_non_symlink_directories() -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        home, codex_home = _homes(root)
        unsafe = root / "unsafe-home"
        unsafe.mkdir(mode=0o700)
        link = root / "linked-home"
        link.symlink_to(unsafe, target_is_directory=True)

        with pytest.raises(ConfigurationError):
            CodexSubscriptionRunner(
                executable=executable,
                model="gpt-5.6",
                home=link,
                codex_home=codex_home,
            )

        codex_home.rmdir()
        codex_home.symlink_to(unsafe, target_is_directory=True)
        with pytest.raises(ConfigurationError):
            CodexSubscriptionRunner(
                executable=executable,
                model="gpt-5.6",
                home=home,
                codex_home=codex_home,
            )


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode contract")
def test_home_ancestor_and_directory_modes_are_validated() -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        home, codex_home = _homes(root)
        home.chmod(0o720)
        try:
            with pytest.raises(ConfigurationError):
                CodexSubscriptionRunner(
                    executable=executable,
                    model="gpt-5.6",
                    home=home,
                    codex_home=codex_home,
                )
        finally:
            home.chmod(0o700)


@pytest.mark.asyncio
async def test_home_identity_and_mode_drift_are_rechecked_before_status() -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable)
        runner.home.chmod(0o720)
        try:
            with pytest.raises(SemanticProviderError, match=r"changed|drift"):
                await runner.check_chatgpt_auth()
        finally:
            runner.home.chmod(0o700)

        assert _records(monitor) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("directory_name", ["home", "codex_home"])
async def test_home_or_codex_home_replacement_is_rejected_before_status(
    directory_name: str,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _runner(root, executable)
        target = runner.home if directory_name == "home" else runner.codex_home
        moved = target.with_name(target.name + "-original")
        target.replace(moved)
        target.mkdir(mode=0o700)

        with pytest.raises(SemanticProviderError, match=r"changed|drift"):
            await runner.check_chatgpt_auth()

        assert _records(monitor) == []


def test_model_identifier_is_bounded_and_never_echoed_on_error() -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        home, codex_home = _homes(root)
        synthetic_secret = "sk-proj-SYNTHETICONLY1234567890"

        with pytest.raises(ConfigurationError) as captured:
            CodexSubscriptionRunner(
                executable=executable,
                model=synthetic_secret,
                home=home,
                codex_home=codex_home,
            )

        assert synthetic_secret not in str(captured.value)


def test_fake_executable_itself_has_no_group_or_world_permissions() -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        assert stat.S_IMODE(executable.stat().st_mode) == 0o700


@pytest.mark.asyncio
async def test_final_output_duplicate_keys_symlink_and_mode_drift_are_rejected() -> None:
    cases: list[dict[str, Any]] = [
        {"final": '{"ok":true,"ok":false}'},
        {"replace_final_with_symlink": True},
        {"final_mode": 0o666},
    ]
    for case in cases:
        with _secure_tree() as root:
            executable, _, _ = _fake_codex(root, **case)
            runner = _runner(root, executable)

            with pytest.raises(SemanticProviderError):
                await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)


@pytest.mark.asyncio
async def test_final_output_opened_descriptor_must_match_validated_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        runner = _runner(root, executable)
        original_open = os.open
        swapped = False

        def swap_before_read(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal swapped
            target = Path(path) if isinstance(path, (str, os.PathLike)) else None
            if (
                not swapped
                and dir_fd is None
                and target is not None
                and target.name == "final.json"
                and flags & os.O_ACCMODE == os.O_RDONLY
            ):
                replacement = target.with_name("replacement.json")
                replacement.write_text('{"ok":false}', encoding="utf-8")
                replacement.chmod(0o600)
                replacement.replace(target)
                swapped = True
            if dir_fd is None:
                return original_open(path, flags, mode)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(
            "verity_cordon.semantic.codex_subscription.os.open",
            swap_before_read,
        )

        with pytest.raises(SemanticProviderError, match="unsafe"):
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert swapped is True
