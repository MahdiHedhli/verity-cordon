"""Adversarial timeout, cleanup, drift, and recursion tests for subscription mode."""

from __future__ import annotations

import asyncio
import os
import signal
import time
from pathlib import Path
from typing import Any

import pytest

from tests.unit.test_codex_subscription_runner import (
    _SIMPLE_SCHEMA,
    _fake_codex,
    _homes,
    _path_exists,
    _records,
    _secure_tree,
)
from verity_cordon.codex.hooks import SELECTED_EVENTS, HookAdapter
from verity_cordon.core.errors import SemanticProviderError
from verity_cordon.semantic.codex_subscription import CodexSubscriptionRunner


def _isolated_runner(
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


def _wait_for_path_sync(path: Path, wait_seconds: float) -> None:
    deadline = time.monotonic() + wait_seconds
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError
        time.sleep(0.01)


async def _wait_for_path(path: Path, wait_seconds: float = 2.0) -> None:
    await asyncio.to_thread(_wait_for_path_sync, path, wait_seconds)


def _wait_for_records_sync(path: Path, count: int, wait_seconds: float) -> None:
    deadline = time.monotonic() + wait_seconds
    while len(_records(path)) < count:
        if time.monotonic() >= deadline:
            raise TimeoutError
        time.sleep(0.01)


async def _wait_for_records(path: Path, count: int, wait_seconds: float = 2.0) -> None:
    await asyncio.to_thread(_wait_for_records_sync, path, count, wait_seconds)


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _force_kill(pid: int | None) -> None:
    if pid is None:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _wait_for_pid_exit_sync(pid: int, wait_seconds: float) -> None:
    deadline = time.monotonic() + wait_seconds
    while _pid_exists(pid):
        if time.monotonic() >= deadline:
            raise TimeoutError
        time.sleep(0.02)


async def _wait_for_pid_exit(pid: int, wait_seconds: float = 2.0) -> None:
    await asyncio.to_thread(_wait_for_pid_exit_sync, pid, wait_seconds)


@pytest.mark.asyncio
async def test_timeout_terminates_process_group_descendants_and_removes_temp_tree() -> None:
    with _secure_tree() as root:
        executable, monitor, descendant_file = _fake_codex(
            root,
            exec_sleep=60.0,
            spawn_descendant=True,
        )
        runner = _isolated_runner(
            root,
            executable,
            semantic_timeout_seconds=0.15,
            termination_grace_seconds=0.05,
        )

        descendant_pid: int | None = None
        try:
            with pytest.raises(SemanticProviderError, match="timed out"):
                await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

            await _wait_for_path(descendant_file)
            descendant_pid = int(descendant_file.read_text(encoding="ascii"))
            await _wait_for_pid_exit(descendant_pid)
            descendant_pid = None
            exec_record = _records(monitor)[1]
            assert not _path_exists(exec_record["tmp_root"])
        finally:
            _force_kill(descendant_pid)


@pytest.mark.asyncio
async def test_parent_cancellation_reaps_descendants_before_reraising() -> None:
    with _secure_tree() as root:
        executable, monitor, descendant_file = _fake_codex(
            root,
            exec_sleep=60.0,
            spawn_descendant=True,
        )
        runner = _isolated_runner(
            root,
            executable,
            semantic_timeout_seconds=30.0,
            termination_grace_seconds=0.05,
        )
        descendant_pid: int | None = None
        task = asyncio.create_task(
            runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)
        )
        try:
            await _wait_for_records(monitor, 2)
            await _wait_for_path(descendant_file)
            descendant_pid = int(descendant_file.read_text(encoding="ascii"))
            temp_root = Path(_records(monitor)[1]["tmp_root"])

            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            await _wait_for_pid_exit(descendant_pid)
            descendant_pid = None
            assert not _path_exists(temp_root)
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            _force_kill(descendant_pid)


@pytest.mark.asyncio
async def test_successful_leader_exit_reaps_descendants_with_detached_stdio() -> None:
    with _secure_tree() as root:
        executable, monitor, descendant_file = _fake_codex(
            root,
            spawn_descendant=True,
            detach_descendant_stdio=True,
        )
        runner = _isolated_runner(
            root,
            executable,
            termination_grace_seconds=0.1,
        )
        descendant_pid: int | None = None
        try:
            assert await runner.run_json(
                prompt="synthetic",
                output_schema=_SIMPLE_SCHEMA,
            ) == {"ok": True}

            await _wait_for_path(descendant_file)
            descendant_pid = int(descendant_file.read_text(encoding="ascii"))
            await _wait_for_pid_exit(descendant_pid)
            descendant_pid = None
            assert not _path_exists(_records(monitor)[1]["tmp_root"])
        finally:
            _force_kill(descendant_pid)


@pytest.mark.asyncio
async def test_semantic_deadline_includes_blocked_stdin_transfer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(
            root,
            stdin_read_delay=60.0,
        )
        runner = _isolated_runner(
            root,
            executable,
            semantic_timeout_seconds=0.15,
            termination_grace_seconds=0.05,
        )
        private_roots: list[Path] = []
        from verity_cordon.semantic import codex_subscription as subscription_module

        original_private_temp_root = subscription_module._private_temp_root

        def record_private_root(prefix: str) -> Path:
            created = original_private_temp_root(prefix)
            private_roots.append(created)
            return created

        monkeypatch.setattr(subscription_module, "_private_temp_root", record_private_root)

        started = time.monotonic()
        with pytest.raises(SemanticProviderError, match="timed out"):
            await runner.run_json(
                prompt="x" * 200_000,
                output_schema=_SIMPLE_SCHEMA,
            )

        assert time.monotonic() - started < 2.0
        assert _records(monitor)[0]["kind"] == "status"
        assert private_roots
        assert all(not _path_exists(path) for path in private_roots)


@pytest.mark.asyncio
async def test_tool_activity_rejects_an_otherwise_valid_final_document() -> None:
    with _secure_tree() as root:
        events = [
            {"type": "thread.started", "thread_id": "thread-synthetic-001"},
            {"type": "turn.started"},
            {
                "type": "item.completed",
                "item": {
                    "id": "item-tool-synthetic",
                    "type": "command_execution",
                    "status": "denied",
                },
            },
            {"type": "turn.completed", "usage": {}},
        ]
        executable, monitor, _ = _fake_codex(root, events=events, final={"ok": True})
        runner = _isolated_runner(root, executable)

        with pytest.raises(SemanticProviderError, match="tool activity"):
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert not _path_exists(_records(monitor)[1]["tmp_root"])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kwargs", "bounds", "expected"),
    [
        ({"final": "x" * 512}, {"max_final_bytes": 128}, "limit"),
        ({"exec_stderr": "x" * 512}, {"max_stderr_bytes": 128}, "limit"),
        (
            {"events": ["x" * 512 + "\n"]},
            {"max_jsonl_bytes": 128, "max_jsonl_line_bytes": 128},
            "limit",
        ),
    ],
)
async def test_final_stderr_and_jsonl_caps_abort_without_retaining_content(
    kwargs: dict[str, Any],
    bounds: dict[str, Any],
    expected: str,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root, **kwargs)
        runner = _isolated_runner(
            root,
            executable,
            **bounds,
        )

        with pytest.raises(SemanticProviderError, match=expected) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert "x" * 32 not in str(captured.value)
        assert not _path_exists(_records(monitor)[1]["tmp_root"])


@pytest.mark.asyncio
async def test_nonzero_semantic_exit_discards_child_stderr() -> None:
    with _secure_tree() as root:
        marker = "SYNTHETIC-CHILD-DETAIL-MUST-NOT-ECHO"
        executable, _, _ = _fake_codex(root, exec_exit=9, exec_stderr=marker)
        runner = _isolated_runner(root, executable)

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert marker not in str(captured.value)


@pytest.mark.asyncio
async def test_executable_replacement_between_auth_and_semantic_launch_is_rejected() -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root, status_sleep=0.3)
        runner = _isolated_runner(root, executable)
        original = executable.read_text(encoding="utf-8")
        task = asyncio.create_task(
            runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)
        )
        await _wait_for_records(monitor, 1)
        old = executable.with_suffix(".running")
        executable.replace(old)
        executable.write_text(original, encoding="utf-8")
        executable.chmod(0o700)

        with pytest.raises(SemanticProviderError, match=r"changed|drift"):
            await task

        assert [record["kind"] for record in _records(monitor)] == ["status"]


@pytest.mark.parametrize("event_name", sorted(SELECTED_EVENTS))
def test_recursion_marker_short_circuits_before_parsing_or_daemon_io(
    monkeypatch: pytest.MonkeyPatch,
    event_name: str,
) -> None:
    calls: list[dict[str, Any]] = []

    def forbidden_transport(**kwargs: Any) -> Any:
        calls.append(kwargs)
        raise AssertionError("semantic child must never contact the daemon")

    monkeypatch.setenv("VERITY_SEMANTIC_CHILD", "1")
    adapter = HookAdapter(transport=forbidden_transport)

    assert adapter.process(event_name, b"deliberately-not-json") == {"continue": True}
    assert calls == []
