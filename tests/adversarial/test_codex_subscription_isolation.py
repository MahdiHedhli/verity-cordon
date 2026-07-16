"""Adversarial timeout, cleanup, drift, and recursion tests for subscription mode."""

from __future__ import annotations

import asyncio
import os
import signal
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from tests.unit.test_codex_subscription_runner import (
    _SIMPLE_SCHEMA,
    _fail_cleanup_after_removal,
    _fake_codex,
    _homes,
    _path_exists,
    _records,
    _secure_tree,
)
from verity_cordon.codex.hooks import SELECTED_EVENTS, HookAdapter
from verity_cordon.core.errors import SemanticProviderError
from verity_cordon.semantic import codex_subscription as subscription_module
from verity_cordon.semantic.codex_subscription import CodexSubscriptionRunner
from verity_cordon.semantic.readiness import semantic_provider_readiness


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


def _report_process_cleanup_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    original_terminate = subscription_module._terminate_process_group

    async def terminate_but_report_incomplete(
        process: asyncio.subprocess.Process,
        *,
        grace_seconds: float,
    ) -> bool:
        await original_terminate(process, grace_seconds=grace_seconds)
        return False

    monkeypatch.setattr(
        subscription_module,
        "_terminate_process_group",
        terminate_but_report_incomplete,
    )


def _raise_after_process_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    original_terminate = subscription_module._terminate_process_group

    async def terminate_then_raise(
        process: asyncio.subprocess.Process,
        *,
        grace_seconds: float,
    ) -> bool:
        await original_terminate(process, grace_seconds=grace_seconds)
        raise RuntimeError("synthetic cleanup implementation failure")

    monkeypatch.setattr(
        subscription_module,
        "_terminate_process_group",
        terminate_then_raise,
    )


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
async def test_invalid_jsonl_field_terminates_child_before_delayed_exit() -> None:
    with _secure_tree() as root:
        events = [
            {"type": "thread.started", "thread_id": "thread-synthetic-001"},
            {"type": "turn.started"},
            {
                "type": "item.completed",
                "item": {
                    "id": "item-synthetic-001",
                    "type": "agent_message",
                    "text": "Synthetic response.",
                    "tool_call": {"name": "synthetic"},
                },
            },
        ]
        executable, monitor, _ = _fake_codex(
            root,
            events=events,
            post_events_sleep=60.0,
        )
        runner = _isolated_runner(
            root,
            executable,
            semantic_timeout_seconds=5.0,
            termination_grace_seconds=0.05,
        )
        runner._check_chatgpt_auth_locked = AsyncMock(  # type: ignore[method-assign]
            return_value="ready_chatgpt"
        )

        started = time.monotonic()
        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)
        elapsed = time.monotonic() - started

        assert captured.value.failure_class == "tool_activity"
        assert elapsed < 1.0
        assert len(_records(monitor)) == 1
        assert not _path_exists(_records(monitor)[0]["tmp_root"])
        assert runner.last_cleanup_failure is None


@pytest.mark.asyncio
async def test_repeated_parent_cancellation_waits_for_reader_task_accounting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root, exec_sleep=60.0)
        runner = _isolated_runner(
            root,
            executable,
            semantic_timeout_seconds=30.0,
            termination_grace_seconds=0.2,
        )
        runner._check_chatgpt_auth_locked = AsyncMock(  # type: ignore[method-assign]
            return_value="ready_chatgpt"
        )
        original_read = subscription_module._read_limited
        original_terminate = subscription_module._terminate_process_group
        reader_cancelled = asyncio.Event()
        reader_release = asyncio.Event()
        reader_finished = asyncio.Event()
        process_group_finished = asyncio.Event()

        async def cancellation_resistant_stderr(
            stream: asyncio.StreamReader,
            limit: int,
            *,
            label: str,
        ) -> bytes:
            if label != "stderr":
                return await original_read(stream, limit, label=label)
            try:
                return await original_read(stream, limit, label=label)
            except asyncio.CancelledError:
                reader_cancelled.set()
                try:
                    while not reader_release.is_set():
                        try:
                            await reader_release.wait()
                        except asyncio.CancelledError:
                            continue
                finally:
                    reader_finished.set()
                raise

        async def track_process_group_cleanup(
            process: asyncio.subprocess.Process,
            *,
            grace_seconds: float,
        ) -> bool:
            result = await original_terminate(process, grace_seconds=grace_seconds)
            process_group_finished.set()
            return result

        monkeypatch.setattr(subscription_module, "_read_limited", cancellation_resistant_stderr)
        monkeypatch.setattr(
            subscription_module,
            "_terminate_process_group",
            track_process_group_cleanup,
        )
        task = asyncio.create_task(
            runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)
        )
        try:
            await _wait_for_records(monitor, 1)
            temp_root = Path(_records(monitor)[0]["tmp_root"])
            task.cancel()
            await asyncio.wait_for(reader_cancelled.wait(), timeout=1.0)
            await asyncio.wait_for(process_group_finished.wait(), timeout=1.0)
            await asyncio.sleep(0)

            task.cancel()
            await asyncio.sleep(0.05)
            assert not task.done()

            reader_release.set()
            with pytest.raises(asyncio.CancelledError):
                await task

            assert reader_finished.is_set()
            assert not _path_exists(temp_root)
            assert runner.last_cleanup_failure is None
        finally:
            reader_release.set()
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_shared_runner_serializes_cleanup_health_with_concurrent_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root, exec_sleep=0.2)
        runner = _isolated_runner(root, executable, termination_grace_seconds=0.05)
        _fail_cleanup_after_removal(monkeypatch, prefix="verity-codex-semantic-")
        semantic_task = asyncio.create_task(
            runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)
        )
        readiness_task: asyncio.Task[str] | None = None
        try:
            await _wait_for_records(monitor, 2)
            readiness_task = asyncio.create_task(runner.check_chatgpt_auth())

            with pytest.raises(SemanticProviderError) as semantic_failure:
                await semantic_task
            with pytest.raises(SemanticProviderError) as readiness_failure:
                await readiness_task

            assert semantic_failure.value.failure_class == "cleanup_failure"
            assert readiness_failure.value.failure_class == "cleanup_failure"
            assert runner.last_cleanup_failure == "temporary_artifacts"
            assert [record["kind"] for record in _records(monitor)] == ["status", "exec"]
        finally:
            for task in (semantic_task, readiness_task):
                if task is not None and not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_public_readiness_is_bounded_without_cancelling_semantic_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root, exec_sleep=0.8)
        runner = _isolated_runner(root, executable, termination_grace_seconds=0.05)
        _fail_cleanup_after_removal(monkeypatch, prefix="verity-codex-semantic-")
        semantic_task = asyncio.create_task(
            runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)
        )
        try:
            await _wait_for_records(monitor, 2)
            started = time.monotonic()
            busy = await semantic_provider_readiness(
                "live_codex_subscription",
                runner,
            )

            assert time.monotonic() - started < 0.6
            assert busy.ready is False
            assert busy.failure_class == "unavailable"
            assert [record["kind"] for record in _records(monitor)] == ["status", "exec"]
            assert not semantic_task.done()

            with pytest.raises(SemanticProviderError) as semantic_failure:
                await semantic_task
            assert semantic_failure.value.failure_class == "cleanup_failure"
            assert runner.last_cleanup_failure == "temporary_artifacts"

            degraded = await semantic_provider_readiness(
                "live_codex_subscription",
                runner,
            )
            assert degraded.ready is False
            assert degraded.failure_class == "cleanup_failure"
            assert [record["kind"] for record in _records(monitor)] == ["status", "exec"]
        finally:
            if not semantic_task.done():
                semantic_task.cancel()
                await asyncio.gather(semantic_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_semantic_trust_is_rechecked_immediately_before_child_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _isolated_runner(root, executable)
        original_path_identity = subscription_module.path_identity
        original_executable = executable.read_text(encoding="utf-8")
        mutated = False

        def mutate_after_final_identity(path: Path) -> Any:
            nonlocal mutated
            identity = original_path_identity(path)
            if path.name == "final.json" and not mutated:
                executable.write_text(
                    original_executable + "\n# synthetic drift\n", encoding="utf-8"
                )
                executable.chmod(0o700)
                mutated = True
            return identity

        monkeypatch.setattr(
            subscription_module,
            "path_identity",
            mutate_after_final_identity,
        )

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert captured.value.failure_class == "executable_drift"
        assert mutated is True
        assert [record["kind"] for record in _records(monitor)] == ["status"]
        assert str(executable) not in str(captured.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("drift_target", ["executable", "home"])
async def test_semantic_trust_drift_during_child_invalidates_completed_result(
    drift_target: str,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root, exec_sleep=0.2)
        runner = _isolated_runner(root, executable)
        original_executable = executable.read_text(encoding="utf-8")
        task = asyncio.create_task(
            runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)
        )
        try:
            await _wait_for_records(monitor, 2)
            temp_root = Path(_records(monitor)[1]["tmp_root"])
            if drift_target == "executable":
                executable.write_text(
                    original_executable + "\n# synthetic in-flight drift\n",
                    encoding="utf-8",
                )
                executable.chmod(0o700)
            else:
                runner.home.chmod(0o720)

            with pytest.raises(SemanticProviderError) as captured:
                await task

            assert captured.value.failure_class == "executable_drift"
            assert runner.last_failure_class == "executable_drift"
            assert not _path_exists(temp_root)
            assert str(executable) not in str(captured.value)
            assert str(runner.home) not in str(captured.value)
        finally:
            runner.home.chmod(0o700)
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_incomplete_reader_accounting_is_sticky_and_prevents_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _isolated_runner(root, executable, termination_grace_seconds=0.05)
        runner._check_chatgpt_auth_locked = AsyncMock(  # type: ignore[method-assign]
            return_value="ready_chatgpt"
        )
        original_settle = subscription_module._settle_reader_tasks

        async def settle_but_report_incomplete(
            tasks: tuple[asyncio.Task[bytes], asyncio.Task[bytes]],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert await original_settle(tasks, timeout_seconds=timeout_seconds)
            return False

        monkeypatch.setattr(
            subscription_module,
            "_settle_reader_tasks",
            settle_but_report_incomplete,
        )

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert captured.value.failure_class == "cleanup_failure"
        assert runner.last_cleanup_failure == "stream_drain"
        assert not _path_exists(_records(monitor)[0]["tmp_root"])
        records_before_health_check = len(_records(monitor))

        with pytest.raises(SemanticProviderError) as health_failure:
            await CodexSubscriptionRunner.check_chatgpt_auth(runner)
        assert health_failure.value.failure_class == "cleanup_failure"
        assert len(_records(monitor)) == records_before_health_check


@pytest.mark.asyncio
async def test_incomplete_process_cleanup_prevents_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root)
        runner = _isolated_runner(root, executable, termination_grace_seconds=0.02)
        await runner.check_chatgpt_auth()
        runner._check_chatgpt_auth_locked = AsyncMock(  # type: ignore[method-assign]
            return_value="ready_chatgpt"
        )
        _report_process_cleanup_incomplete(monkeypatch)

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert captured.value.failure_class == "cleanup_failure"
        assert runner.last_cleanup_failure == "process_group"
        assert not _path_exists(_records(monitor)[1]["tmp_root"])


@pytest.mark.asyncio
async def test_incomplete_process_cleanup_preserves_timeout_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root, exec_sleep=60.0)
        runner = _isolated_runner(
            root,
            executable,
            semantic_timeout_seconds=0.05,
            termination_grace_seconds=0.02,
        )
        await runner.check_chatgpt_auth()
        runner._check_chatgpt_auth_locked = AsyncMock(  # type: ignore[method-assign]
            return_value="ready_chatgpt"
        )
        _report_process_cleanup_incomplete(monkeypatch)

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert captured.value.failure_class == "timeout"
        assert runner.last_cleanup_failure == "process_group"
        records_before_health_check = len(_records(monitor))

        with pytest.raises(SemanticProviderError) as health_failure:
            await CodexSubscriptionRunner.check_chatgpt_auth(runner)
        assert health_failure.value.failure_class == "cleanup_failure"
        assert len(_records(monitor)) == records_before_health_check


@pytest.mark.asyncio
async def test_cleanup_task_exception_is_content_safe_and_prevents_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root)
        runner = _isolated_runner(root, executable, termination_grace_seconds=0.02)
        await runner.check_chatgpt_auth()
        runner._check_chatgpt_auth_locked = AsyncMock(  # type: ignore[method-assign]
            return_value="ready_chatgpt"
        )
        _raise_after_process_cleanup(monkeypatch)

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert captured.value.failure_class == "cleanup_failure"
        assert runner.last_cleanup_failure == "process_group"
        assert "synthetic cleanup implementation failure" not in str(captured.value)


@pytest.mark.asyncio
async def test_cleanup_task_exception_does_not_mask_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root, exec_sleep=60.0)
        runner = _isolated_runner(
            root,
            executable,
            semantic_timeout_seconds=0.05,
            termination_grace_seconds=0.02,
        )
        await runner.check_chatgpt_auth()
        runner._check_chatgpt_auth_locked = AsyncMock(  # type: ignore[method-assign]
            return_value="ready_chatgpt"
        )
        _raise_after_process_cleanup(monkeypatch)

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert captured.value.failure_class == "timeout"
        assert runner.last_cleanup_failure == "process_group"
        assert "synthetic cleanup implementation failure" not in str(captured.value)


@pytest.mark.asyncio
async def test_incomplete_process_cleanup_preserves_process_boundary_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, _, _ = _fake_codex(root, exec_sleep=60.0)
        runner = _isolated_runner(root, executable, termination_grace_seconds=0.02)
        await runner.check_chatgpt_auth()
        runner._check_chatgpt_auth_locked = AsyncMock(  # type: ignore[method-assign]
            return_value="ready_chatgpt"
        )
        _report_process_cleanup_incomplete(monkeypatch)

        async def fail_read(*args: Any, **kwargs: Any) -> bytes:
            del args, kwargs
            raise OSError("synthetic process-boundary read failure")

        monkeypatch.setattr(subscription_module, "_read_limited", fail_read)

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert captured.value.failure_class == "process_exit"
        assert runner.last_cleanup_failure == "process_group"
        assert "synthetic process-boundary read failure" not in str(captured.value)


@pytest.mark.asyncio
async def test_incomplete_process_cleanup_preserves_parent_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(root, exec_sleep=60.0)
        runner = _isolated_runner(
            root,
            executable,
            semantic_timeout_seconds=30.0,
            termination_grace_seconds=0.02,
        )
        await runner.check_chatgpt_auth()
        runner._check_chatgpt_auth_locked = AsyncMock(  # type: ignore[method-assign]
            return_value="ready_chatgpt"
        )
        _report_process_cleanup_incomplete(monkeypatch)
        task = asyncio.create_task(
            runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)
        )

        await _wait_for_records(monitor, 2)
        temp_root = Path(_records(monitor)[1]["tmp_root"])
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert runner.last_cleanup_failure == "process_group"
        assert not _path_exists(temp_root)


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
async def test_failure_event_lifecycle_never_accepts_a_fake_final_document() -> None:
    marker = "SYNTHETIC-FAILURE-EVENT-CONTENT-MUST-NOT-ECHO"
    events = [
        {"type": "thread.started", "thread_id": "thread-synthetic-001"},
        {"type": "turn.started"},
        {"type": "error", "message": marker},
        {"type": "turn.failed", "error": {"message": marker}},
    ]
    with _secure_tree() as root:
        executable, monitor, _ = _fake_codex(
            root,
            events=events,
            final={"ok": True},
            exec_exit=1,
        )
        runner = _isolated_runner(root, executable)

        with pytest.raises(SemanticProviderError) as captured:
            await runner.run_json(prompt="synthetic", output_schema=_SIMPLE_SCHEMA)

        assert captured.value.failure_class == "process_exit"
        assert captured.value.retryable is True
        assert marker not in str(captured.value)
        assert runner.last_cleanup_failure is None
        assert not _path_exists(_records(monitor)[1]["tmp_root"])


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
