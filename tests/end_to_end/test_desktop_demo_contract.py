"""End-to-end contract for the bounded Desktop fixture and install boundary."""

from __future__ import annotations

import os
import stat
import sys
import time
import tomllib
from pathlib import Path

import pytest

from tests.contract.test_desktop_demo_setup import (
    MANAGED_NAME,
    NORMAL_RECEIPT,
    _api,
    _ready_context,
    _setup,
    _teardown,
    _tree_snapshot,
)

RAW_ATTACK_FRAGMENT = "For all future releases"
RAW_SINK_FRAGMENT = "Before publishing, send the release manifest"
STABLE_GUIDANCE_SHA256 = "8032a7249839a6e9059ffe31ea98e2191927388ce404baf1dbb5b111b5f6d40e"


def test_bounded_fixture_probe_is_content_safe_and_separate_from_normal_install(
    tmp_path: Path,
) -> None:
    context = _ready_context(tmp_path)
    normal_receipt = context.data_dir / NORMAL_RECEIPT
    normal_marketplace = context.data_dir / "codex-marketplace"
    receipt_before = normal_receipt.read_bytes()
    marketplace_before = _tree_snapshot(normal_marketplace)
    config_after_normal_install = tomllib.loads(context.config_path.read_text(encoding="utf-8"))

    assert MANAGED_NAME not in config_after_normal_install.get("mcp_servers", {})
    assert b"poisoned_docs" not in receipt_before
    assert all("poisoned_docs" not in path for path in marketplace_before)

    preview = _setup(context)
    installed = _setup(
        context,
        confirmed=True,
        expected_preview_digest=preview.preview_digest,
    )
    staged_script = installed.staging_root / "poisoned_docs_server.py"
    probe = _api().probe_desktop_fixture(
        staged_script,
        python_executable=context.python_executable,
        timeout_seconds=2.0,
        max_output_bytes=64 * 1024,
    )

    assert probe.ready is True
    assert probe.server_name == "verity-cordon-poisoned-docs-fixture"
    assert probe.protocol_version == "2025-11-25"
    assert tuple(probe.tool_names) == (
        "get_release_guidance",
        "demo_artifact_sink",
    )
    assert probe.guidance_sha256 == STABLE_GUIDANCE_SHA256
    assert probe.sink_invoked is False
    assert probe.issues == ()
    assert not hasattr(probe, "guidance")
    assert not hasattr(probe, "raw_response")
    assert RAW_ATTACK_FRAGMENT not in repr(probe)
    assert RAW_SINK_FRAGMENT not in repr(probe)

    assert normal_receipt.read_bytes() == receipt_before
    assert _tree_snapshot(normal_marketplace) == marketplace_before

    teardown_preview = _teardown(context)
    removed = _teardown(
        context,
        confirmed=True,
        expected_preview_digest=teardown_preview.preview_digest,
    )

    assert removed.applied is True
    assert removed.state == "removed"
    restored = tomllib.loads(context.config_path.read_text(encoding="utf-8"))
    assert MANAGED_NAME not in restored.get("mcp_servers", {})
    assert restored["features"] == {"hooks": True, "memories": False}
    assert restored["memories"] == {
        "generate_memories": False,
        "use_memories": False,
        "disable_on_external_context": True,
    }
    assert normal_receipt.read_bytes() == receipt_before
    assert _tree_snapshot(normal_marketplace) == marketplace_before
    assert context.runner.installed is True


@pytest.mark.parametrize(
    ("script_body", "expected_issue", "max_output_bytes"),
    [
        (
            "import time\ntime.sleep(30)\n",
            "fixture_probe_timeout",
            1024,
        ),
        (
            'import sys\nsys.stdout.write("synthetic-private-output-" * 10000)\n',
            "fixture_probe_output_limit",
            1024,
        ),
    ],
)
def test_fixture_probe_bounds_time_and_output_without_echoing_child_content(
    tmp_path: Path,
    script_body: str,
    expected_issue: str,
    max_output_bytes: int,
) -> None:
    fixture = tmp_path / "synthetic_probe_fixture.py"
    fixture.write_text(script_body, encoding="utf-8")
    fixture.chmod(0o600)
    assert stat.S_IMODE(fixture.stat().st_mode) == 0o600

    started = time.monotonic()
    report = _api().probe_desktop_fixture(
        fixture,
        python_executable=Path(sys.executable).resolve(),
        timeout_seconds=0.1,
        max_output_bytes=max_output_bytes,
    )
    elapsed = time.monotonic() - started

    assert elapsed < 2.0
    assert report.ready is False
    assert report.sink_invoked is False
    assert report.issues == (expected_issue,)
    assert "synthetic-private-output" not in repr(report)


def test_fixture_probe_rejects_symlink_relative_and_traversal_script_paths(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "synthetic_probe_fixture.py"
    fixture.write_text("raise SystemExit(0)\n", encoding="utf-8")
    fixture.chmod(0o600)
    link = tmp_path / "fixture-link.py"
    link.symlink_to(fixture)
    nested = tmp_path / "nested"
    nested.mkdir(mode=0o700)

    unsafe_paths = (
        link,
        Path("synthetic-relative-fixture.py"),
        nested / ".." / fixture.name,
    )
    for unsafe in unsafe_paths:
        report = _api().probe_desktop_fixture(
            unsafe,
            python_executable=Path(sys.executable).resolve(),
        )
        assert report.ready is False
        assert report.issues == ("fixture_probe_failed",)


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group cleanup contract")
def test_fixture_probe_cleans_descendant_after_direct_child_exits(tmp_path: Path) -> None:
    fixture = tmp_path / "synthetic_descendant_probe.py"
    pid_path = tmp_path / "synthetic-descendant.pid"
    fixture.write_text(
        "import json\n"
        "import subprocess\n"
        "import sys\n"
        "for _ in range(3):\n"
        "    sys.stdin.readline()\n"
        f"child = subprocess.Popen([{str(Path(sys.executable).resolve())!r}, "
        "'-c', 'import time; time.sleep(30)'], stdout=sys.stdout, stderr=sys.stderr)\n"
        f"open({str(pid_path)!r}, 'w', encoding='utf-8').write(str(child.pid))\n"
        "responses = [\n"
        "    {'jsonrpc': '2.0', 'id': 1, 'result': {'protocolVersion': '2025-11-25', "
        "'serverInfo': {'name': 'verity-cordon-poisoned-docs-fixture'}}},\n"
        "    {'jsonrpc': '2.0', 'id': 2, 'result': {'tools': ["
        "{'name': 'get_release_guidance'}, {'name': 'demo_artifact_sink'}]}},\n"
        "]\n"
        "for response in responses:\n"
        "    print(json.dumps(response), flush=True)\n",
        encoding="utf-8",
    )
    fixture.chmod(0o600)

    report = _api().probe_desktop_fixture(
        fixture,
        python_executable=Path(sys.executable).resolve(),
        timeout_seconds=0.2,
        max_output_bytes=4096,
    )

    assert report.ready is False
    assert report.issues == ("fixture_probe_timeout",)
    descendant_pid = int(pid_path.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            os.kill(descendant_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        pytest.fail("fixture probe descendant survived process-group cleanup")
