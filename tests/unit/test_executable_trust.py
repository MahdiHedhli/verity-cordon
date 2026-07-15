"""Focused tests for the reusable local executable trust boundary."""

from __future__ import annotations

import os
from hashlib import sha256
from pathlib import Path

import pytest

from tests.unit.test_codex_subscription_runner import _secure_tree
from verity_cordon.core.errors import ConfigurationError
from verity_cordon.core.executable_trust import (
    recheck_trusted_executable,
    resolve_trusted_executable,
)


def _executable(directory: Path, name: str = "runner", *, body: str = "exit 0\n") -> Path:
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}", encoding="utf-8")
    path.chmod(0o700)
    return path


@pytest.mark.parametrize("search_path", ["", "relative/bin", "relative/bin:/usr/bin"])
def test_search_path_rejects_empty_or_relative_entries(search_path: str) -> None:
    with pytest.raises(ConfigurationError, match="non-empty absolute"):
        resolve_trusted_executable("runner", None, search_path=search_path)


def test_resolution_returns_verified_path_identity_and_digest() -> None:
    with _secure_tree() as root:
        executable = _executable(root / "bin")

        resolved, identity = resolve_trusted_executable(
            "runner",
            None,
            search_path=str(executable.parent),
        )

        assert resolved == executable.resolve()
        assert identity.source_chain[-1].path == executable
        assert identity.target_chain[-1].path == resolved
        assert identity.digest == sha256(executable.read_bytes()).hexdigest()
        assert recheck_trusted_executable(resolved, identity) is True


def test_explicit_path_must_be_absolute() -> None:
    with pytest.raises(ConfigurationError, match="must be absolute"):
        resolve_trusted_executable("runner", Path("relative/runner"))


@pytest.mark.parametrize("name", ["", ".", "..", "nested/runner", "runner\x00suffix"])
def test_executable_name_must_be_one_safe_path_component(name: str) -> None:
    with pytest.raises(ConfigurationError, match="name is invalid"):
        resolve_trusted_executable(name, None, search_path=str(Path.cwd()))


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode contract")
def test_writable_ancestor_is_rejected() -> None:
    with _secure_tree() as root:
        executable = _executable(root / "bin")
        executable.parent.chmod(0o720)
        try:
            with pytest.raises(ConfigurationError, match="unsafe ownership or mode"):
                resolve_trusted_executable("runner", executable)
        finally:
            executable.parent.chmod(0o700)


def test_source_symlink_retarget_fails_recheck() -> None:
    with _secure_tree() as root:
        first = _executable(root / "first", body="exit 0\n")
        second = _executable(root / "second", body="exit 1\n")
        links = root / "links"
        links.mkdir(mode=0o700)
        source = links / "runner"
        source.symlink_to(first)
        resolved, identity = resolve_trusted_executable("runner", source)

        source.unlink()
        source.symlink_to(second)

        assert recheck_trusted_executable(resolved, identity) is False


def test_inode_replacement_with_identical_content_fails_recheck() -> None:
    with _secure_tree() as root:
        executable = _executable(root / "bin")
        resolved, identity = resolve_trusted_executable("runner", executable)
        original = executable.read_bytes()
        executable.replace(executable.with_suffix(".old"))
        executable.write_bytes(original)
        executable.chmod(0o700)

        assert recheck_trusted_executable(resolved, identity) is False


def test_in_place_digest_drift_fails_recheck() -> None:
    with _secure_tree() as root:
        executable = _executable(root / "bin")
        resolved, identity = resolve_trusted_executable("runner", executable)
        executable.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
        executable.chmod(0o700)

        assert recheck_trusted_executable(resolved, identity) is False
