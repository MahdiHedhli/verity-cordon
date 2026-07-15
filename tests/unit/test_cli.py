"""CLI boundary tests that must fail before any network service starts."""

from __future__ import annotations

from typer.testing import CliRunner

from verity_cordon.cli.main import app


def test_serve_rejects_non_loopback_host_override() -> None:
    result = CliRunner().invoke(app, ["serve", "--host", "0.0.0.0"])  # noqa: S104

    assert result.exit_code == 1
    assert "non-loopback" in result.output


def test_serve_rejects_invalid_port_override() -> None:
    result = CliRunner().invoke(app, ["serve", "--port", "70000"])

    assert result.exit_code == 1
    assert "valid range" in result.output


def test_memory_rescan_requires_explicit_confirmation() -> None:
    result = CliRunner().invoke(
        app,
        [
            "memory",
            "rescan",
            "019bffff-ffff-7fff-bfff-ffffffffffff",
            "--reason",
            "Routine policy review.",
        ],
    )

    assert result.exit_code == 2
    assert "requires --yes" in result.output
