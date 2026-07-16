"""Working `verity` command-line surface for local operation and verification."""

from __future__ import annotations

import asyncio
import getpass
import http.client
import json
import os
from collections.abc import Coroutine
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Any

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from verity_cordon.codex import (
    DesktopDemoResult,
    IntegrationResult,
    doctor_codex,
    install_codex,
    setup_desktop_demo,
    status_desktop_demo,
    teardown_desktop_demo,
    uninstall_codex,
)
from verity_cordon.core.config import Settings, loopback_origin, validate_loopback_host
from verity_cordon.core.errors import ConfigurationError, VerityError
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.daemon.app import create_app
from verity_cordon.daemon.runtime import build_runtime
from verity_cordon.daemon.static import default_control_room_dist
from verity_cordon.demo import run_live_demo, run_offline_demo
from verity_cordon.policies.load import load_policy
from verity_cordon.semantic.readiness import semantic_provider_readiness

app = typer.Typer(
    name="verity",
    help="Verity Cordon — verifiable memory, revocable trust.",
    no_args_is_help=True,
)
ledger_app = typer.Typer(help="Initialize and verify the signed event ledger.")
memory_app = typer.Typer(help="Inspect, revoke, and rebuild durable memory.")
policy_app = typer.Typer(help="Validate, inspect, and activate local policies.")
demo_app = typer.Typer(help="Run synthetic offline or explicit live demonstrations.")
app.add_typer(ledger_app, name="ledger")
app.add_typer(memory_app, name="memory")
app.add_typer(policy_app, name="policy")
app.add_typer(demo_app, name="demo")
console = Console()
error_console = Console(stderr=True)
DESKTOP_DEMO_CONFIGURATION_SCOPE = "user_wide_codex_home"
DESKTOP_DEMO_OPERATOR_WARNING = (
    "Before confirmed setup or teardown, close every ChatGPT Desktop task, exit "
    "all Codex CLI TUI and IDE Codex sessions, and fully quit the ChatGPT desktop "
    "app. Tear down the user-wide demo fixture immediately after the rehearsal."
)


def _run[T](awaitable: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(awaitable)


def _safe_error(error: Exception) -> None:
    if isinstance(error, VerityError):
        error_console.print(f"[red]{error.code}:[/red] {error}")
    else:
        error_console.print("[red]unexpected_error:[/red] Operation failed safely.")


@app.command()
def doctor(
    confirm_hook_trust: Annotated[
        bool,
        typer.Option(
            "--confirm-hook-trust",
            help="Assert that you reviewed and trusted the installed Codex hook definition.",
        ),
    ] = False,
) -> None:
    """Check runtime, key, policy, daemon state, and ledger without printing secrets."""

    settings = Settings.from_env()
    settings.prepare()
    checks: list[tuple[str, str]] = []
    checks.append(("Python", "compatible"))
    checks.append(("Data directory", str(settings.data_dir)))
    checks.append(
        (
            "Database path",
            "writable" if os.access(settings.database_path.parent, os.W_OK) else "not writable",
        )
    )
    checks.append(("Signing key", "present" if settings.key_path.exists() else "missing"))
    checks.append(
        ("OpenAI key", "present" if bool(__import__("os").getenv("OPENAI_API_KEY")) else "absent")
    )
    ok = settings.key_path.exists() and os.access(settings.database_path.parent, os.W_OK)
    if ok:
        try:
            runtime = _run(build_runtime(settings))
            verification = _run(runtime.event_store.verify())
            checks.extend(
                [
                    (
                        "Policy",
                        f"{runtime.memory_service.policy_engine.policy.policy_id} "
                        f"{runtime.policy_validation_state}",
                    ),
                    ("Ledger", "verified" if verification.verified else "invalid"),
                    (
                        "Memory view",
                        "consistent" if verification.materialized_view_consistent else "stale",
                    ),
                ]
            )
            provider = _run(
                semantic_provider_readiness(
                    runtime.memory_service.semantic_adjudicator.provider_label,
                    runtime.subscription_runner,
                )
            )
            provider_status = (
                f"ready ({provider.isolation.value})"
                if provider.ready
                else f"not ready ({provider.failure_class})"
            )
            checks.append(("Semantic provider", provider_status))
            ok = ok and verification.verified
            ok = ok and verification.materialized_view_consistent
            ok = ok and runtime.policy_validation_state == "valid"
            ok = ok and provider.ready
        except Exception as error:
            _safe_error(error)
            checks.append(("Runtime", "unavailable"))
            ok = False
    try:
        codex = doctor_codex(operator_confirmed_hook_trust=confirm_hook_trust)
        checks.append(
            (
                "Codex integration",
                "ready" if codex.ready else ", ".join(codex.issues[:3]) or "not ready",
            )
        )
        ok = ok and codex.ready
    except Exception:
        checks.append(("Codex integration", "status unavailable"))
        ok = False

    control_room_dist = settings.control_room_dist or default_control_room_dist()
    control_room_built = (control_room_dist / "index.html").is_file()
    checks.append(("Control Room assets", "built" if control_room_built else "missing"))
    ok = ok and control_room_built
    daemon_reachable = False
    connection: http.client.HTTPConnection | None = None
    try:
        connection = http.client.HTTPConnection(settings.host, settings.port, timeout=0.5)
        connection.request(
            "GET",
            "/api/v1/health",
            headers={"Host": f"{settings.host}:{settings.port}"},
        )
        response = connection.getresponse()
        body = response.read(4097)
        daemon_reachable = response.status == 200 and len(body) <= 4096
    except (OSError, TimeoutError, http.client.HTTPException):
        daemon_reachable = False
    finally:
        if connection is not None:
            connection.close()
    checks.append(("Daemon", "reachable" if daemon_reachable else "not running"))
    ok = ok and daemon_reachable
    table = Table(title="Verity Cordon Doctor")
    table.add_column("Check")
    table.add_column("Result")
    for name, value in checks:
        table.add_row(name, value)
    console.print(table)
    if not ok:
        raise typer.Exit(1)


def _integration_json(result: IntegrationResult) -> dict[str, Any]:
    return {
        "operation": result.operation,
        "confirmed": result.confirmed,
        "applied": result.applied,
        "config_path": str(result.config_path),
        "backup_path": str(result.backup_path) if result.backup_path else None,
        "marketplace_root": str(result.marketplace_root),
        "changes": [
            {
                "dotted_key": change.dotted_key,
                "previous": change.previous,
                "previous_present": change.previous_present,
                "required": change.required,
            }
            for change in result.changes
        ],
        "commands": [list(command) for command in result.commands],
        "marketplace_registered": result.marketplace_registered,
        "plugin_installed": result.plugin_installed,
        "preview_digest": result.preview_digest,
        "artifacts": list(result.artifacts),
        "hook_manifest": result.hook_manifest,
        "hook_runtime": result.hook_runtime,
        "issues": list(result.issues),
        "operator_actions": list(result.operator_actions),
    }


def _desktop_demo_json(result: DesktopDemoResult) -> dict[str, Any]:
    return {
        "configuration_scope": DESKTOP_DEMO_CONFIGURATION_SCOPE,
        "operator_warning": DESKTOP_DEMO_OPERATOR_WARNING,
        "operation": result.operation,
        "confirmed": result.confirmed,
        "applied": result.applied,
        "state": result.state,
        "preview_digest": result.preview_digest,
        "config_path": str(result.config_path),
        "receipt_path": str(result.receipt_path),
        "staging_root": str(result.staging_root),
        "managed_entry": result.managed_entry,
        "artifacts": list(result.artifacts),
        "normal_integration_ready": result.normal_integration_ready,
        "issues": list(result.issues),
        "operator_actions": list(result.operator_actions),
    }


@app.command("install-codex")
def install_codex_command(
    source_root: Annotated[
        Path,
        typer.Option(help="Repository root containing the reviewed plugin manifests."),
    ] = Path("."),
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Apply the previewed Codex configuration changes."),
    ] = False,
    expected_preview_digest: Annotated[
        str | None,
        typer.Option(
            "--expected-preview-digest",
            help="Exact digest copied from a separate immutable install preview.",
        ),
    ] = None,
) -> None:
    """Preview or install the supported local Codex plugin and memory controls."""

    try:
        preview = install_codex(source_root.resolve(), confirmed=False)
        console.print_json(data={"preview": _integration_json(preview)})
        if not yes:
            console.print(
                "[yellow]Review the rendered hooks and artifact hashes, then rerun with "
                "--expected-preview-digest <digest> --yes.[/yellow]"
            )
            raise typer.Exit(2)
        if expected_preview_digest is None:
            console.print(
                "[yellow]Confirmed install requires --expected-preview-digest from a "
                "separate preview.[/yellow]"
            )
            raise typer.Exit(2)
        result = install_codex(
            source_root.resolve(),
            confirmed=True,
            expected_preview_digest=expected_preview_digest,
        )
        console.print_json(data={"result": _integration_json(result)})
        if result.issues:
            raise typer.Exit(1)
    except typer.Exit:
        raise
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@app.command("uninstall-codex")
def uninstall_codex_command(
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Remove the plugin and restore recorded config values."),
    ] = False,
) -> None:
    """Preview or remove Verity's Codex integration without overwriting config drift."""

    try:
        preview = uninstall_codex(confirmed=False)
        console.print_json(data={"preview": _integration_json(preview)})
        if not yes:
            console.print("[yellow]Review the preview, then rerun with --yes.[/yellow]")
            raise typer.Exit(2)
        result = uninstall_codex(confirmed=True)
        console.print_json(data={"result": _integration_json(result)})
        if result.issues or not result.applied:
            raise typer.Exit(1)
    except typer.Exit:
        raise
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@app.command()
def status() -> None:
    """Show privacy-safe local product status."""

    async def operation() -> dict[str, Any]:
        runtime = await build_runtime()
        verification = await runtime.event_store.verify()
        statistics = await runtime.queries.statistics()
        policy = runtime.memory_service.policy_engine.policy
        provider = await semantic_provider_readiness(
            runtime.memory_service.semantic_adjudicator.provider_label,
            runtime.subscription_runner,
        )
        return {
            "mode": policy.mode.value,
            "policy": f"{policy.policy_id}@{policy.version}",
            "ledger_verified": verification.verified,
            "view_consistent": verification.materialized_view_consistent,
            "semantic_provider": provider.provider.value,
            "semantic_provider_isolation": provider.isolation.value,
            "semantic_provider_ready": provider.ready,
            "semantic_provider_failure_class": provider.failure_class,
            "counts": statistics["counts"],
        }

    try:
        console.print_json(data=_run(operation()))
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@app.command()
def serve(
    host: Annotated[str | None, typer.Option(help="Loopback host override.")] = None,
    port: Annotated[int | None, typer.Option(help="Local port override.")] = None,
) -> None:
    """Start the loopback daemon and Memory Control Room."""

    try:
        settings = Settings.from_env()
        selected_host = validate_loopback_host(host or settings.host)
        selected_port = port or settings.port
        if not 1 <= selected_port <= 65535:
            raise ConfigurationError("The local port override is outside the valid range.")
        settings = replace(
            settings,
            host=selected_host,
            port=selected_port,
            control_room_origin=loopback_origin(selected_host, selected_port),
        )
        if settings.control_room_passphrase is None:
            entered = getpass.getpass("Control Room passphrase (12+ characters): ")
            settings.validate_control_room_passphrase(entered)
            settings = replace(settings, control_room_passphrase=entered)
        runtime = _run(build_runtime(settings))
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error
    uvicorn.run(
        create_app(runtime),
        host=settings.host,
        port=settings.port,
        log_level="info",
        access_log=False,
    )


@ledger_app.command("init-key")
def ledger_init_key() -> None:
    """Explicitly generate one restrictive local Ed25519 installation key."""

    settings = Settings.from_env()
    settings.prepare()
    try:
        provider = FileKeyProvider.generate(settings.key_path)
        console.print(f"Created Ed25519 installation key: [cyan]{provider.key_id}[/cyan]")
    except FileExistsError as error:
        error_console.print("[red]Key already exists; refusing to overwrite it.[/red]")
        raise typer.Exit(1) from error
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@ledger_app.command("verify")
def ledger_verify() -> None:
    """Verify event order, payloads, hashes, signatures, head, and memory view."""

    try:
        runtime = _run(build_runtime())
        result = _run(runtime.event_store.verify())
        console.print_json(data=result.model_dump(mode="json"))
        if not result.verified:
            raise typer.Exit(1)
    except typer.Exit:
        raise
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@ledger_app.command("export-public-key")
def ledger_export_public_key(
    output: Annotated[Path | None, typer.Option(help="Optional JSON output path.")] = None,
) -> None:
    """Export only the public Ed25519 verification material."""

    try:
        runtime = _run(build_runtime())
        exported = _run(runtime.key_provider.export_public())
        rendered = json.dumps(exported, indent=2, sort_keys=True) + "\n"
        if output is None:
            console.print(rendered, end="")
        else:
            output.write_text(rendered, encoding="utf-8")
            console.print(f"Wrote public verification material to {output}")
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@memory_app.command("list")
def memory_list() -> None:
    """List safe memory inventory records."""

    try:
        runtime = _run(build_runtime())
        items = _run(runtime.queries.list_memories())
        table = Table(title="Verity Memory Inventory")
        for heading in ("ID", "Status", "Namespace", "Kind", "Source"):
            table.add_column(heading)
        for item in items:
            table.add_row(
                item.memory_id,
                item.status,
                item.namespace,
                item.kind.value,
                item.source_class.value,
            )
        console.print(table)
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@memory_app.command("show")
def memory_show(memory_id: str) -> None:
    """Show one content-safe memory record."""

    try:
        runtime = _run(build_runtime())
        record = _run(runtime.queries.get_memory(memory_id))
        console.print_json(data=record.model_dump(mode="json"))
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@memory_app.command("revoke")
def memory_revoke(
    memory_id: str,
    reason: Annotated[str, typer.Option(prompt=True, help="Content-safe revocation reason.")],
    actor_id: Annotated[str, typer.Option()] = "operator.local",
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the revocation.")] = False,
) -> None:
    """Append one reasoned revocation event and verify the resulting view."""

    if not yes:
        console.print("[yellow]Revocation requires --yes after reviewing the target.[/yellow]")
        raise typer.Exit(2)
    try:
        runtime = _run(build_runtime())
        record = _run(
            runtime.trust_actions.revoke(
                memory_id,
                actor_id=actor_id,
                reason=reason,
                confirmed=True,
            )
        )
        console.print_json(data=record.model_dump(mode="json"))
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@memory_app.command("rescan")
def memory_rescan(
    memory_id: str,
    reason: Annotated[str, typer.Option(prompt=True, help="Content-safe rescan reason.")],
    actor_id: Annotated[str, typer.Option()] = "operator.local",
    yes: Annotated[bool, typer.Option("--yes", help="Confirm the retroactive rescan.")] = False,
) -> None:
    """Re-evaluate one active memory and atomically revoke an unsafe result."""

    if not yes:
        console.print("[yellow]Retroactive rescan requires --yes.[/yellow]")
        raise typer.Exit(2)
    try:
        runtime = _run(build_runtime())
        result = _run(
            runtime.rescan.rescan(
                memory_id,
                actor_id=actor_id,
                reason=reason,
                confirmed=True,
            )
        )
        console.print_json(data=result.model_dump(mode="json"))
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@memory_app.command("rebuild")
def memory_rebuild(
    dry_run: Annotated[bool, typer.Option(help="Compare without replacing projections.")] = False,
) -> None:
    """Replay signed events and compare or rebuild the memory view."""

    try:
        runtime = _run(build_runtime())
        console.print_json(data=_run(runtime.memory_view.rebuild(dry_run=dry_run)))
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@policy_app.command("validate")
def policy_validate(path: Path) -> None:
    """Validate a local YAML or JSON policy and print its canonical digest."""

    try:
        policy = load_policy(path)
        console.print_json(
            data={
                "valid": True,
                "policy_id": policy.policy_id,
                "version": policy.version,
                "digest": policy.content_digest,
            }
        )
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@policy_app.command("show")
def policy_show() -> None:
    """Show the active validated local policy."""

    try:
        runtime = _run(build_runtime())
        policy = runtime.memory_service.policy_engine.policy
        console.print_json(data=policy.model_dump(mode="json"))
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@policy_app.command("activate")
def policy_activate(
    path: Path,
    actor_id: Annotated[str, typer.Option()] = "operator.local",
    reason: Annotated[
        str,
        typer.Option(prompt=True, help="Content-safe policy activation reason."),
    ] = "Local policy activation.",
    yes: Annotated[bool, typer.Option("--yes", help="Confirm policy activation.")] = False,
) -> None:
    """Activate a validated local policy and append PolicyActivated."""

    if not yes:
        console.print("[yellow]Policy activation requires --yes.[/yellow]")
        raise typer.Exit(2)
    try:
        policy = load_policy(path)
        runtime = _run(build_runtime())
        activated = _run(
            runtime.policy_repository.activate(
                policy,
                actor_id=actor_id,
                reason=reason,
            )
        )
        console.print_json(
            data={
                "policy_id": activated.policy_id,
                "version": activated.version,
                "digest": activated.content_digest,
                "mode": activated.mode.value,
            }
        )
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


def _desktop_demo_paths() -> tuple[Path, Path]:
    settings = Settings.from_env()
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
    return codex_home, settings.data_dir.expanduser()


@demo_app.command("desktop-setup")
def demo_desktop_setup(
    source_root: Annotated[
        Path,
        typer.Option(help="Repository root containing the reviewed synthetic fixture."),
    ] = Path("."),
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Apply the exact previewed demo-only MCP entry."),
    ] = False,
    expected_preview_digest: Annotated[
        str | None,
        typer.Option(
            "--expected-preview-digest",
            help="SHA-256 digest copied from the separately reviewed preview.",
        ),
    ] = None,
    confirm_hook_trust: Annotated[
        bool,
        typer.Option(
            "--confirm-hook-trust",
            help="Assert that the normal Verity hook definition was reviewed and trusted.",
        ),
    ] = False,
) -> None:
    """Preview or install the reversible synthetic Codex Desktop fixture."""

    try:
        if yes and expected_preview_digest is None:
            console.print(
                "[yellow]Desktop setup with --yes requires "
                "--expected-preview-digest from a separate preview.[/yellow]"
            )
            raise typer.Exit(2)
        codex_home, data_dir = _desktop_demo_paths()
        preview = setup_desktop_demo(
            source_root.resolve(),
            confirmed=False,
            codex_home=codex_home,
            data_dir=data_dir,
            operator_confirmed_hook_trust=confirm_hook_trust,
        )
        console.print_json(data={"preview": _desktop_demo_json(preview)})
        if not yes:
            console.print("[yellow]Review the preview, then rerun with --yes.[/yellow]")
            raise typer.Exit(2)
        result = setup_desktop_demo(
            source_root.resolve(),
            confirmed=True,
            expected_preview_digest=expected_preview_digest,
            codex_home=codex_home,
            data_dir=data_dir,
            operator_confirmed_hook_trust=confirm_hook_trust,
        )
        console.print_json(data={"result": _desktop_demo_json(result)})
        if result.issues or not result.applied:
            raise typer.Exit(1)
    except typer.Exit:
        raise
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@demo_app.command("desktop-status")
def demo_desktop_status(
    source_root: Annotated[
        Path,
        typer.Option(help="Repository root containing the reviewed synthetic fixture."),
    ] = Path("."),
    confirm_hook_trust: Annotated[
        bool,
        typer.Option(
            "--confirm-hook-trust",
            help="Assert that the normal Verity hook definition was reviewed and trusted.",
        ),
    ] = False,
) -> None:
    """Check receipt, config, artifacts, runtimes, and bounded fixture readiness."""

    try:
        codex_home, data_dir = _desktop_demo_paths()
        settings = Settings.from_env()
        report = status_desktop_demo(
            source_root.resolve(),
            codex_home=codex_home,
            data_dir=data_dir,
            operator_confirmed_hook_trust=confirm_hook_trust,
            daemon_host=settings.host,
            daemon_port=settings.port,
        )
        console.print_json(
            data={
                "configuration_scope": DESKTOP_DEMO_CONFIGURATION_SCOPE,
                "operator_warning": DESKTOP_DEMO_OPERATOR_WARNING,
                "ready": report.ready,
                "fixture_ready": report.fixture_ready,
                "system_ready": report.system_ready,
                "state": report.state,
                "receipt_valid": report.receipt_valid,
                "managed_entry_intact": report.managed_entry_intact,
                "artifacts_intact": report.artifacts_intact,
                "runtimes_intact": report.runtimes_intact,
                "normal_integration_ready": report.normal_integration_ready,
                "fixture_probe_ready": report.fixture_probe_ready,
                "daemon_ready": report.daemon_ready,
                "ledger_verified": report.ledger_verified,
                "policy_valid": report.policy_valid,
                "memory_view_consistent": report.memory_view_consistent,
                "control_room_ready": report.control_room_ready,
                "control_room_headers_ready": report.control_room_headers_ready,
                "issues": list(report.issues),
            }
        )
        if not report.ready:
            raise typer.Exit(1)
    except typer.Exit:
        raise
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@demo_app.command("desktop-teardown")
def demo_desktop_teardown(
    source_root: Annotated[
        Path,
        typer.Option(help="Repository root used for the Desktop demonstration."),
    ] = Path("."),
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Remove only the exact receipt-bound demo entry."),
    ] = False,
    expected_preview_digest: Annotated[
        str | None,
        typer.Option(
            "--expected-preview-digest",
            help="SHA-256 digest copied from the separately reviewed teardown preview.",
        ),
    ] = None,
    confirm_hook_trust: Annotated[
        bool,
        typer.Option(
            "--confirm-hook-trust",
            help="Assert that the normal Verity hook definition was reviewed and trusted.",
        ),
    ] = False,
) -> None:
    """Preview or remove the demo fixture without uninstalling Verity."""

    try:
        if yes and expected_preview_digest is None:
            console.print(
                "[yellow]Desktop teardown with --yes requires "
                "--expected-preview-digest from a separate preview.[/yellow]"
            )
            raise typer.Exit(2)
        codex_home, data_dir = _desktop_demo_paths()
        preview = teardown_desktop_demo(
            source_root.resolve(),
            confirmed=False,
            codex_home=codex_home,
            data_dir=data_dir,
            operator_confirmed_hook_trust=confirm_hook_trust,
        )
        console.print_json(data={"preview": _desktop_demo_json(preview)})
        if not yes:
            console.print("[yellow]Review the preview, then rerun with --yes.[/yellow]")
            raise typer.Exit(2)
        result = teardown_desktop_demo(
            source_root.resolve(),
            confirmed=True,
            expected_preview_digest=expected_preview_digest,
            codex_home=codex_home,
            data_dir=data_dir,
            operator_confirmed_hook_trust=confirm_hook_trust,
        )
        console.print_json(data={"result": _desktop_demo_json(result)})
        if result.issues or not result.applied:
            raise typer.Exit(1)
    except typer.Exit:
        raise
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@demo_app.command("offline")
def demo_offline(
    serve_control_room: Annotated[
        bool,
        typer.Option("--serve/--no-serve", help="Start the local Control Room after seeding."),
    ] = False,
) -> None:
    """Run attack, shadow, enforcement, revocation, and verification without an API key."""

    try:
        run = _run(run_offline_demo())
        console.print_json(data=run.summary)
        if serve_control_room:
            settings = run.runtime.settings
            if settings.control_room_passphrase is None:
                entered = getpass.getpass("Control Room passphrase (12+ characters): ")
                settings.validate_control_room_passphrase(entered)
                settings = replace(settings, control_room_passphrase=entered)
                run.runtime.settings = settings
            uvicorn.run(
                create_app(run.runtime),
                host=settings.host,
                port=settings.port,
                access_log=False,
            )
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


@demo_app.command("live")
def demo_live(
    serve_control_room: Annotated[
        bool,
        typer.Option("--serve/--no-serve", help="Start the local Control Room after seeding."),
    ] = False,
) -> None:
    """Run the synthetic attack through explicit live GPT-5.6 structured assessment."""

    try:
        run = _run(run_live_demo())
        console.print_json(data=run.summary)
        if serve_control_room:
            uvicorn.run(
                create_app(run.runtime),
                host=run.runtime.settings.host,
                port=run.runtime.settings.port,
                access_log=False,
            )
    except Exception as error:
        _safe_error(error)
        raise typer.Exit(1) from error


if __name__ == "__main__":
    app()
