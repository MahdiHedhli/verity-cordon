"""Working `verity` command-line surface for local operation and verification."""

from __future__ import annotations

import asyncio
import getpass
import json
from collections.abc import Coroutine
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Any

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from verity_cordon.core.config import Settings
from verity_cordon.core.errors import VerityError
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.daemon.app import create_app
from verity_cordon.daemon.runtime import build_runtime
from verity_cordon.policies.load import load_policy

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


def _run[T](awaitable: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(awaitable)


def _safe_error(error: Exception) -> None:
    if isinstance(error, VerityError):
        error_console.print(f"[red]{error.code}:[/red] {error}")
    else:
        error_console.print("[red]unexpected_error:[/red] Operation failed safely.")


@app.command()
def doctor() -> None:
    """Check runtime, key, policy, daemon state, and ledger without printing secrets."""

    settings = Settings.from_env()
    checks: list[tuple[str, str]] = []
    checks.append(("Python", "compatible"))
    checks.append(("Data directory", str(settings.data_dir)))
    checks.append(("Signing key", "present" if settings.key_path.exists() else "missing"))
    checks.append(
        ("OpenAI key", "present" if bool(__import__("os").getenv("OPENAI_API_KEY")) else "absent")
    )
    ok = settings.key_path.exists()
    if ok:
        try:
            runtime = _run(build_runtime(settings))
            verification = _run(runtime.event_store.verify())
            checks.extend(
                [
                    ("Policy", f"{runtime.memory_service.policy_engine.policy.policy_id} valid"),
                    ("Ledger", "verified" if verification.verified else "invalid"),
                    (
                        "Memory view",
                        "consistent" if verification.materialized_view_consistent else "stale",
                    ),
                    ("Codex integration", "run 'verity install-codex' to configure"),
                    ("Control Room", f"http://{settings.host}:{settings.port}"),
                ]
            )
            ok = verification.verified
        except Exception as error:
            _safe_error(error)
            checks.append(("Runtime", "unavailable"))
            ok = False
    table = Table(title="Verity Cordon Doctor")
    table.add_column("Check")
    table.add_column("Result")
    for name, value in checks:
        table.add_row(name, value)
    console.print(table)
    if not ok:
        raise typer.Exit(1)


@app.command()
def status() -> None:
    """Show privacy-safe local product status."""

    async def operation() -> dict[str, Any]:
        runtime = await build_runtime()
        verification = await runtime.event_store.verify()
        statistics = await runtime.queries.statistics()
        policy = runtime.memory_service.policy_engine.policy
        return {
            "mode": policy.mode.value,
            "policy": f"{policy.policy_id}@{policy.version}",
            "ledger_verified": verification.verified,
            "view_consistent": verification.materialized_view_consistent,
            "semantic_provider": runtime.memory_service.semantic_adjudicator.provider_label,
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

    settings = Settings.from_env()
    if host is not None:
        settings = replace(
            settings,
            host=host,
            control_room_origin=f"http://{host}:{port or settings.port}",
        )
    if port is not None:
        settings = replace(
            settings,
            port=port,
            control_room_origin=f"http://{host or settings.host}:{port}",
        )
    if settings.control_room_passphrase is None:
        entered = getpass.getpass("Control Room passphrase (12+ characters): ")
        settings.validate_control_room_passphrase(entered)
        settings = replace(settings, control_room_passphrase=entered)
    try:
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
    yes: Annotated[bool, typer.Option("--yes", help="Confirm policy activation.")] = False,
) -> None:
    """Activate a validated local policy and append PolicyActivated."""

    if not yes:
        console.print("[yellow]Policy activation requires --yes.[/yellow]")
        raise typer.Exit(2)
    try:
        policy = load_policy(path)
        runtime = _run(build_runtime())
        activated = _run(runtime.policy_repository.activate(policy, actor_id=actor_id))
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


if __name__ == "__main__":
    app()
