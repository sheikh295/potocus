"""``potocus scope`` — allowlist management and ScopeGuard checks."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.utils.config import get_active_workspace_path
from src.utils.logger import setup_workspace_logger
from src.workspace.manager import WorkspaceError, load_workspace
from src.workspace.scope_guard import ScopeGuard

app = typer.Typer(help="Define and edit scope; check commands against the allowlist.")
console = Console()


def _require_workspace():
    """Load the active workspace or exit."""
    active = get_active_workspace_path()
    if active is None:
        console.print("[yellow]No active workspace.[/yellow]")
        raise typer.Exit(code=1)
    try:
        return load_workspace(active)
    except WorkspaceError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc


def _require_scoped_workspace():
    """Load active workspace and ensure it is scoped with a scope.yaml."""
    workspace = _require_workspace()
    if workspace.mode != "scoped":
        console.print(
            f"[yellow]Workspace is unscoped[/yellow] ({workspace.root}). "
            "Scope allowlist commands only apply in scoped mode."
        )
        raise typer.Exit(code=1)
    return workspace


def _load_scope(path) -> dict:
    """Read scope.yaml."""
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        data = {"targets": []}
    data.setdefault("targets", [])
    return data


def _save_scope(path, data: dict) -> None:
    """Write scope.yaml."""
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, default_flow_style=False, sort_keys=False)


@app.command("list")
def scope_list(
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """List allowlisted targets for the active scoped workspace."""
    workspace = _require_scoped_workspace()
    data = _load_scope(workspace.scope_yaml)
    targets = data.get("targets") or []

    if json_out:
        console.print_json(data={"targets": targets})
        return

    if not targets:
        console.print("[yellow]No targets in scope yet. Use `potocus scope add`.[/yellow]")
        return

    table = Table(title=f"Scope — {workspace.name}")
    table.add_column("#", style="dim")
    table.add_column("Target")
    table.add_column("Note")
    for idx, entry in enumerate(targets, start=1):
        if isinstance(entry, dict):
            table.add_row(str(idx), str(entry.get("target", "")), str(entry.get("note", "")))
        else:
            table.add_row(str(idx), str(entry), "")
    console.print(table)


@app.command("add")
def scope_add(
    target: str = typer.Argument(..., help="CIDR, domain, or wildcard domain."),
    note: Optional[str] = typer.Option(None, "--note", help="Optional ROE note."),
) -> None:
    """Add a target to the workspace allowlist."""
    workspace = _require_scoped_workspace()
    data = _load_scope(workspace.scope_yaml)
    targets = data.setdefault("targets", [])
    entry = {
        "target": target,
        "note": note or "",
        "added_at": datetime.now(timezone.utc).isoformat(),
    }
    targets.append(entry)
    _save_scope(workspace.scope_yaml, data)
    logger = setup_workspace_logger(workspace.root)
    logger.info("scope add target=%s note=%s", target, note or "")
    console.print(f"[green]Added to scope:[/green] {target}")


@app.command("remove")
def scope_remove(
    target: str = typer.Argument(..., help="Exact target string to remove."),
) -> None:
    """Remove a target from the workspace allowlist."""
    workspace = _require_scoped_workspace()
    data = _load_scope(workspace.scope_yaml)
    targets = data.get("targets") or []
    new_targets = []
    removed = False
    for entry in targets:
        value = entry.get("target") if isinstance(entry, dict) else entry
        if str(value) == target and not removed:
            removed = True
            continue
        new_targets.append(entry)
    if not removed:
        console.print(f"[yellow]Target not found:[/yellow] {target}")
        raise typer.Exit(code=1)
    data["targets"] = new_targets
    _save_scope(workspace.scope_yaml, data)
    logger = setup_workspace_logger(workspace.root)
    logger.info("scope remove target=%s", target)
    console.print(f"[green]Removed from scope:[/green] {target}")


@app.command(
    "check",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def scope_check(ctx: typer.Context) -> None:
    """
    Run ScopeGuard against a command (does not execute it).

    Example: ``potocus scope check -- nmap -sn 10.10.20.5``
    """
    command = list(ctx.args)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        console.print("[red]Provide a command after `--`.[/red]")
        console.print("Example: potocus scope check -- nmap -sn 10.10.20.5")
        raise typer.Exit(code=1)

    workspace = _require_workspace()
    guard = ScopeGuard.from_workspace(
        mode=workspace.mode,
        scope_yaml=workspace.scope_yaml if workspace.mode == "scoped" else None,
    )
    result = guard.check_command(command)
    color = "green" if result.decision == "allow" else "red"
    console.print(
        Panel.fit(
            f"[{color}]{result.decision.upper()}[/{color}]\n"
            f"{result.reason}\n\n"
            f"command: {' '.join(command)}\n"
            f"targets: {', '.join(result.targets) or '(none)'}\n"
            f"blocked: {', '.join(result.blocked) or '(none)'}",
            title="ScopeGuard",
            border_style=color,
        )
    )
    logger = setup_workspace_logger(workspace.root)
    logger.info(
        "scope check decision=%s targets=%s blocked=%s cmd=%s",
        result.decision,
        result.targets,
        result.blocked,
        command,
    )
    if result.decision == "block":
        raise typer.Exit(code=2)
