"""``potocus workspace`` command group."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from src.utils.config import get_active_workspace_path, set_active_workspace
from src.workspace.manager import (
    WorkspaceError,
    init_workspace,
    load_workspace,
    set_workspace_mode,
)

app = typer.Typer(help="Create, list, switch, and configure workspaces.")
console = Console()


@app.command("init")
def workspace_init(
    path: Path = typer.Argument(..., help="Directory to bind as the workspace root."),
    mode: str = typer.Option(
        "scoped",
        "--mode",
        help="scoped (engagements) or unscoped (labs/learning).",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        help="Where generated reports are written (default: ./reports).",
    ),
    pacing: str = typer.Option(
        "normal",
        "--pacing",
        help="stealth | normal | aggressive",
    ),
    name: Optional[str] = typer.Option(None, "--name", help="Display name (default: dir name)."),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Initialize a new workspace and set it active."""
    if mode not in ("scoped", "unscoped"):
        console.print(f"[red]Invalid mode:[/red] {mode}")
        raise typer.Exit(code=1)
    if pacing not in ("stealth", "normal", "aggressive"):
        console.print(f"[red]Invalid pacing:[/red] {pacing}")
        raise typer.Exit(code=1)

    try:
        workspace = init_workspace(
            path,
            mode=mode,  # type: ignore[arg-type]
            output_dir=output_dir,
            pacing=pacing,  # type: ignore[arg-type]
            name=name,
            activate=True,
        )
    except WorkspaceError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    if json_out:
        console.print_json(
            data={
                "name": workspace.name,
                "root": str(workspace.root),
                "mode": workspace.mode,
                "output_dir": str(workspace.output_dir),
                "pacing": workspace.pacing,
            }
        )
        return

    console.print(
        f"[green]Initialized workspace[/green] [bold]{workspace.name}[/bold]\n"
        f"  root:   {workspace.root}\n"
        f"  mode:   {workspace.mode}\n"
        f"  pacing: {workspace.pacing}\n"
        f"  output: {workspace.output_dir}"
    )
    if workspace.mode == "scoped":
        console.print(
            "[yellow]Scoped mode:[/yellow] add targets with "
            "`potocus scope add` before engaging."
        )


@app.command("switch")
def workspace_switch(
    path: Path = typer.Argument(..., help="Existing workspace directory."),
) -> None:
    """Switch the active workspace."""
    try:
        workspace = load_workspace(path)
    except WorkspaceError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    set_active_workspace(workspace.root)
    console.print(
        f"[green]Active workspace:[/green] {workspace.name} ({workspace.root}) "
        f"[{workspace.mode}]"
    )


@app.command("show")
def workspace_show(
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Show the active workspace."""
    active = get_active_workspace_path()
    if active is None:
        console.print("[yellow]No active workspace. Run `potocus workspace init` or `switch`.[/yellow]")
        raise typer.Exit(code=1)
    try:
        workspace = load_workspace(active)
    except WorkspaceError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    if json_out:
        console.print_json(
            data={
                "name": workspace.name,
                "root": str(workspace.root),
                "mode": workspace.mode,
                "output_dir": str(workspace.output_dir),
                "pacing": workspace.pacing,
                "models": workspace.models,
                "created_at": workspace.created_at,
            }
        )
        return

    table = Table(title="Active Workspace")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("name", workspace.name)
    table.add_row("root", str(workspace.root))
    table.add_row("mode", workspace.mode)
    table.add_row("pacing", workspace.pacing)
    table.add_row("output_dir", str(workspace.output_dir))
    table.add_row("model", workspace.models.get("primary", ""))
    table.add_row("created_at", workspace.created_at)
    console.print(table)


@app.command("set-mode")
def workspace_set_mode(
    mode: str = typer.Argument(..., help="scoped | unscoped"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Confirm the mode change."),
) -> None:
    """Change workspace mode (requires confirmation)."""
    if mode not in ("scoped", "unscoped"):
        console.print(f"[red]Invalid mode:[/red] {mode}")
        raise typer.Exit(code=1)

    active = get_active_workspace_path()
    if active is None:
        console.print("[yellow]No active workspace.[/yellow]")
        raise typer.Exit(code=1)

    try:
        workspace = load_workspace(active)
        if not yes:
            console.print(
                f"[yellow]This will change mode from {workspace.mode} → {mode}.[/yellow]\n"
                "Re-run with --yes to confirm."
            )
            raise typer.Exit(code=1)
        updated = set_workspace_mode(workspace, mode, confirm=True)  # type: ignore[arg-type]
    except WorkspaceError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]Mode set to[/green] {updated.mode}")


@app.command("set-pacing")
def workspace_set_pacing(
    pacing: str = typer.Argument(..., help="stealth | normal | aggressive"),
) -> None:
    """Set the workspace default pacing profile (sessions may override)."""
    if pacing not in ("stealth", "normal", "aggressive"):
        console.print("[red]Invalid pacing.[/red] Use stealth | normal | aggressive")
        raise typer.Exit(code=1)

    active = get_active_workspace_path()
    if active is None:
        console.print("[yellow]No active workspace.[/yellow]")
        raise typer.Exit(code=1)

    try:
        workspace = load_workspace(active)
        from src.workspace.manager import save_workspace_config

        updated = save_workspace_config(workspace, {"pacing": pacing})
    except WorkspaceError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[green]Workspace pacing:[/green] {updated.pacing} "
        "(session overrides via `potocus session set-pacing` still win)"
    )
