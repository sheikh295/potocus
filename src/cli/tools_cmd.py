"""``potocus tools`` — index and search Kali tool manuals."""

from __future__ import annotations

import platform

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.memory.vectorstore import WorkspaceVectorStore
from src.tools.discovery import (
    TOOL_NAME,
    collect_manuals,
    index_tools,
    search_kali_tools,
    seed_dir,
)
from src.utils.config import get_active_workspace_path
from src.workspace.manager import WorkspaceError, load_workspace

app = typer.Typer(help="Index and search Kali tool manuals (workspace-scoped).")
console = Console()


def _require_workspace():
    """Load the active workspace or exit."""
    active = get_active_workspace_path()
    if active is None:
        console.print("[yellow]No active workspace. Run `potocus workspace init` first.[/yellow]")
        raise typer.Exit(code=1)
    try:
        return load_workspace(active)
    except WorkspaceError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc


@app.command("index")
def tools_index(
    reset: bool = typer.Option(
        False,
        "--reset",
        help="Drop and rebuild the kali_tools collection.",
    ),
    live_only: bool = typer.Option(
        False,
        "--live-only",
        help="Only index binaries found on PATH (use on Kali for full fidelity).",
    ),
) -> None:
    """
    Index tool manuals into this workspace's ChromaDB.

    On Mac/dev: live help for installed tools + shipped seed manuals for the rest.
    On Kali: prefer ``--live-only --reset`` after a full tool install.
    """
    workspace = _require_workspace()
    store = WorkspaceVectorStore(workspace.vectorstore_dir)
    console.print(
        f"[dim]platform={platform.platform()} seed_dir={seed_dir()} "
        f"vectorstore={workspace.vectorstore_dir}[/dim]"
    )
    with console.status("[dim]indexing tool manuals…[/dim]", spinner="dots"):
        manuals = collect_manuals(include_seed_fallback=not live_only)
        report = index_tools(
            store,
            manuals=manuals,
            reset=reset,
            include_seed_fallback=not live_only,
        )

    table = Table(title="Tool index report")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("platform", report.platform)
    table.add_row("live (--help captured)", str(report.live_count))
    table.add_row("seed (shipped manuals)", str(report.seed_count))
    table.add_row("skipped (no live/seed)", str(report.skipped))
    table.add_row("upserted", str(report.total_upserted))
    table.add_row("collection size", str(report.collection_size))
    console.print(table)

    if report.live_count == 0 and report.seed_count > 0:
        console.print(
            "[yellow]No Kali binaries on PATH — indexed seed manuals for Mac/dev. "
            "On Kali, re-run: potocus tools index --reset --live-only[/yellow]"
        )
    elif report.total_upserted == 0:
        console.print("[red]Nothing indexed. Install tools or check data/kali_tools.[/red]")
        raise typer.Exit(code=1)
    else:
        console.print("[green]Tool manuals ready for search_kali_tools.[/green]")


@app.command("search")
def tools_search(
    query: str = typer.Argument(..., help="Natural-language tool query."),
    n: int = typer.Option(5, "--n", help="Number of results."),
) -> None:
    """Search indexed tool manuals in the active workspace."""
    workspace = _require_workspace()
    store = WorkspaceVectorStore(workspace.vectorstore_dir)
    if store.count(WorkspaceVectorStore.TOOLS_COLLECTION) == 0:
        console.print(
            "[yellow]Index is empty. Run `potocus tools index` first.[/yellow]"
        )
        raise typer.Exit(code=1)
    result = search_kali_tools(query, store=store, n_results=n)
    console.print(Panel(result, title=TOOL_NAME, border_style="cyan"))


@app.command("status")
def tools_status() -> None:
    """Show index size and environment hints."""
    workspace = _require_workspace()
    store = WorkspaceVectorStore(workspace.vectorstore_dir)
    count = store.count(WorkspaceVectorStore.TOOLS_COLLECTION)
    console.print(
        Panel.fit(
            f"workspace: {workspace.root}\n"
            f"vectorstore: {workspace.vectorstore_dir}\n"
            f"kali_tools docs: {count}\n"
            f"host: {platform.platform()}\n"
            f"seed_dir: {seed_dir()}",
            title="Tool discovery status",
            border_style="cyan",
        )
    )
