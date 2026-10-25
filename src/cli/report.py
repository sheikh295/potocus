"""``potocus report`` — generate deliverables from findings.db."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from src.reporting.generator import generate_report, list_templates
from src.utils.config import get_active_workspace_path
from src.workspace.manager import WorkspaceError, load_workspace

app = typer.Typer(help="Generate engagement reports from structured findings.")
console = Console()


def _require_workspace():
    """Load active workspace or exit."""
    active = get_active_workspace_path()
    if active is None:
        console.print("[yellow]No active workspace.[/yellow]")
        raise typer.Exit(code=1)
    try:
        return load_workspace(active)
    except WorkspaceError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc


@app.command("templates")
def report_templates() -> None:
    """List available report templates."""
    names = list_templates()
    for name in names:
        console.print(f"- {name}")


@app.command("generate")
def report_generate(
    format: str = typer.Option(  # noqa: A002
        "md",
        "--format",
        help="md | pdf | docx",
    ),
    template: str = typer.Option(
        "pentest",
        "--template",
        help="pentest | bug_bounty | research",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        help="Override workspace output_dir for this run.",
    ),
) -> None:
    """
    Compile findings.db (+ session metas) into a report under the workspace output dir.
    """
    if format not in ("md", "pdf", "docx"):
        console.print(f"[red]Unsupported format:[/red] {format}")
        raise typer.Exit(code=1)
    if template not in ("pentest", "bug_bounty", "research"):
        console.print(
            f"[red]Unknown template:[/red] {template}. "
            f"Available: {', '.join(list_templates())}"
        )
        raise typer.Exit(code=1)

    workspace = _require_workspace()
    try:
        with console.status("[dim]generating report…[/dim]", spinner="dots"):
            result = generate_report(
                workspace,
                fmt=format,  # type: ignore[arg-type]
                template=template,  # type: ignore[arg-type]
                output_dir=output_dir,
            )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Report failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        Panel.fit(
            f"[green]Wrote[/green] {result.path}\n"
            f"format: {result.format}\n"
            f"template: {result.template}\n"
            f"chars: {len(result.markdown)}",
            title="Report",
            border_style="green",
        )
    )
