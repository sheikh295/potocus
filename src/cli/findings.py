"""``potocus findings`` — inspect the workspace findings database."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from src.memory.findings_db import FindingsDB
from src.utils.config import get_active_workspace_path
from src.workspace.manager import WorkspaceError, load_workspace

app = typer.Typer(help="List and search structured findings for the active workspace.")
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


@app.command("summary")
def findings_summary() -> None:
    """Show host/service/finding counts."""
    workspace = _require_workspace()
    db = FindingsDB(workspace.findings_db)
    try:
        summary = db.summary()
    finally:
        db.close()
    console.print(
        f"[bold]{workspace.name}[/bold] findings.db — "
        f"hosts={summary['hosts']} services={summary['services']} "
        f"findings={summary['findings']}"
    )


@app.command("hosts")
def findings_hosts(
    json_out: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """List discovered hosts."""
    workspace = _require_workspace()
    db = FindingsDB(workspace.findings_db)
    try:
        hosts = db.list_hosts()
    finally:
        db.close()
    if json_out:
        console.print_json(
            data=[
                {
                    "id": h.id,
                    "address": h.address,
                    "hostname": h.hostname,
                    "os_guess": h.os_guess,
                    "last_seen": h.last_seen,
                }
                for h in hosts
            ]
        )
        return
    if not hosts:
        console.print("[yellow]No hosts recorded yet.[/yellow]")
        return
    table = Table(title=f"Hosts — {workspace.name}")
    table.add_column("ID")
    table.add_column("Address")
    table.add_column("Hostname")
    table.add_column("OS")
    table.add_column("Last seen")
    for host in hosts:
        table.add_row(
            str(host.id),
            host.address,
            host.hostname or "",
            host.os_guess or "",
            host.last_seen,
        )
    console.print(table)


@app.command("services")
def findings_services(
    host_id: int | None = typer.Option(None, "--host-id", help="Filter by host id."),
) -> None:
    """List discovered services/ports."""
    workspace = _require_workspace()
    db = FindingsDB(workspace.findings_db)
    try:
        services = db.list_services(host_id=host_id)
    finally:
        db.close()
    if not services:
        console.print("[yellow]No services recorded yet.[/yellow]")
        return
    table = Table(title=f"Services — {workspace.name}")
    table.add_column("ID")
    table.add_column("Host")
    table.add_column("Port")
    table.add_column("Proto")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Product/Version")
    for svc in services:
        table.add_row(
            str(svc.id),
            str(svc.host_id),
            str(svc.port),
            svc.protocol,
            svc.state,
            svc.service_name or "",
            " ".join(p for p in (svc.product, svc.version) if p),
        )
    console.print(table)


@app.command("list")
def findings_list(
    kind: str | None = typer.Option(None, "--kind", help="Filter kind."),
    severity: str | None = typer.Option(None, "--severity", help="Filter severity."),
    limit: int = typer.Option(50, "--limit", help="Max rows."),
) -> None:
    """List structured findings (paths, vulns, service notes, …)."""
    workspace = _require_workspace()
    db = FindingsDB(workspace.findings_db)
    try:
        rows = db.list_findings(kind=kind, severity=severity, limit=limit)
    finally:
        db.close()
    if not rows:
        console.print("[yellow]No findings recorded yet.[/yellow]")
        return
    table = Table(title=f"Findings — {workspace.name}")
    table.add_column("ID")
    table.add_column("Kind")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Tool")
    table.add_column("Created")
    for row in rows:
        table.add_row(
            str(row.id),
            row.kind,
            row.severity,
            row.title[:80],
            row.source_tool or "",
            row.created_at,
        )
    console.print(table)


@app.command("search")
def findings_search(
    query: str = typer.Argument(..., help="Keyword / host / service search."),
    limit: int = typer.Option(20, "--limit"),
) -> None:
    """Search hosts, services, and findings in this workspace."""
    workspace = _require_workspace()
    db = FindingsDB(workspace.findings_db)
    try:
        hits = db.search(query, limit=limit)
    finally:
        db.close()
    if not hits:
        console.print(f"[yellow]No matches for[/yellow] {query!r}")
        raise typer.Exit(code=1)
    for hit in hits:
        console.print(hit)


@app.command("set-severity")
def findings_set_severity(
    finding_id: int = typer.Argument(..., help="Finding id from `findings list`."),
    severity: str = typer.Option(
        ...,
        "--severity",
        help="info | low | medium | high | critical",
    ),
    cvss: float | None = typer.Option(None, "--cvss", help="Optional CVSS score."),
) -> None:
    """Set severity/CVSS on a finding (used by report scoring)."""
    allowed = {"info", "low", "medium", "high", "critical", "unknown"}
    if severity not in allowed:
        console.print(f"[red]Invalid severity.[/red] Choose from {sorted(allowed)}")
        raise typer.Exit(code=1)
    workspace = _require_workspace()
    db = FindingsDB(workspace.findings_db)
    try:
        ok = db.update_finding_severity(finding_id, severity=severity, cvss=cvss)
    finally:
        db.close()
    if not ok:
        console.print(f"[red]Finding not found:[/red] {finding_id}")
        raise typer.Exit(code=1)
    console.print(
        f"[green]Updated finding[/green] {finding_id} → severity={severity}"
        + (f" cvss={cvss}" if cvss is not None else "")
    )
