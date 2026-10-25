"""``potocus session`` — create, list, activate, rename, and close sessions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

import typer
import yaml
from rich.console import Console
from rich.table import Table

from src.utils.config import (
    get_active_session_id,
    get_active_workspace_path,
    set_active_session,
)
from src.workspace.manager import EngagementPhase, WorkspaceError, load_workspace

app = typer.Typer(help="Create, list, resume, rename, and close sessions.")
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


def _write_session_yaml(path, data: dict) -> None:
    """Write session.yaml."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, default_flow_style=False, sort_keys=False)


def _read_session_yaml(path) -> dict:
    """Read session.yaml."""
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data if isinstance(data, dict) else {}


@app.command("new")
def session_new(
    name: str = typer.Option(..., "--name", help="Human-readable session name."),
    phase: str = typer.Option(
        EngagementPhase.RECON.value,
        "--phase",
        help="Starting engagement phase.",
    ),
) -> None:
    """Create a new session in the active workspace and set it active."""
    workspace = _require_workspace()
    valid_phases = {p.value for p in EngagementPhase}
    if phase not in valid_phases:
        console.print(f"[red]Invalid phase:[/red] {phase}. Choose from {sorted(valid_phases)}")
        raise typer.Exit(code=1)

    session_id = uuid4().hex[:12]
    session_dir = workspace.sessions_dir / session_id
    (session_dir / "checkpoints").mkdir(parents=True, exist_ok=True)
    (session_dir / "raw_output").mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).isoformat()
    meta = {
        "id": session_id,
        "name": name,
        "created_at": now,
        "updated_at": now,
        "phase": phase,
        "target_focus": "",
        "status": "open",
    }
    _write_session_yaml(session_dir / "session.yaml", meta)
    set_active_session(session_id)
    console.print(
        f"[green]Created session[/green] [bold]{name}[/bold] ({session_id}) "
        f"phase={phase}"
    )


@app.command("list")
def session_list(
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """List sessions in the active workspace."""
    workspace = _require_workspace()
    active_id = get_active_session_id()
    rows = []
    for entry in sorted(workspace.sessions_dir.iterdir()):
        meta_path = entry / "session.yaml"
        if entry.is_dir() and meta_path.exists():
            meta = _read_session_yaml(meta_path)
            meta["id"] = entry.name
            meta["active"] = entry.name == active_id
            rows.append(meta)

    if json_out:
        console.print_json(data={"sessions": rows})
        return

    if not rows:
        console.print("[yellow]No sessions yet. Use `potocus session new --name ...`.[/yellow]")
        return

    table = Table(title=f"Sessions — {workspace.name}")
    table.add_column("Active")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Phase")
    table.add_column("Status")
    table.add_column("Updated")
    for row in rows:
        table.add_row(
            "*" if row.get("active") else "",
            str(row.get("id", "")),
            str(row.get("name", "")),
            str(row.get("phase", "")),
            str(row.get("status", "")),
            str(row.get("updated_at", "")),
        )
    console.print(table)


@app.command("resume")
def session_resume(
    session_id: str = typer.Argument(..., help="Session id to resume."),
) -> None:
    """Activate an existing session in the current workspace."""
    workspace = _require_workspace()
    meta_path = workspace.sessions_dir / session_id / "session.yaml"
    if not meta_path.exists():
        console.print(f"[red]Unknown session:[/red] {session_id}")
        raise typer.Exit(code=1)
    meta = _read_session_yaml(meta_path)
    meta["updated_at"] = datetime.now(timezone.utc).isoformat()
    meta["status"] = "open"
    _write_session_yaml(meta_path, meta)
    set_active_session(session_id)
    console.print(
        f"[green]Active session:[/green] {meta.get('name', session_id)} ({session_id}) "
        f"phase={meta.get('phase')}"
    )


@app.command("rename")
def session_rename(
    session_id: str = typer.Argument(..., help="Session id."),
    name: str = typer.Option(..., "--name", help="New display name."),
) -> None:
    """Rename a session."""
    workspace = _require_workspace()
    meta_path = workspace.sessions_dir / session_id / "session.yaml"
    if not meta_path.exists():
        console.print(f"[red]Unknown session:[/red] {session_id}")
        raise typer.Exit(code=1)
    meta = _read_session_yaml(meta_path)
    meta["name"] = name
    meta["updated_at"] = datetime.now(timezone.utc).isoformat()
    _write_session_yaml(meta_path, meta)
    console.print(f"[green]Renamed session[/green] {session_id} → {name}")


@app.command("close")
def session_close(
    session_id: Optional[str] = typer.Argument(
        None, help="Session id (default: active session)."
    ),
) -> None:
    """Mark a session closed and clear it if it was active."""
    workspace = _require_workspace()
    target = session_id or get_active_session_id()
    if not target:
        console.print("[yellow]No session specified and none active.[/yellow]")
        raise typer.Exit(code=1)
    meta_path = workspace.sessions_dir / target / "session.yaml"
    if not meta_path.exists():
        console.print(f"[red]Unknown session:[/red] {target}")
        raise typer.Exit(code=1)
    meta = _read_session_yaml(meta_path)
    meta["status"] = "closed"
    meta["updated_at"] = datetime.now(timezone.utc).isoformat()
    _write_session_yaml(meta_path, meta)
    if get_active_session_id() == target:
        set_active_session(None)
    console.print(f"[green]Closed session[/green] {target}")


@app.command("set-phase")
def session_set_phase(
    phase: str = typer.Argument(..., help="Engagement phase name."),
    session_id: Optional[str] = typer.Option(None, "--session", help="Session id."),
) -> None:
    """Manually advance or rewind the engagement phase for a session."""
    workspace = _require_workspace()
    valid_phases = {p.value for p in EngagementPhase}
    if phase not in valid_phases:
        console.print(f"[red]Invalid phase:[/red] {phase}. Choose from {sorted(valid_phases)}")
        raise typer.Exit(code=1)
    target = session_id or get_active_session_id()
    if not target:
        console.print("[yellow]No session specified and none active.[/yellow]")
        raise typer.Exit(code=1)
    meta_path = workspace.sessions_dir / target / "session.yaml"
    if not meta_path.exists():
        console.print(f"[red]Unknown session:[/red] {target}")
        raise typer.Exit(code=1)
    meta = _read_session_yaml(meta_path)
    old = meta.get("phase")
    meta["phase"] = phase
    meta["updated_at"] = datetime.now(timezone.utc).isoformat()
    _write_session_yaml(meta_path, meta)
    console.print(f"[green]Phase[/green] {old} → {phase} (session {target})")
