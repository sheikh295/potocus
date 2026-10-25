"""``potocus session`` — multi-session lifecycle with checkpoint resume."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.utils.config import (
    get_active_session_id,
    get_active_workspace_path,
    set_active_session,
)
from src.workspace.manager import EngagementPhase, WorkspaceError, load_workspace
from src.workspace.session_store import (
    inspect_checkpoint,
    list_session_ids,
    read_session_meta,
    session_yaml_path,
    sync_meta_from_checkpoint,
    touch_session,
    write_session_meta,
)

app = typer.Typer(help="Create, list, resume, and manage sessions (checkpointed).")
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


def _valid_phase(phase: str) -> str:
    """Validate engagement phase name."""
    valid = {p.value for p in EngagementPhase}
    if phase not in valid:
        console.print(f"[red]Invalid phase:[/red] {phase}. Choose from {sorted(valid)}")
        raise typer.Exit(code=1)
    return phase


@app.command("new")
def session_new(
    name: str = typer.Option(..., "--name", help="Human-readable session name."),
    phase: str = typer.Option(
        EngagementPhase.RECON.value,
        "--phase",
        help="Starting engagement phase.",
    ),
    focus: str = typer.Option("", "--focus", help="Optional target focus note."),
) -> None:
    """Create a new session in the active workspace and set it active."""
    workspace = _require_workspace()
    phase = _valid_phase(phase)

    session_id = uuid4().hex[:12]
    session_path = session_yaml_path(workspace, session_id)
    (session_path.parent / "checkpoints").mkdir(parents=True, exist_ok=True)
    (session_path.parent / "raw_output").mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).isoformat()
    meta = {
        "id": session_id,
        "name": name,
        "created_at": now,
        "updated_at": now,
        "phase": phase,
        "target_focus": focus,
        "status": "open",
        "message_count": 0,
        "checkpoint_exists": False,
    }
    write_session_meta(workspace, session_id, meta)
    set_active_session(session_id)
    console.print(
        f"[green]Created session[/green] [bold]{name}[/bold] ({session_id}) "
        f"phase={phase}"
        + (f" focus={focus!r}" if focus else "")
    )


@app.command("list")
def session_list(
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """List sessions with phase, focus, and checkpoint message counts."""
    workspace = _require_workspace()
    active_id = get_active_session_id()
    rows: list[dict] = []
    for session_id in list_session_ids(workspace):
        meta = read_session_meta(workspace, session_id)
        snap = inspect_checkpoint(workspace, session_id)
        # Keep yaml message_count fresh without rewriting every list unless useful.
        meta["active"] = session_id == active_id
        meta["checkpoint_exists"] = snap.exists
        meta["messages"] = snap.message_count
        meta["pending_interrupt"] = snap.pending_interrupt
        if snap.phase:
            meta["phase"] = snap.phase
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
    table.add_column("Focus")
    table.add_column("Msgs")
    table.add_column("CKPT")
    table.add_column("Status")
    table.add_column("Updated")
    for row in rows:
        table.add_row(
            "*" if row.get("active") else "",
            str(row.get("id", "")),
            str(row.get("name", "")),
            str(row.get("phase", "")),
            str(row.get("target_focus", "") or "")[:24],
            str(row.get("messages", 0)),
            "yes" if row.get("checkpoint_exists") else "no",
            str(row.get("status", "")),
            str(row.get("updated_at", "")),
        )
    console.print(table)


@app.command("show")
def session_show(
    session_id: Optional[str] = typer.Argument(
        None, help="Session id (default: active)."
    ),
) -> None:
    """Show session metadata and checkpoint summary."""
    workspace = _require_workspace()
    target = session_id or get_active_session_id()
    if not target:
        console.print("[yellow]No session specified and none active.[/yellow]")
        raise typer.Exit(code=1)
    try:
        meta = read_session_meta(workspace, target)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    snap = inspect_checkpoint(workspace, target)
    console.print(
        Panel.fit(
            f"name: {meta.get('name')}\n"
            f"id: {target}\n"
            f"status: {meta.get('status')}\n"
            f"phase: {snap.phase or meta.get('phase')}\n"
            f"focus: {meta.get('target_focus') or '(none)'}\n"
            f"pacing: {meta.get('pacing') or '(workspace default)'}\n"
            f"messages: {snap.message_count}\n"
            f"tokens≈: {snap.context_tokens_approx}\n"
            f"seen_targets: {', '.join(snap.seen_targets) or '(none)'}\n"
            f"tier2_confirmed: {snap.tier2_confirmed}\n"
            f"pending_HITL: {snap.pending_interrupt}\n"
            f"checkpoint: {snap.path or '(none)'}\n"
            f"updated: {meta.get('updated_at')}",
            title="Session",
            border_style="cyan",
        )
    )


@app.command("resume")
def session_resume(
    session_id: str = typer.Argument(..., help="Session id to resume."),
) -> None:
    """
    Activate a session and sync metadata from its LangGraph checkpoint.

    Message history / phase / seen targets are restored automatically the next
    time you enter ``potocus chat`` (same thread id).
    """
    workspace = _require_workspace()
    try:
        meta, snap = sync_meta_from_checkpoint(workspace, session_id)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    meta = touch_session(workspace, session_id, status="open")
    set_active_session(session_id)

    console.print(
        Panel.fit(
            f"[green]Resumed[/green] [bold]{meta.get('name', session_id)}[/bold] ({session_id})\n"
            f"phase: {meta.get('phase')}\n"
            f"focus: {meta.get('target_focus') or '(none)'}\n"
            f"checkpoint: {'yes' if snap.exists else 'no (fresh thread)'}\n"
            f"messages restored: {snap.message_count}\n"
            f"tokens≈: {snap.context_tokens_approx}\n"
            f"pending HITL: {snap.pending_interrupt}\n"
            f"seen_targets: {', '.join(snap.seen_targets) or '(none)'}\n\n"
            "[dim]Run `potocus chat` to continue this thread.[/dim]",
            title="Session resume",
            border_style="green",
        )
    )


@app.command("rename")
def session_rename(
    session_id: str = typer.Argument(..., help="Session id."),
    name: str = typer.Option(..., "--name", help="New display name."),
) -> None:
    """Rename a session."""
    workspace = _require_workspace()
    try:
        touch_session(workspace, session_id, name=name)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
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
    try:
        touch_session(workspace, target, status="closed")
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    if get_active_session_id() == target:
        set_active_session(None)
    console.print(f"[green]Closed session[/green] {target}")


@app.command("set-phase")
def session_set_phase(
    phase: str = typer.Argument(..., help="Engagement phase name."),
    session_id: Optional[str] = typer.Option(None, "--session", help="Session id."),
) -> None:
    """Advance/rewind phase in session.yaml and the LangGraph checkpoint."""
    workspace = _require_workspace()
    phase = _valid_phase(phase)
    target = session_id or get_active_session_id()
    if not target:
        console.print("[yellow]No session specified and none active.[/yellow]")
        raise typer.Exit(code=1)
    try:
        meta = read_session_meta(workspace, target)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    old = meta.get("phase")
    touch_session(workspace, target, phase=phase)

    # Persist into checkpoint so chat/resume see it immediately.
    from src.graph import create_agent

    agent = create_agent(workspace, session_id=target, phase=phase)
    try:
        agent.graph.update_state(agent.config(), {"phase": phase})
    finally:
        agent.close()

    console.print(f"[green]Phase[/green] {old} → {phase} (session {target})")


@app.command("set-focus")
def session_set_focus(
    focus: str = typer.Argument(..., help="Target focus note for this session."),
    session_id: Optional[str] = typer.Option(None, "--session", help="Session id."),
) -> None:
    """Set the session's target focus (shown in list/status/chat)."""
    workspace = _require_workspace()
    target = session_id or get_active_session_id()
    if not target:
        console.print("[yellow]No session specified and none active.[/yellow]")
        raise typer.Exit(code=1)
    try:
        touch_session(workspace, target, target_focus=focus)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Focus set:[/green] {focus}")


@app.command("set-pacing")
def session_set_pacing(
    pacing: str = typer.Argument(..., help="stealth | normal | aggressive"),
    session_id: Optional[str] = typer.Option(None, "--session", help="Session id."),
) -> None:
    """Override pacing for this session without changing the workspace default."""
    if pacing not in ("stealth", "normal", "aggressive"):
        console.print("[red]Invalid pacing.[/red] Use stealth | normal | aggressive")
        raise typer.Exit(code=1)
    workspace = _require_workspace()
    target = session_id or get_active_session_id()
    if not target:
        console.print("[yellow]No session specified and none active.[/yellow]")
        raise typer.Exit(code=1)
    try:
        touch_session(workspace, target, pacing=pacing)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Session pacing:[/green] {pacing}")
