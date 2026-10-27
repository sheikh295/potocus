"""``potocus status`` — one-call context snapshot."""

from __future__ import annotations

import typer
import yaml
from rich.console import Console
from rich.table import Table

from src.memory.findings_db import FindingsDB
from src.models import get_model_endpoints
from src.utils.config import get_active_session_id, get_active_workspace_path
from src.workspace.manager import WorkspaceError, load_workspace

app = typer.Typer(help="Show current workspace, session, phase, and scope mode.")
console = Console()


@app.callback(invoke_without_command=True)
def status(
    ctx: typer.Context,
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Print the operator's current Potocus context at a glance."""
    if ctx.invoked_subcommand is not None:
        return

    active_ws = get_active_workspace_path()
    session_id = get_active_session_id()
    endpoints = get_model_endpoints()

    payload: dict = {
        "workspace": None,
        "session": None,
        "models": {
            "primary": endpoints.primary,
            "base_url": endpoints.base_url,
        },
    }

    if active_ws is not None:
        try:
            workspace = load_workspace(active_ws)
            scope_count = 0
            if workspace.mode == "scoped" and workspace.scope_yaml.exists():
                with workspace.scope_yaml.open("r", encoding="utf-8") as handle:
                    scope_data = yaml.safe_load(handle) or {}
                targets = scope_data.get("targets") or []
                scope_count = len(targets)

            findings_summary = {"hosts": 0, "services": 0, "findings": 0}
            try:
                db = FindingsDB(workspace.findings_db)
                findings_summary = db.summary()
                db.close()
            except Exception:  # noqa: BLE001 — status should still render
                pass

            payload["workspace"] = {
                "name": workspace.name,
                "root": str(workspace.root),
                "mode": workspace.mode,
                "pacing": workspace.pacing,
                "output_dir": str(workspace.output_dir),
                "scope_target_count": scope_count,
                "models": workspace.models,
                "findings": findings_summary,
            }

            if session_id:
                meta_path = workspace.sessions_dir / session_id / "session.yaml"
                if meta_path.exists():
                    with meta_path.open("r", encoding="utf-8") as handle:
                        meta = yaml.safe_load(handle) or {}
                    payload["session"] = {
                        "id": session_id,
                        "name": meta.get("name"),
                        "phase": meta.get("phase"),
                        "status": meta.get("status"),
                        "target_focus": meta.get("target_focus", ""),
                    }
                else:
                    payload["session"] = {"id": session_id, "missing": True}
        except WorkspaceError as exc:
            payload["workspace_error"] = str(exc)

    if json_out:
        console.print_json(data=payload)
        return

    table = Table(title="Potocus Status")
    table.add_column("Field")
    table.add_column("Value")

    ws = payload.get("workspace")
    if not ws:
        table.add_row("workspace", "[yellow]none — run `potocus workspace init`[/yellow]")
    else:
        mode_color = "red" if ws["mode"] == "scoped" else "yellow"
        table.add_row("workspace", f"{ws['name']} ({ws['root']})")
        table.add_row("mode", f"[{mode_color}]{ws['mode']}[/{mode_color}]")
        table.add_row("pacing", ws["pacing"])
        table.add_row("scope targets", str(ws["scope_target_count"]))
        table.add_row("output_dir", ws["output_dir"])
        findings = ws.get("findings") or {}
        table.add_row(
            "findings.db",
            f"hosts={findings.get('hosts', 0)} "
            f"services={findings.get('services', 0)} "
            f"findings={findings.get('findings', 0)}",
        )

    sess = payload.get("session")
    if not sess:
        table.add_row("session", "[dim]none[/dim]")
        table.add_row("phase", "[dim]—[/dim]")
    else:
        table.add_row("session", f"{sess.get('name', '')} ({sess.get('id')})")
        table.add_row("phase", str(sess.get("phase", "—")))
        table.add_row("session status", str(sess.get("status", "—")))

    table.add_row("model", endpoints.primary)
    table.add_row("ollama", endpoints.base_url)
    console.print(table)
