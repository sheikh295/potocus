"""``potocus chat`` — interactive orchestrator REPL against local Ollama."""

from __future__ import annotations

from typing import Any

import typer
import yaml
from openai import OpenAI
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from src.models import get_model_endpoints, get_openai_client
from src.prompts import ORCHESTRATOR_SYSTEM_PROMPT
from src.utils.config import (
    GLOBAL_STATE_DIR,
    get_active_session_id,
    get_active_workspace_path,
)
from src.workspace.manager import WorkspaceError, load_workspace

app = typer.Typer(help="Enter the interactive agent REPL for the active session.")
console = Console()


def _load_session_meta(workspace, session_id: str) -> dict[str, Any]:
    """Read session.yaml for the active session."""
    path = workspace.sessions_dir / session_id / "session.yaml"
    if not path.exists():
        raise WorkspaceError(f"Session not found: {session_id}")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise WorkspaceError(f"Invalid session.yaml for {session_id}")
    return data


def _chat_once(
    client: OpenAI,
    *,
    model: str,
    temperature: float,
    messages: list[dict[str, str]],
) -> str:
    """Send one chat turn to the orchestrator and return assistant text."""
    completion = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature,
        extra_body={"think": False},
    )
    message = completion.choices[0].message
    content = (message.content or "").strip()
    if not content:
        reasoning = getattr(message, "reasoning", None) or ""
        content = str(reasoning).strip()
    return content


@app.callback(invoke_without_command=True)
def chat(ctx: typer.Context) -> None:
    """
    Start a real orchestrator chat loop for the active workspace/session.

    Tool calling and HITL interrupt flow wire in with the LangGraph engine;
    this REPL already talks to your live local models with full session context.
    """
    if ctx.invoked_subcommand is not None:
        return

    active_ws = get_active_workspace_path()
    if active_ws is None:
        console.print("[yellow]No active workspace. Run `potocus workspace init` first.[/yellow]")
        raise typer.Exit(code=1)

    try:
        workspace = load_workspace(active_ws)
    except WorkspaceError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    session_id = get_active_session_id()
    if session_id is None:
        console.print(
            "[yellow]No active session.[/yellow] "
            "Create one with `potocus session new --name ...`."
        )
        raise typer.Exit(code=1)

    try:
        meta = _load_session_meta(workspace, session_id)
    except WorkspaceError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    endpoints = get_model_endpoints()
    # Prefer workspace model overrides when present.
    model = workspace.models.get("orchestrator") or endpoints.orchestrator
    client = get_openai_client()

    mode_style = "bold red" if workspace.mode == "scoped" else "bold yellow"
    console.print(
        Panel.fit(
            f"[{mode_style}]{workspace.mode.upper()}[/{mode_style}]  "
            f"{workspace.name}  ·  session {meta.get('name', session_id)} ({session_id})\n"
            f"phase: {meta.get('phase', 'RECON')}  ·  model: {model}\n"
            "[dim]Type a message. Commands: /exit  /clear  /status[/dim]",
            title="Potocus Chat",
            border_style="cyan",
        )
    )

    system = (
        f"{ORCHESTRATOR_SYSTEM_PROMPT}\n\n"
        f"Workspace: {workspace.name}\n"
        f"Mode: {workspace.mode}\n"
        f"Phase: {meta.get('phase', 'RECON')}\n"
        f"Pacing: {workspace.pacing}\n"
    )
    messages: list[dict[str, str]] = [{"role": "system", "content": system}]

    GLOBAL_STATE_DIR.mkdir(parents=True, exist_ok=True)
    history_path = GLOBAL_STATE_DIR / "chat_history.txt"
    session: PromptSession[str] = PromptSession(history=FileHistory(str(history_path)))

    while True:
        try:
            user_text = session.prompt("you › ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Bye.[/dim]")
            break

        if not user_text:
            continue
        if user_text in {"/exit", "/quit", ":q"}:
            console.print("[dim]Bye.[/dim]")
            break
        if user_text == "/clear":
            messages = [{"role": "system", "content": system}]
            console.print("[green]Context cleared.[/green]")
            continue
        if user_text == "/status":
            console.print(
                f"mode={workspace.mode} phase={meta.get('phase')} "
                f"messages={len(messages)} model={model}"
            )
            continue

        messages.append({"role": "user", "content": user_text})
        try:
            with console.status("[dim]thinking…[/dim]", spinner="dots"):
                reply = _chat_once(
                    client,
                    model=model,
                    temperature=endpoints.temperature,
                    messages=messages,
                )
        except Exception as exc:  # noqa: BLE001 — show live API errors to the operator
            console.print(f"[red]Model error:[/red] {exc}")
            messages.pop()  # drop the failed user turn
            continue

        if not reply:
            console.print("[yellow]Empty model response.[/yellow]")
            continue

        messages.append({"role": "assistant", "content": reply})
        console.print()
        console.print(Markdown(reply))
        console.print()
