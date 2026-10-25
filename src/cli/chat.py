"""``potocus chat`` — LangGraph ReAct REPL for the active session."""

from __future__ import annotations

from typing import Any

import typer
import yaml
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt

from src.graph import PotocusAgent, create_agent, valid_phases
from src.tools.expert import TOOL_NAME as CONSULT_TOOL_NAME
from src.tools.terminal import TOOL_NAME as EXECUTE_TOOL_NAME
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


def _save_session_phase(workspace, session_id: str, phase: str) -> None:
    """Persist phase changes back to session.yaml."""
    path = workspace.sessions_dir / session_id / "session.yaml"
    meta = _load_session_meta(workspace, session_id)
    meta["phase"] = phase
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(meta, handle, default_flow_style=False, sort_keys=False)


def _hitl_prompt(payload: dict[str, Any]) -> str:
    """Render a Rich HITL panel and return approve/deny."""
    tier = str(payload.get("tier_name") or payload.get("tier") or "?")
    color = "red" if "3" in str(payload.get("tier", "")) or "EXPLOIT" in tier else "yellow"
    lines = [
        f"[bold]{payload.get('tool', EXECUTE_TOOL_NAME)}[/bold]",
        f"command: [white]{payload.get('command_display') or payload.get('command')}[/white]",
        f"tier: [{color}]{tier}[/{color}] — {payload.get('tier_reason', '')}",
        f"mode: {payload.get('mode')}",
        f"scope: {payload.get('scope_decision')} — {payload.get('scope_reason', '')}",
    ]
    targets = payload.get("targets") or []
    new_targets = payload.get("new_targets") or []
    if targets:
        lines.append(f"targets: {', '.join(map(str, targets))}")
    if new_targets:
        lines.append(f"[yellow]new targets:[/yellow] {', '.join(map(str, new_targets))}")
    console.print(
        Panel(
            "\n".join(lines),
            title="HITL confirmation required",
            border_style=color,
        )
    )
    answer = Prompt.ask("Allow execution?", choices=["y", "n"], default="n")
    return "approve" if answer.lower() == "y" else "deny"


def _print_turn(agent: PotocusAgent, state: dict[str, Any], user_text: str) -> None:
    """Render tool calls and the final assistant reply for this turn."""
    messages = list(state.get("messages") or [])
    start = 0
    for idx in range(len(messages) - 1, -1, -1):
        msg = messages[idx]
        if isinstance(msg, HumanMessage) and msg.content == user_text:
            start = idx + 1
            break

    for msg in messages[start:]:
        if isinstance(msg, AIMessage) and msg.tool_calls:
            for call in msg.tool_calls:
                name = call.get("name", "tool")
                args = call.get("args", {})
                console.print(
                    Panel.fit(
                        f"[bold]{name}[/bold]\n{args}",
                        title="tool call",
                        border_style="cyan",
                    )
                )
        elif isinstance(msg, ToolMessage):
            content = str(msg.content)
            border = "yellow" if (
                "BUDGET_EXCEEDED" in content
                or "blocked_scope" in content
                or "denied_hitl" in content
            ) else "magenta"
            console.print(
                Panel(
                    Markdown(content),
                    title=f"tool result · {msg.name or CONSULT_TOOL_NAME}",
                    border_style=border,
                )
            )

    reply = agent.latest_ai_text(state)  # type: ignore[arg-type]
    if reply:
        console.print()
        console.print(Markdown(reply))
        console.print()
    else:
        console.print("[yellow]No final assistant message in this turn.[/yellow]")


@app.callback(invoke_without_command=True)
def chat(ctx: typer.Context) -> None:
    """
    Start the Potocus LangGraph ReAct loop for the active workspace/session.

    Destructive / Tier-3 (and new-target) commands pause for inline HITL.
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

    phase = str(meta.get("phase") or "RECON")
    agent = create_agent(workspace, session_id=session_id, phase=phase)

    mode_style = "bold red" if workspace.mode == "scoped" else "bold yellow"
    console.print(
        Panel.fit(
            f"[{mode_style}]{workspace.mode.upper()}[/{mode_style}]  "
            f"{workspace.name}  ·  session {meta.get('name', session_id)} ({session_id})\n"
            f"phase: {phase}\n"
            f"orchestrator: {agent.runtime.orchestrator_model}\n"
            f"specialist:   {agent.runtime.specialist_model}\n"
            f"tools: {EXECUTE_TOOL_NAME}, {CONSULT_TOOL_NAME}\n"
            f"context budget: {agent.runtime.context_token_limit} tokens (approx)\n"
            "[dim]Commands: /exit  /status  /phase <NAME>[/dim]",
            title="Potocus Chat (LangGraph)",
            border_style="cyan",
        )
    )

    GLOBAL_STATE_DIR.mkdir(parents=True, exist_ok=True)
    history_path = GLOBAL_STATE_DIR / "chat_history.txt"
    prompt_session: PromptSession[str] = PromptSession(
        history=FileHistory(str(history_path))
    )

    try:
        while True:
            try:
                user_text = prompt_session.prompt("you › ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Bye.[/dim]")
                break

            if not user_text:
                continue
            if user_text in {"/exit", "/quit", ":q"}:
                console.print("[dim]Bye.[/dim]")
                break
            if user_text == "/status":
                snap = agent.graph.get_state(agent.config())
                values = snap.values if snap else {}
                console.print(
                    f"mode={workspace.mode} phase={agent.runtime.phase} "
                    f"tokens≈{values.get('context_tokens_approx', 0)} "
                    f"specialist_this_turn="
                    f"{values.get('specialist_calls_this_turn', 0)}/"
                    f"{agent.runtime.budget.max_calls_per_turn} "
                    f"tier2_confirmed={agent.runtime.tier2_confirmed} "
                    f"seen_targets={agent.runtime.seen_targets} "
                    f"messages={len(values.get('messages') or [])}"
                )
                continue
            if user_text.startswith("/phase"):
                parts = user_text.split(maxsplit=1)
                if len(parts) != 2:
                    console.print("[yellow]Usage:[/yellow] /phase RECON|ENUMERATION|...")
                    continue
                new_phase = parts[1].strip().upper()
                if new_phase not in valid_phases():
                    console.print(f"[red]Invalid phase.[/red] Choose from {valid_phases()}")
                    continue
                agent.runtime.phase = new_phase
                _save_session_phase(workspace, session_id, new_phase)
                agent.graph.update_state(agent.config(), {"phase": new_phase})
                console.print(f"[green]Phase set to[/green] {new_phase}")
                continue

            console.print("[dim]agent loop…[/dim]")
            try:
                state = agent.invoke_turn(user_text, hitl_callback=_hitl_prompt)
            except Exception as exc:  # noqa: BLE001
                console.print(f"[red]Agent error:[/red] {exc}")
                continue

            _print_turn(agent, state, user_text)
    finally:
        agent.close()
