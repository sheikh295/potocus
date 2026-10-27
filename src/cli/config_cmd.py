"""``potocus config`` — view global settings, test Ollama, classify risk."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.models import (
    get_model_endpoints,
    test_ollama_connection,
    list_local_models,
    list_local_models_detail,
)
from src.tools.expert import TOOL_NAME, consult_security_expert, new_budget_from_config
from src.tools.risk_classification import classify_command
from src.utils.config import GLOBAL_CONFIG_PATH, load_global_config, _write_yaml

app = typer.Typer(help="View global (non-secret) settings and test connectivity.")
console = Console()


@app.command("show")
def config_show(
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Show resolved global configuration (secrets never printed)."""
    cfg = load_global_config()
    endpoints = get_model_endpoints()

    if json_out:
        console.print_json(
            data={
                "config_path": str(GLOBAL_CONFIG_PATH),
                "ollama": {
                    "base_url": endpoints.base_url,
                    "native_url": endpoints.native_url,
                    "timeout_seconds": endpoints.timeout_seconds,
                },
                "models": {
                    "primary": endpoints.primary,
                    "temperature": endpoints.temperature,
                },
                "defaults": cfg.get("defaults", {}),
            }
        )
        return

    table = Table(title=f"Global Config — {GLOBAL_CONFIG_PATH}")
    table.add_column("Key")
    table.add_column("Value")
    table.add_row("ollama.base_url", endpoints.base_url)
    table.add_row("ollama.native_url", endpoints.native_url)
    table.add_row("models.primary", endpoints.primary)
    table.add_row("models.temperature", str(endpoints.temperature))
    defaults = cfg.get("defaults", {})
    table.add_row("defaults.pacing", str(defaults.get("pacing", "")))
    table.add_row("defaults.output_dir", str(defaults.get("output_dir", "")))
    console.print(table)


@app.command("test-ollama")
def config_test_ollama(
    skip_chat: bool = typer.Option(
        False,
        "--skip-chat",
        help="Only check /api/tags; skip the chat completion probe.",
    ),
) -> None:
    """Verify Ollama is up and both configured models are available."""
    console.print("[dim]Probing Ollama…[/dim]")
    result = test_ollama_connection(run_chat_probe=not skip_chat)

    table = Table(title="Ollama Connection Test")
    table.add_column("Check")
    table.add_column("Result")
    table.add_row("native_url", result.native_url)
    table.add_row("base_url", result.base_url)
    table.add_row(
        "primary present",
        "[green]yes[/green]" if result.primary_present else "[red]no[/red]",
    )
    if not skip_chat:
        table.add_row(
            "chat probe",
            "[green]ok[/green]" if result.chat_ok else "[red]failed[/red]",
        )
        if result.chat_preview:
            table.add_row("chat preview", result.chat_preview[:120])
    if result.context_window:
        table.add_row("context window", str(result.context_window))
    table.add_row("models on host", ", ".join(result.available_models) or "(none)")
    console.print(table)

    if result.ok:
        console.print("[green]Ollama ready — primary model available.[/green]")
    else:
        console.print(f"[red]Not ready:[/red] {result.error}")
        raise typer.Exit(code=1)


@app.command(
    "classify",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def config_classify(ctx: typer.Context) -> None:
    """
    Classify a command into risk Tier 1/2/3 (does not execute it).

    Example: ``potocus config classify -- nmap -sV 10.10.20.5``
    """
    command = list(ctx.args)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        console.print("[red]Provide a command after `--`.[/red]")
        console.print("Example: potocus config classify -- nmap -sV 10.10.20.5")
        raise typer.Exit(code=1)

    result = classify_command(command)
    color = {
        "tier1": "green",
        "tier2": "yellow",
        "tier3": "red",
    }[result.tier.value]
    console.print(
        Panel.fit(
            f"[{color}]{result.tier.name}[/{color}] ({result.tier.value})\n"
            f"rule: {result.matched_rule}\n"
            f"reason: {result.reason}\n"
            f"command: {' '.join(command)}",
            title="Risk Classification",
            border_style=color,
        )
    )


@app.command("consult")
def config_consult(
    query: str = typer.Argument(..., help="Question for the security specialist."),
    context: str | None = typer.Option(
        None,
        "--context",
        "-c",
        help="Optional factual context (scan notes, CVE ids).",
    ),
    twice: bool = typer.Option(
        False,
        "--twice",
        help="Call twice with the same budget to demonstrate the per-turn cap.",
    ),
) -> None:
    """
    Call ``consult_security_expert`` against the live Dolphin3-Cyber model.

    Specialist history stays isolated from the orchestrator. Use ``--twice`` to
    verify the per-turn budget (second call should be capped).
    """
    from rich.markdown import Markdown

    budget = new_budget_from_config()
    endpoints = get_model_endpoints()
    console.print(
        f"[dim]{TOOL_NAME} → {endpoints.primary} "
        f"(budget {budget.max_calls_per_turn}/turn)[/dim]"
    )

    def _run(label: str) -> None:
        with console.status(f"[dim]{label}…[/dim]", spinner="dots"):
            result = consult_security_expert(query, context=context, budget=budget)
        border = "yellow" if result.capped else "magenta"
        console.print(
            Panel(
                Markdown(result.answer),
                title=(
                    f"{TOOL_NAME} · call {result.calls_this_turn}/"
                    f"{result.max_calls_per_turn}"
                    + (" · CAPPED" if result.capped else "")
                ),
                border_style=border,
            )
        )

    _run("consulting specialist")
    if twice:
        _run("second consult (expect cap)")


# ---------------------------------------------------------------------------
# `potocus config model` — switch / inspect the single security-expert model
# ---------------------------------------------------------------------------

model_app = typer.Typer(help="List, show, and set the single Ollama security-expert model.")
app.add_typer(model_app, name="model")


@model_app.command("list")
def model_list(json_out: bool = typer.Option(False, "--json", help="Emit JSON.")) -> None:
    """List installed Ollama models with capabilities and context window."""
    models = list_local_models_detail()
    endpoints = get_model_endpoints()
    current = endpoints.primary
    rows = []
    for m in models:
        name = str(m.get("name", ""))
        details = m.get("details", {}) or {}
        caps = m.get("capabilities", [])
        ctx = details.get("context_length", 0)
        rows.append({
            "name": name,
            "active": name == current,
            "capabilities": ", ".join(caps) if isinstance(caps, list) else str(caps),
            "context_window": ctx,
            "parameter_size": details.get("parameter_size", ""),
            "quantization": details.get("quantization_level", ""),
        })
    if json_out:
        console.print_json(data={"current": current, "models": rows})
        return
    table = Table(title="Local Ollama Models")
    table.add_column("Name")
    table.add_column("Active", justify="center")
    table.add_column("Capabilities")
    table.add_column("Context", justify="right")
    table.add_column("Param / Quant")
    for r in rows:
        table.add_row(
            r["name"],
            "[green]●[/green]" if r["active"] else "",
            r["capabilities"],
            str(r["context_window"]),
            f"{r['parameter_size']} / {r['quantization']}",
        )
    console.print(table)


@model_app.command("show")
def model_show() -> None:
    """Show the configured primary model."""
    endpoints = get_model_endpoints()
    console.print(f"[bold]primary model:[/bold] {endpoints.primary}")
    console.print(f"[dim]Ollama API:[/dim] {endpoints.base_url}")


@model_app.command("set")
def model_set(
    name: str = typer.Argument(..., help="Ollama model name (must be present via `ollama list`)."),
) -> None:
    """Set the primary security-expert model (validates it exists locally)."""
    installed = list_local_models()
    if name not in installed:
        console.print(f"[red]Model not installed locally:[/red] {name}")
        console.print(f"[dim]Installed: {', '.join(installed) or '(none)'}[/dim]")
        console.print("[dim]Pull it first: ollama pull <name>[/dim]")
        raise typer.Exit(code=1)

    cfg = load_global_config()
    cfg.setdefault("models", {})["primary"] = name
    _write_yaml(GLOBAL_CONFIG_PATH, cfg)

    # Also update the active workspace's override if a workspace is active.
    from src.utils.config import load_active_state, save_active_state, get_active_workspace_path
    from src.workspace.manager import load_workspace

    state = load_active_state()
    ws_path = state.get("workspace")
    if ws_path:
        try:
            ws = load_workspace(__import__("pathlib").Path(ws_path))
            from src.workspace.manager import save_workspace_config
            save_workspace_config(ws, {"models": {"primary": name}})
        except Exception:  # noqa: BLE001
            pass

    console.print(f"[green]Primary model set to:[/green] {name}")
    console.print("[dim]Run `potocus config test-ollama` to verify.[/dim]")


@model_app.command("test")
def model_test(
    name: str = typer.Argument(..., help="Model name to probe."),
) -> None:
    """Chat-probe a specific model to confirm it answers end-to-end."""
    from openai import OpenAI

    endpoints = get_model_endpoints()
    if name not in list_local_models():
        console.print(f"[red]Model not installed locally:[/red] {name}")
        raise typer.Exit(code=1)
    client = OpenAI(base_url=endpoints.base_url, api_key="ollama", timeout=endpoints.timeout_seconds)
    try:
        completion = client.chat.completions.create(
            model=name,
            messages=[{"role": "user", "content": "Reply with exactly: potocus-ok"}],
            temperature=0,
            max_tokens=256,
            extra_body={"think": False},
        )
        preview = (completion.choices[0].message.content or "").strip()
        if preview:
            console.print(f"[green]{name} responded:[/green] {preview[:120]}")
        else:
            console.print(f"[yellow]{name} returned empty content[/yellow]")
            raise typer.Exit(code=1)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Probe failed for {name}:[/red] {exc}")
        raise typer.Exit(code=1)
