"""``potocus config`` — view global settings, test Ollama, classify risk."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.models import get_model_endpoints, test_ollama_connection
from src.tools.risk_classification import classify_command
from src.utils.config import GLOBAL_CONFIG_PATH, load_global_config

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
                    "orchestrator": endpoints.orchestrator,
                    "specialist": endpoints.specialist,
                    "temperature": endpoints.temperature,
                    "specialist_calls_per_turn": endpoints.specialist_calls_per_turn,
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
    table.add_row("models.orchestrator", endpoints.orchestrator)
    table.add_row("models.specialist", endpoints.specialist)
    table.add_row("models.temperature", str(endpoints.temperature))
    table.add_row(
        "models.specialist_calls_per_turn",
        str(endpoints.specialist_calls_per_turn),
    )
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
        "orchestrator present",
        "[green]yes[/green]" if result.orchestrator_present else "[red]no[/red]",
    )
    table.add_row(
        "specialist present",
        "[green]yes[/green]" if result.specialist_present else "[red]no[/red]",
    )
    if not skip_chat:
        table.add_row(
            "chat probe",
            "[green]ok[/green]" if result.chat_ok else "[red]failed[/red]",
        )
        if result.chat_preview:
            table.add_row("chat preview", result.chat_preview[:120])
    table.add_row("models on host", ", ".join(result.available_models) or "(none)")
    console.print(table)

    if result.ok:
        console.print("[green]Ollama ready — both models available.[/green]")
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
