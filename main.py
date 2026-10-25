"""Potocus CLI entry point."""

from __future__ import annotations

import typer
from rich.console import Console

from src.cli import chat, config_cmd, scope, session, status, workspace

app = typer.Typer(
    name="potocus",
    help=(
        "Potocus — local-first hybrid AI agent harness for authorized "
        "offensive security operations."
    ),
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

app.add_typer(workspace.app, name="workspace")
app.add_typer(scope.app, name="scope")
app.add_typer(session.app, name="session")
app.add_typer(chat.app, name="chat")
app.add_typer(status.app, name="status")
app.add_typer(config_cmd.app, name="config")


@app.command("version")
def version() -> None:
    """Print the Potocus version."""
    console.print("potocus 0.1.0")


def main() -> None:
    """Console-script entry point for ``pip install`` / ``pip install -e .``."""
    app()


if __name__ == "__main__":
    main()
