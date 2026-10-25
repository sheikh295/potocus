"""Claude-style terminal activity UI for Potocus chat (security-themed verbs)."""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.spinner import Spinner
from rich.text import Text

# Rotating status verbs — same energy as Claude Code's "Noodling", but recon/ops flavored.
SECURITY_VERBS: tuple[str, ...] = (
    "Reconning",
    "Enumerating",
    "Fingerprinting",
    "Pivoting",
    "Payloading",
    "Exfiltrating",
    "Weaponizing",
    "Hardening",
    "Scope-checking",
    "Threat-modeling",
    "Packet-sniffing",
    "Hash-cracking",
    "Lateral-moving",
    "Privilege-escalating",
    "Beaconing",
    "Tunneling",
    "Fuzzing",
    "Squatting",
    "Spoofing",
    "Bruteforcing",
    "Shellcoding",
    "Rootkitting",
    "Phishing-for-ideas",
    "Zero-daydreaming",
    "CVE-diving",
    "Port-knocking",
    "Traffic-shaping",
    "Opsec-ing",
    "Red-teaming",
    "Blue-teaming",
    "Purple-teaming",
    "Huntressing",
    "Incident-responding",
    "Forensicking",
    "Sandboxing",
    "Decompiling",
    "Reverse-engineering",
    "Buffer-overflowing",
    "Heap-spraying",
    "ROP-chaining",
    "Kerberoasting",
    "Pass-the-hashing",
    "Living-off-the-land",
    "Nmap-whispering",
    "Gobuster-ing",
    "Metasploiting",
    "Burping",
    "Wiresharking",
    "Yara-ing",
    "Sigma-crafting",
    "Flibbertigibbeting",
    "Wibbling",
    "Smooshing",
    "Honking",
    "Noodling",
    "Combobulating",
    "Clauding",
    "Schlepping",
    "Moseying",
    "Ruminating",
    "Yodeling",
    "Jiving",
    "Fermenting",
)


@dataclass
class ActivityDisplay:
    """
    Live status line with a rotating security verb + optional detail.

    Verbose event lines are printed above the live status (not inside it), so
    the operator sees a Claude-like stream of work while the spinner keeps moving.
    """

    console: Console
    verbose: bool = True
    _verb: str = field(default_factory=lambda: random.choice(SECURITY_VERBS))
    _detail: str = "working"
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None
    _live: Live | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _render(self) -> Spinner:
        # Single-line Claude-style status: spinner + verb + dim detail.
        label = Text.assemble(
            ("• ", "cyan bold"),
            (self._verb, "cyan"),
            ("  ", ""),
            (self._detail, "dim"),
        )
        return Spinner("dots", text=label, style="cyan")

    def start(self, detail: str = "starting agent loop") -> None:
        """Start the live rotating status line."""
        self._detail = detail
        self._stop.clear()
        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=8,
            transient=True,
        )
        self._live.start()

        def _rotate() -> None:
            while not self._stop.wait(1.6):
                with self._lock:
                    self._verb = random.choice(SECURITY_VERBS)
                    if self._live is not None:
                        self._live.update(self._render())

        self._thread = threading.Thread(target=_rotate, daemon=True)
        self._thread.start()

    def set_detail(self, detail: str) -> None:
        """Update the dim detail text next to the verb."""
        with self._lock:
            self._detail = detail
            if self._live is not None:
                self._live.update(self._render())

    def bump_verb(self, preferred: str | None = None) -> None:
        """Force a new verb (optionally a specific one)."""
        with self._lock:
            self._verb = preferred or random.choice(SECURITY_VERBS)
            if self._live is not None:
                self._live.update(self._render())

    def pause(self) -> None:
        """Temporarily hide the live spinner (e.g. before HITL prompts)."""
        if self._live is not None:
            self._live.stop()
            self._live = None

    def resume(self, detail: str | None = None) -> None:
        """Restart the spinner after a pause."""
        if detail:
            self._detail = detail
        if self._live is None and not self._stop.is_set():
            self._live = Live(
                self._render(),
                console=self.console,
                refresh_per_second=8,
                transient=True,
            )
            self._live.start()

    def stop(self) -> None:
        """Stop rotation and clear the live line."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self._live is not None:
            self._live.stop()
            self._live = None

    def log(self, message: str, *, style: str = "dim") -> None:
        """Print a verbose line above the spinner."""
        if not self.verbose:
            return
        # Pause live briefly so Rich doesn't fight over the cursor.
        live = self._live
        if live is not None:
            live.stop()
        self.console.print(f"[{style}]{message}[/{style}]")
        if live is not None and not self._stop.is_set():
            self._live = Live(
                self._render(),
                console=self.console,
                refresh_per_second=8,
                transient=True,
            )
            self._live.start()

    def panel(self, content: Any, *, title: str, border_style: str = "cyan") -> None:
        """Print a Rich panel above the spinner."""
        if not self.verbose:
            return
        live = self._live
        if live is not None:
            live.stop()
        body = content if isinstance(content, (str, Markdown, Text, Panel)) else str(content)
        if isinstance(body, str):
            body = Markdown(body) if "\n" in body or body.startswith("#") else Text(body)
        self.console.print(Panel(body, title=title, border_style=border_style))
        if live is not None and not self._stop.is_set():
            self._live = Live(
                self._render(),
                console=self.console,
                refresh_per_second=8,
                transient=True,
            )
            self._live.start()


def render_stream_event(ui: ActivityDisplay, event: dict[str, Any]) -> None:
    """Render one agent event into the chat UI.

    Events arrive from the LangGraph event sink. The live spinner keeps
    rotating while verbose panels/log lines print above it — the Claude
    Code terminal experience: thinking verb, reasoning text, tool calls,
    tool results, and status updates all visible as the agent works.
    """
    kind = event.get("type")
    if kind == "node":
        node = event.get("node", "")
        labels = {
            "compact": ("Compacting", "compacting context window"),
            "agent": ("Ruminating", "orchestrator reasoning"),
            "tools": ("Enumerating", "running tools"),
        }
        verb, detail = labels.get(node, (None, f"node={node}"))
        ui.bump_verb(verb)
        ui.set_detail(detail)
        ui.log(f"> {node}", style="dim cyan")
    elif kind == "thinking":
        text = (event.get("text") or "").strip()
        if text:
            ui.bump_verb("Ruminating")
            ui.set_detail("model thinking")
            shown = text if len(text) <= 4000 else text[:4000] + "\n... [thinking truncated]"
            ui.panel(shown, title="thinking", border_style="blue")
    elif kind == "llm_token":
        pass
    elif kind == "assistant":
        text = (event.get("text") or "").strip()
        if text:
            ui.set_detail("drafting reply")
            ui.panel(Markdown(text), title="assistant", border_style="green")
    elif kind == "tool_call":
        name = event.get("name", "tool")
        args = event.get("args") or {}
        ui.bump_verb("Weaponizing")
        ui.set_detail(f"calling {name}")
        ui.panel(f"**{name}\n\n```\n{args}\n```", title="tool call", border_style="cyan")
    elif kind == "tool_result":
        name = event.get("name", "tool")
        content = str(event.get("content") or "")
        ui.bump_verb("Enumerating")
        ui.set_detail(f"{name} returned")
        border = "yellow" if any(
            s in content for s in ("BUDGET_EXCEEDED", "blocked_scope", "denied_hitl", "error")
        ) else "magenta"
        shown = content if len(content) <= 6000 else content[:6000] + "\n... [truncated]"
        ui.panel(shown, title=f"tool result · {name}", border_style=border)
    elif kind == "status":
        ui.set_detail(str(event.get("text") or ""))
        ui.log(f"• {event.get('text')}", style="dim")
    elif kind == "error":
        ui.panel(str(event.get("text") or "error"), title="error", border_style="red")
    elif kind == "plan":
        text = (event.get("text") or "").strip()
        if text:
            ui.bump_verb("Threat-modeling")
            ui.set_detail("planning")
            ui.panel(text, title="plan", border_style="yellow")
    elif kind == "decision":
        text = (event.get("text") or "").strip()
        if text:
            ui.bump_verb("Ruminating")
            ui.set_detail("deciding")
            ui.panel(text, title="decision", border_style="magenta")


EventSink = Callable[[dict[str, Any]], None]

__all__ = [
    "SECURITY_VERBS",
    "ActivityDisplay",
    "EventSink",
    "extract_reasoning",
    "messages_to_events",
    "render_stream_event",
]
