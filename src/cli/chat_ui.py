"""Fixed-position terminal UI for Potocus chat (security-themed).

Renders three fixed boxes — thinking, chat, terminal — plus a status line.
Content is kept in bounded line buffers so boxes stay in place instead of
scrolling the whole terminal. A live pseudo-terminal streams command output into
the terminal box while a command runs.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque

from rich.console import Console
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
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

BOX_LINES = 14


@dataclass
class ActivityDisplay:
    """
    Fixed-position Live layout:

      header   — status line (verb + detail)
      thinking — model reasoning / thinking
      chat     — assistant replies + tool results
      terminal — live command output while a command runs

    Boxes keep a bounded line buffer so they stay fixed on screen instead of
    scrolling the whole terminal. ``update()`` rewrites the Live renderable in
    place.
    """

    console: Console
    verbose: bool = True
    _verb: str = field(default_factory=lambda: __import__("random").choice(SECURITY_VERBS))
    _detail: str = "working"
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None
    _live: Live | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # Bounded line buffers for the three fixed boxes.
    thinking_lines: Deque[str] = field(default_factory=lambda: deque(maxlen=BOX_LINES))
    chat_lines: Deque[str] = field(default_factory=lambda: deque(maxlen=BOX_LINES))
    terminal_lines: Deque[str] = field(default_factory=lambda: deque(maxlen=BOX_LINES))

    # ------------------------------------------------------------------ render

    def _render(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(name="header", size=1),
            Layout(name="thinking", size=BOX_LINES + 2),
            Layout(name="chat", size=BOX_LINES + 2),
            Layout(name="terminal", size=BOX_LINES + 2),
        )

        def _box(title: str, lines: Deque[str], border: str) -> Panel:
            body = "\n".join(lines) if lines else "(empty)"
            return Panel(
                body,
                title=title,
                border_style=border,
                height=BOX_LINES + 2,
            )

        layout["header"].update(
            Panel(
                Text.assemble(
                    ("• ", "cyan bold"),
                    (self._verb, "cyan"),
                    ("  ", ""),
                    (self._detail, "dim"),
                ),
                border_style="cyan",
                height=1,
            )
        )
        layout["thinking"].update(_box("thinking", self.thinking_lines, "blue"))
        layout["chat"].update(_box("chat", self.chat_lines, "green"))
        layout["terminal"].update(_box("terminal", self.terminal_lines, "magenta"))
        return layout

    # ------------------------------------------------------------------ lifecycle

    def start(self, detail: str = "starting agent loop") -> None:
        """Begin the persistent fixed layout."""
        self._detail = detail
        self._stop.clear()
        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=4,
            transient=False,
        )
        self._live.start()

        def _rotate() -> None:
            while not self._stop.wait(1.6):
                with self._lock:
                    self._verb = __import__("random").choice(SECURITY_VERBS)
                if self._live is not None:
                    self._live.update(self._render())

        self._thread = threading.Thread(target=_rotate, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """End the Live layout (last frame stays on screen)."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        if self._live is not None:
            try:
                self._live.stop()
            except Exception:  # noqa: BLE001
                pass
        self._live = None

    def update(self) -> None:
        """Redraw the Live layout in place (call after mutating buffers)."""
        if self._live is not None:
            try:
                self._live.update(self._render())
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------ content

    def _append(self, target: Deque[str], text: str) -> None:
        with self._lock:
            for line in str(text).split("\n"):
                target.append(line)
        self.update()

    def set_detail(self, detail: str) -> None:
        self._detail = detail
        self.update()

    def bump_verb(self, verb: str | None = None) -> None:
        if verb:
            self._verb = verb
        self.update()

    def log(self, text: str, style: str = "dim") -> None:
        self._append(self.chat_lines, text)

    def panel(self, content: Any, title: str = "chat", border_style: str = "green") -> None:
        text = content if isinstance(content, str) else str(content)
        self._append(self.chat_lines, f"[{title}] {text}")

    def thinking(self, text: str) -> None:
        self._append(self.thinking_lines, text)

    def terminal(self, line: str, is_stderr: bool = False) -> None:
        prefix = "stderr> " if is_stderr else ""
        self._append(self.terminal_lines, prefix + line)

    def pause(self) -> None:
        """Stop Live while a blocking HITL prompt is shown."""
        self.stop()

    def resume(self, detail: str = "resuming") -> None:
        """Restart Live after a blocking HITL prompt."""
        self._detail = detail
        self.start(detail=detail)


def render_stream_event(ui: ActivityDisplay, event: dict[str, Any]) -> None:
    """Render one agent event into the fixed UI boxes."""
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
            ui.thinking(shown)
    elif kind == "llm_token":
        pass
    elif kind == "assistant":
        text = (event.get("text") or "").strip()
        if text:
            ui.set_detail("drafting reply")
            ui.panel(text, title="assistant", border_style="green")
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
    elif kind == "terminal_output":
        line = event.get("line", "")
        is_stderr = bool(event.get("is_stderr"))
        ui.set_detail("command output")
        ui.terminal(line, is_stderr=is_stderr)
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
    elif kind == "context_compacted":
        ui.set_detail("context compacted")
        ui.panel(
            str(event.get("text") or "[context_compacted]"),
            title="context",
            border_style="yellow",
        )


EventSink = Callable[[dict[str, Any]], None]

__all__ = [
    "SECURITY_VERBS",
    "ActivityDisplay",
    "EventSink",
    "render_stream_event",
]
