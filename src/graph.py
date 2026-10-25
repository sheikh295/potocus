"""LangGraph agent state types.

The ReAct graph itself is built when the tool + HITL loop lands — this module
only defines shared state types used across the harness.
"""

from __future__ import annotations

from typing import Any, TypedDict

from src.workspace.manager import EngagementPhase


class AgentState(TypedDict, total=False):
    """Per-session agent state carried through the LangGraph loop."""

    messages: list[Any]
    phase: EngagementPhase
    context_tokens_approx: int
    specialist_calls_this_turn: int
    workspace_root: str
    session_id: str
    seen_targets: list[str]
    tier2_confirmed: bool
