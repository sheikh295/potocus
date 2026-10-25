"""LangGraph HITL interrupt tests for execute_kali_command — no mocks."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, TypedDict

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.types import Command

from src.graph import create_agent
from src.models import test_ollama_connection as probe_ollama
from src.tools.terminal import TOOL_NAME as EXECUTE_TOOL_NAME
from src.tools.terminal import execute_kali_command
from src.workspace.manager import init_workspace
from src.workspace.scope_guard import ScopeGuard


def _session(ws, session_id: str) -> None:
    (ws.sessions_dir / session_id / "checkpoints").mkdir(parents=True)
    (ws.sessions_dir / session_id / "raw_output").mkdir(parents=True)


def test_tier3_interrupt_then_resume_approve(tmp_path: Path) -> None:
    """Tier-3 commands pause the graph via interrupt; resume approve continues."""
    raw = tmp_path / "raw"
    guard = ScopeGuard(mode="unscoped", allowlist=[])

    @tool(EXECUTE_TOOL_NAME)
    def exec_tool(command: str) -> str:
        """Execute a gated command."""
        result = execute_kali_command(
            command,
            scope_guard=guard,
            mode="unscoped",
            seen_targets=[],
            tier2_confirmed=False,
            raw_output_dir=raw,
        )
        return result.as_tool_text()

    class S(TypedDict):
        messages: Annotated[list, add_messages]

    def agent(_state: S) -> dict:
        return {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": EXECUTE_TOOL_NAME,
                            "args": {"command": "hydra -h"},
                            "id": "t2",
                            "type": "tool_call",
                        }
                    ],
                )
            ]
        }

    graph = StateGraph(S)
    graph.add_node("agent", agent)
    graph.add_node("tools", ToolNode([exec_tool]))
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", tools_condition)
    graph.add_edge("tools", END)
    app = graph.compile(checkpointer=MemorySaver())
    cfg = {"configurable": {"thread_id": "hitl-tier3"}}

    out = app.invoke({"messages": [HumanMessage(content="go")]}, cfg)
    interrupts = out.get("__interrupt__") or app.get_state(cfg).interrupts
    assert interrupts, "expected HITL interrupt for Tier-3 hydra"
    payload = interrupts[0].value
    assert payload["tier"] == "tier3"
    assert "hydra" in payload["command_display"]

    final = app.invoke(Command(resume="approve"), cfg)
    tool_msgs = [m for m in final["messages"] if isinstance(m, ToolMessage)]
    assert tool_msgs
    assert "denied_hitl" not in tool_msgs[-1].content
    assert "status=" in tool_msgs[-1].content


def test_tier3_interrupt_deny(tmp_path: Path) -> None:
    """Operator deny returns denied_hitl without executing."""
    raw = tmp_path / "raw"
    guard = ScopeGuard(mode="unscoped", allowlist=[])

    @tool(EXECUTE_TOOL_NAME)
    def exec_tool(command: str) -> str:
        """Execute a gated command."""
        result = execute_kali_command(
            command,
            scope_guard=guard,
            mode="unscoped",
            seen_targets=[],
            tier2_confirmed=False,
            raw_output_dir=raw,
        )
        return result.as_tool_text()

    class S(TypedDict):
        messages: Annotated[list, add_messages]

    def agent(_state: S) -> dict:
        return {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": EXECUTE_TOOL_NAME,
                            "args": {"command": "msfconsole -h"},
                            "id": "t3",
                            "type": "tool_call",
                        }
                    ],
                )
            ]
        }

    graph = StateGraph(S)
    graph.add_node("agent", agent)
    graph.add_node("tools", ToolNode([exec_tool]))
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", tools_condition)
    graph.add_edge("tools", END)
    app = graph.compile(checkpointer=MemorySaver())
    cfg = {"configurable": {"thread_id": "hitl-deny"}}
    app.invoke({"messages": [HumanMessage(content="go")]}, cfg)
    final = app.invoke(Command(resume="deny"), cfg)
    tool_msgs = [m for m in final["messages"] if isinstance(m, ToolMessage)]
    assert tool_msgs
    assert "denied_hitl" in tool_msgs[-1].content


def test_agent_execute_echo_via_llm(tmp_path: Path) -> None:
    """Live orchestrator calls execute_kali_command for a safe Tier-1 command."""
    probe = probe_ollama(run_chat_probe=True)
    if not probe.ok:
        pytest.skip(f"ollama not ready: {probe.error}")

    ws = init_workspace(tmp_path / "hitl-lab", mode="unscoped", activate=False)
    session_id = "sesshitl01"
    _session(ws, session_id)
    agent = create_agent(ws, session_id=session_id, phase="RECON")
    try:
        state = agent.invoke_turn(
            f"Call {EXECUTE_TOOL_NAME} with command exactly: echo potocus-exec. "
            "Then quote the stdout in your final answer.",
            hitl_callback=lambda _p: "approve",
        )
        blob = " ".join(str(getattr(m, "content", "")) for m in state.get("messages", []))
        assert "potocus-exec" in blob
        raw_files = list((ws.sessions_dir / session_id / "raw_output").glob("*.txt"))
        assert raw_files, "expected raw_output archival"
    finally:
        agent.close()
