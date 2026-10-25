"""Real LangGraph engine tests against local Ollama — no mocks."""

from __future__ import annotations

from pathlib import Path

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from src.graph import PotocusAgent, create_agent, estimate_tokens
from src.models import test_ollama_connection as probe_ollama
from src.tools.expert import TOOL_NAME
from src.workspace.manager import init_workspace


def _ready_or_skip() -> None:
    """Skip when Ollama/orchestrator is unavailable."""
    probe = probe_ollama(run_chat_probe=True)
    if not probe.ok:
        pytest.skip(f"ollama not ready: {probe.error}")


def test_estimate_tokens_grows_with_content() -> None:
    """Token heuristic scales with message size."""
    small = estimate_tokens([HumanMessage(content="abcd")])
    big = estimate_tokens([HumanMessage(content="abcd" * 100)])
    assert big > small


def test_create_agent_and_plain_turn(tmp_path: Path) -> None:
    """Compiled graph answers a plain question and checkpoints to disk."""
    _ready_or_skip()
    ws = init_workspace(tmp_path / "graph-lab", mode="unscoped", activate=False)
    # Create a session directory layout matching CLI.
    session_id = "testsession01"
    (ws.sessions_dir / session_id / "checkpoints").mkdir(parents=True)
    (ws.sessions_dir / session_id / "raw_output").mkdir(parents=True)

    agent = create_agent(ws, session_id=session_id, phase="RECON")
    try:
        state = agent.invoke_turn("Reply with exactly: graph-ok")
        text = agent.latest_ai_text(state).lower()
        assert "graph-ok" in text.replace(" ", "")
        assert state.get("phase") == "RECON"
        assert int(state.get("context_tokens_approx") or 0) > 0
        checkpoint = ws.sessions_dir / session_id / "checkpoints" / "langgraph.sqlite"
        assert checkpoint.exists()
        assert checkpoint.stat().st_size > 0
    finally:
        agent.close()


def test_agent_can_call_specialist_tool(tmp_path: Path) -> None:
    """Orchestrator can invoke consult_security_expert inside the ReAct loop."""
    _ready_or_skip()
    probe = probe_ollama(run_chat_probe=False)
    if not probe.specialist_present:
        pytest.skip("specialist model missing")

    ws = init_workspace(tmp_path / "graph-expert", mode="unscoped", activate=False)
    session_id = "testsession02"
    (ws.sessions_dir / session_id / "checkpoints").mkdir(parents=True)

    agent = create_agent(ws, session_id=session_id, phase="VULN_IDENTIFICATION")
    try:
        prompt = (
            f"You must call the {TOOL_NAME} tool with query exactly "
            "'Reply with exactly: specialist-via-graph'. "
            "After the tool returns, briefly confirm you received it."
        )
        state = agent.invoke_turn(prompt)
        messages = list(state.get("messages") or [])
        tool_names = []
        for msg in messages:
            if isinstance(msg, AIMessage) and msg.tool_calls:
                tool_names.extend(c.get("name") for c in msg.tool_calls)
        assert TOOL_NAME in tool_names, f"expected tool call, got messages={messages!r}"
        blob = " ".join(
            str(getattr(m, "content", "")) for m in messages
        ).lower()
        assert "specialist-via-graph" in blob.replace(" ", "")
    finally:
        agent.close()


def test_checkpoint_resume_keeps_history(tmp_path: Path) -> None:
    """Reopening the same session thread sees prior checkpointed messages."""
    _ready_or_skip()
    ws = init_workspace(tmp_path / "graph-resume", mode="unscoped", activate=False)
    session_id = "testsession03"
    (ws.sessions_dir / session_id / "checkpoints").mkdir(parents=True)

    agent = create_agent(ws, session_id=session_id, phase="RECON")
    try:
        agent.invoke_turn("Remember the codeword: orchid-42. Reply with: noted")
    finally:
        agent.close()

    agent2 = create_agent(ws, session_id=session_id, phase="RECON")
    try:
        state = agent2.invoke_turn("What codeword did I ask you to remember? Reply with just the codeword.")
        text = agent2.latest_ai_text(state).lower()
        assert "orchid-42" in text.replace(" ", "")
    finally:
        agent2.close()
