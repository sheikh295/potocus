"""LangGraph ReAct engine — orchestrator loop, phase tracking, context budget."""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Sequence, TypedDict

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    RemoveMessage,
    SystemMessage,
    ToolMessage,
    message_chunk_to_message,
)
from langgraph.graph.message import REMOVE_ALL_MESSAGES
from langchain_core.tools import BaseTool, tool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from src.models import get_model_endpoints
from src.prompts import ORCHESTRATOR_SYSTEM_PROMPT
from src.tools.expert import (
    TOOL_NAME,
    SpecialistBudget,
    consult_security_expert,
)
from src.workspace.manager import EngagementPhase, Workspace

logger = logging.getLogger("potocus.graph")


class AgentState(TypedDict, total=False):
    """Per-session LangGraph state (§10, §12)."""

    messages: Annotated[list[BaseMessage], add_messages]
    phase: str
    context_tokens_approx: int
    specialist_calls_this_turn: int
    workspace_root: str
    session_id: str
    seen_targets: list[str]
    tier2_confirmed: bool


@dataclass
class GraphRuntime:
    """Mutable per-session runtime closed over by graph nodes and tools."""

    workspace: Workspace
    session_id: str
    phase: str
    orchestrator_model: str
    specialist_model: str
    budget: SpecialistBudget
    context_token_limit: int = 8000
    keep_recent_messages: int = 8
    _db_conn: sqlite3.Connection | None = field(default=None, repr=False)


def estimate_tokens(messages: Sequence[BaseMessage | dict[str, Any]]) -> int:
    """
    Approximate token usage for context budgeting.

    Uses a chars/4 heuristic — good enough to trigger compaction before an
    8B context window collapses; not a billing meter.
    """
    total_chars = 0
    for message in messages:
        if isinstance(message, BaseMessage):
            content = message.content
        elif isinstance(message, dict):
            content = message.get("content", "")
        else:
            content = str(message)
        if isinstance(content, str):
            total_chars += len(content)
        elif isinstance(content, list):
            total_chars += len(str(content))
        else:
            total_chars += len(str(content))
    return max(1, total_chars // 4)


def _build_system_prompt(runtime: GraphRuntime, phase: str) -> str:
    """Compose the orchestrator system prompt with live workspace/phase context."""
    ws = runtime.workspace
    return (
        f"{ORCHESTRATOR_SYSTEM_PROMPT}\n\n"
        f"Workspace: {ws.name}\n"
        f"Mode: {ws.mode}\n"
        f"Phase: {phase}\n"
        f"Pacing: {ws.pacing}\n"
        f"Available tools: {TOOL_NAME} "
        f"(at most {runtime.budget.max_calls_per_turn} call(s) per reasoning step).\n"
        "When you need deep offensive/CVE/exploit analysis, call "
        f"{TOOL_NAME}. Otherwise answer directly.\n"
        "Do not invent tool results. Scope and HITL are enforced outside the model."
    )


def _make_llm(model: str, temperature: float) -> ChatOpenAI:
    """OpenAI-compatible chat model pointed at local Ollama."""
    endpoints = get_model_endpoints()
    return ChatOpenAI(
        base_url=endpoints.base_url,
        api_key="ollama",
        model=model,
        temperature=temperature,
        timeout=endpoints.timeout_seconds,
        extra_body={"think": False},
    )


def build_tools(runtime: GraphRuntime) -> list[BaseTool]:
    """
    Build the tool set available to the orchestrator for this session.

    Phase 4 ships ``consult_security_expert``. Terminal execution lands next.
    """

    @tool(TOOL_NAME)
    def consult_security_expert_tool(query: str, context: str = "") -> str:
        """
        Consult the offensive-security specialist (Dolphin3-Cyber) for deep CVE
        analysis, exploit reasoning, or specialized red-team questions.

        Args:
            query: The specialist question.
            context: Optional factual context (scan notes, CVE ids, host data).
        """
        result = consult_security_expert(
            query,
            context=context or None,
            budget=runtime.budget,
            model=runtime.specialist_model,
        )
        logger.info(
            "%s capped=%s calls=%s/%s",
            TOOL_NAME,
            result.capped,
            result.calls_this_turn,
            result.max_calls_per_turn,
        )
        if result.capped:
            return (
                f"BUDGET_EXCEEDED: {result.answer} "
                "Do not call this tool again in the same reasoning step."
            )
        return result.answer

    return [consult_security_expert_tool]


def _checkpoint_path(workspace: Workspace, session_id: str) -> Path:
    """Return the SQLite checkpoint DB path for a session."""
    path = workspace.sessions_dir / session_id / "checkpoints" / "langgraph.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def build_graph(runtime: GraphRuntime) -> Any:
    """
    Compile the Potocus ReAct StateGraph for a workspace session.

    Flow: START → compact → agent → (tools ↔ agent)* → END
    """
    tools = build_tools(runtime)
    tool_node = ToolNode(tools)
    endpoints = get_model_endpoints()

    def compact_node(state: AgentState) -> dict[str, Any]:
        """Proactively summarize older turns before hitting the context ceiling."""
        messages = list(state.get("messages") or [])
        tokens = estimate_tokens(messages)
        limit = runtime.context_token_limit
        if tokens < limit or len(messages) <= runtime.keep_recent_messages + 1:
            return {"context_tokens_approx": tokens}

        keep = runtime.keep_recent_messages
        older = messages[:-keep] if keep < len(messages) else messages[:1]
        recent = messages[-keep:] if keep < len(messages) else messages[1:]

        digest_source = []
        for msg in older:
            role = getattr(msg, "type", msg.__class__.__name__)
            content = getattr(msg, "content", "")
            if isinstance(content, str) and content.strip():
                digest_source.append(f"{role}: {content[:800]}")
        digest_blob = "\n".join(digest_source)[:6000]

        summarizer = _make_llm(runtime.orchestrator_model, endpoints.temperature)
        summary = summarizer.invoke(
            [
                SystemMessage(
                    content=(
                        "Summarize prior engagement context for a penetration-testing "
                        "agent. Keep facts, hosts, findings, and decisions. Drop fluff."
                    )
                ),
                HumanMessage(content=digest_blob or "(empty)"),
            ]
        )
        summary_text = (
            summary.content
            if isinstance(summary.content, str)
            else str(summary.content)
        )
        compacted: list[BaseMessage] = [
            HumanMessage(
                content=f"[context_compacted]\n{summary_text}",
                name="potocus_compactor",
            ),
            *recent,
        ]
        new_tokens = estimate_tokens(compacted)
        logger.info(
            "context compacted %s → %s tokens (%s messages kept)",
            tokens,
            new_tokens,
            len(compacted),
        )
        return {
            "messages": [RemoveMessage(id=REMOVE_ALL_MESSAGES), *compacted],
            "context_tokens_approx": new_tokens,
        }

    def agent_node(state: AgentState) -> dict[str, Any]:
        """One orchestrator reasoning step (may request tools)."""
        runtime.budget.reset_turn()
        phase = str(state.get("phase") or runtime.phase)
        runtime.phase = phase

        llm = _make_llm(runtime.orchestrator_model, endpoints.temperature).bind_tools(
            tools
        )
        prior = list(state.get("messages") or [])
        # System prompt is injected each step so phase changes apply immediately.
        prompt = [SystemMessage(content=_build_system_prompt(runtime, phase)), *prior]
        response = llm.invoke(prompt)
        # Normalize streaming chunks if any.
        if not isinstance(response, AIMessage):
            response = message_chunk_to_message(response)

        all_for_estimate = prior + [response]
        return {
            "messages": [response],
            "specialist_calls_this_turn": runtime.budget.calls_this_turn,
            "context_tokens_approx": estimate_tokens(all_for_estimate),
            "phase": phase,
        }

    graph = StateGraph(AgentState)
    graph.add_node("compact", compact_node)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_edge(START, "compact")
    graph.add_edge("compact", "agent")
    graph.add_conditional_edges("agent", tools_condition, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")

    db_path = _checkpoint_path(runtime.workspace, runtime.session_id)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    checkpointer = SqliteSaver(conn)
    checkpointer.setup()
    runtime._db_conn = conn

    return graph.compile(checkpointer=checkpointer)


@dataclass
class PotocusAgent:
    """Compiled graph + runtime for one workspace session."""

    runtime: GraphRuntime
    graph: Any

    @property
    def thread_id(self) -> str:
        """LangGraph thread id (= session id)."""
        return self.runtime.session_id

    def config(self) -> dict[str, Any]:
        """Invoke/stream config with checkpoint thread id."""
        return {"configurable": {"thread_id": self.thread_id}}

    def invoke_turn(self, user_text: str) -> AgentState:
        """
        Run one operator turn through the ReAct graph.

        Persists checkpoint state under the session's checkpoints directory.
        """
        text = user_text.strip()
        if not text:
            raise ValueError("Empty user message")

        payload: dict[str, Any] = {
            "messages": [HumanMessage(content=text)],
            "phase": self.runtime.phase,
            "workspace_root": str(self.runtime.workspace.root),
            "session_id": self.runtime.session_id,
            "specialist_calls_this_turn": 0,
            "seen_targets": [],
            "tier2_confirmed": False,
        }
        result = self.graph.invoke(payload, config=self.config())
        return result  # type: ignore[return-value]

    def latest_ai_text(self, state: AgentState) -> str:
        """Return the latest non-tool AI message content."""
        for message in reversed(list(state.get("messages") or [])):
            if isinstance(message, AIMessage) and not message.tool_calls:
                content = message.content
                return content if isinstance(content, str) else str(content)
        return ""

    def tool_messages(self, state: AgentState) -> list[ToolMessage]:
        """Return tool result messages from the state (for CLI display)."""
        return [m for m in (state.get("messages") or []) if isinstance(m, ToolMessage)]

    def close(self) -> None:
        """Close the checkpoint SQLite connection."""
        if self.runtime._db_conn is not None:
            self.runtime._db_conn.close()
            self.runtime._db_conn = None


def create_agent(
    workspace: Workspace,
    *,
    session_id: str,
    phase: str | EngagementPhase | None = None,
    context_token_limit: int | None = None,
) -> PotocusAgent:
    """
    Create a compiled Potocus agent for a workspace session.

    Model names prefer workspace.yaml overrides, then global config.
    """
    endpoints = get_model_endpoints()
    resolved_phase = (
        phase.value
        if isinstance(phase, EngagementPhase)
        else (phase or EngagementPhase.RECON.value)
    )
    from src.utils.config import load_global_config

    cfg = load_global_config()
    agent_cfg = cfg.get("agent", {})
    limit = (
        context_token_limit
        if context_token_limit is not None
        else int(agent_cfg.get("context_token_limit", 8000))
    )
    keep_recent = int(agent_cfg.get("keep_recent_messages", 8))

    runtime = GraphRuntime(
        workspace=workspace,
        session_id=session_id,
        phase=str(resolved_phase),
        orchestrator_model=workspace.models.get("orchestrator") or endpoints.orchestrator,
        specialist_model=workspace.models.get("specialist") or endpoints.specialist,
        budget=SpecialistBudget(max_calls_per_turn=endpoints.specialist_calls_per_turn),
        context_token_limit=limit,
        keep_recent_messages=keep_recent,
    )
    compiled = build_graph(runtime)
    return PotocusAgent(runtime=runtime, graph=compiled)


def valid_phases() -> list[str]:
    """Return engagement phase names."""
    return [p.value for p in EngagementPhase]
