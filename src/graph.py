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

from langgraph.types import Command

from src.models import get_model_endpoints
from src.prompts import ORCHESTRATOR_SYSTEM_PROMPT
from src.tools.expert import (
    TOOL_NAME as CONSULT_TOOL_NAME,
    SpecialistBudget,
    consult_security_expert,
)
from src.memory.vectorstore import WorkspaceVectorStore
from src.tools.discovery import (
    TOOL_NAME as SEARCH_TOOLS_NAME,
    search_kali_tools,
)
from src.tools.terminal import (
    TOOL_NAME as EXECUTE_TOOL_NAME,
    execute_kali_command,
)
from src.workspace.manager import EngagementPhase, Workspace
from src.workspace.scope_guard import ScopeGuard

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
    scope_guard: ScopeGuard
    vectorstore: WorkspaceVectorStore
    seen_targets: list[str] = field(default_factory=list)
    tier2_confirmed: bool = False
    context_token_limit: int = 8000
    keep_recent_messages: int = 8
    command_timeout_seconds: float = 120.0
    _db_conn: sqlite3.Connection | None = field(default=None, repr=False)

    @property
    def raw_output_dir(self) -> Path:
        """Session directory for full unsummarized tool stdout/stderr."""
        path = self.workspace.sessions_dir / self.session_id / "raw_output"
        path.mkdir(parents=True, exist_ok=True)
        return path


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
        f"Available tools:\n"
        f"- {SEARCH_TOOLS_NAME}: find the right Kali tool and usage from manuals "
        "(call this when unsure which binary/flags to use).\n"
        f"- {EXECUTE_TOOL_NAME}: run a host CLI command (argv string). "
        "ScopeGuard + risk HITL gate execution in code.\n"
        f"- {CONSULT_TOOL_NAME}: deep CVE/exploit analysis via the specialist "
        f"(at most {runtime.budget.max_calls_per_turn} call(s) per reasoning step).\n"
        "Typical flow: search tools → format command → execute. "
        "Do not invent tool results. Never ask the operator to bypass scope or HITL."
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
    """Build the tool set available to the orchestrator for this session."""

    @tool(CONSULT_TOOL_NAME)
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
            CONSULT_TOOL_NAME,
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

    @tool(EXECUTE_TOOL_NAME)
    def execute_kali_command_tool(
        command: str,
        timeout_seconds: float = 120.0,
        background: bool = False,
    ) -> str:
        """
        Execute a host CLI command through ScopeGuard and risk-tier HITL.

        Pass the full command as a single string (e.g. ``nmap -sn 10.10.20.0/24``).
        Do not use shell metacharacters; arguments are parsed safely without a shell.

        Args:
            command: The command line to run.
            timeout_seconds: Max seconds before the process is killed (foreground).
            background: If true, start the process and return immediately with a pid.
        """
        timeout = timeout_seconds or runtime.command_timeout_seconds

        def _mark_targets(targets: list[str]) -> None:
            for target in targets:
                if target not in runtime.seen_targets:
                    runtime.seen_targets.append(target)

        def _mark_tier2() -> None:
            runtime.tier2_confirmed = True

        result = execute_kali_command(
            command,
            scope_guard=runtime.scope_guard,
            mode=runtime.workspace.mode,
            seen_targets=list(runtime.seen_targets),
            tier2_confirmed=runtime.tier2_confirmed,
            raw_output_dir=runtime.raw_output_dir,
            timeout_seconds=float(timeout),
            background=bool(background),
            on_targets_seen=_mark_targets,
            on_tier2_confirmed=_mark_tier2,
        )
        return result.as_tool_text()

    @tool(SEARCH_TOOLS_NAME)
    def search_kali_tools_tool(query: str, n_results: int = 5) -> str:
        """
        Search indexed Kali tool manuals (help text) for tools matching a need.

        Use when you need a network scanner, web fuzzer, SMB enum tool, etc.
        Then call execute_kali_command with a concrete command line.

        Args:
            query: Natural-language description of the needed capability.
            n_results: How many tool manuals to return (default 5).
        """
        return search_kali_tools(
            query,
            store=runtime.vectorstore,
            n_results=max(1, min(int(n_results), 10)),
        )

    return [search_kali_tools_tool, execute_kali_command_tool, consult_security_expert_tool]


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
        # Union checkpointed gates with anything tools mutated on the runtime.
        merged_targets = list(
            dict.fromkeys([*(state.get("seen_targets") or []), *runtime.seen_targets])
        )
        runtime.seen_targets = merged_targets
        runtime.tier2_confirmed = bool(state.get("tier2_confirmed")) or runtime.tier2_confirmed

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
            "seen_targets": list(runtime.seen_targets),
            "tier2_confirmed": runtime.tier2_confirmed,
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

    def pending_interrupts(self) -> list[Any]:
        """Return outstanding HITL interrupt payloads for this thread."""
        snap = self.graph.get_state(self.config())
        return list(getattr(snap, "interrupts", ()) or ())

    def invoke_turn(
        self,
        user_text: str,
        *,
        hitl_callback: Any | None = None,
    ) -> AgentState:
        """
        Run one operator turn through the ReAct graph, resolving HITL interrupts.

        ``hitl_callback`` receives the interrupt payload dict and must return
        ``\"approve\"`` or ``\"deny\"``. When omitted, interrupts surface to the
        caller via ``pending_interrupts()`` after a partial invoke (tests may
        resume manually with ``resume``).
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
            "seen_targets": list(self.runtime.seen_targets),
            "tier2_confirmed": self.runtime.tier2_confirmed,
        }
        result = self.graph.invoke(payload, config=self.config())
        return self._drain_interrupts(result, hitl_callback=hitl_callback)

    def resume(self, decision: str, *, hitl_callback: Any | None = None) -> AgentState:
        """Resume after a HITL interrupt with ``approve`` / ``deny``."""
        result = self.graph.invoke(Command(resume=decision), config=self.config())
        return self._drain_interrupts(result, hitl_callback=hitl_callback)

    def _drain_interrupts(
        self,
        result: dict[str, Any] | AgentState,
        *,
        hitl_callback: Any | None,
    ) -> AgentState:
        """Keep resuming while HITL interrupts are pending and a callback exists."""
        current: dict[str, Any] = dict(result)  # type: ignore[arg-type]
        while True:
            interrupts = self.pending_interrupts()
            if not interrupts:
                # Sync runtime from final state.
                self.runtime.seen_targets = list(current.get("seen_targets") or self.runtime.seen_targets)
                self.runtime.tier2_confirmed = bool(
                    current.get("tier2_confirmed", self.runtime.tier2_confirmed)
                )
                return current  # type: ignore[return-value]
            if hitl_callback is None:
                return current  # type: ignore[return-value]
            payload = interrupts[0].value
            if not isinstance(payload, dict):
                payload = {"raw": payload}
            decision = hitl_callback(payload)
            current = self.graph.invoke(
                Command(resume=decision),
                config=self.config(),
            )

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
    cmd_timeout = float(agent_cfg.get("command_timeout_seconds", 120))

    scope_guard = ScopeGuard.from_workspace(
        mode=workspace.mode,
        scope_yaml=workspace.scope_yaml if workspace.mode == "scoped" else None,
    )
    vectorstore = WorkspaceVectorStore(workspace.vectorstore_dir)

    runtime = GraphRuntime(
        workspace=workspace,
        session_id=session_id,
        phase=str(resolved_phase),
        orchestrator_model=workspace.models.get("orchestrator") or endpoints.orchestrator,
        specialist_model=workspace.models.get("specialist") or endpoints.specialist,
        budget=SpecialistBudget(max_calls_per_turn=endpoints.specialist_calls_per_turn),
        scope_guard=scope_guard,
        vectorstore=vectorstore,
        context_token_limit=limit,
        keep_recent_messages=keep_recent,
        command_timeout_seconds=cmd_timeout,
    )
    compiled = build_graph(runtime)
    return PotocusAgent(runtime=runtime, graph=compiled)


def valid_phases() -> list[str]:
    """Return engagement phase names."""
    return [p.value for p in EngagementPhase]
