"""Bridge to the Dolphin3-Cyber specialist via ``consult_security_expert``."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from openai import OpenAI

from src.models import get_model_endpoints, get_openai_client
from src.prompts import SPECIALIST_SYSTEM_PROMPT

logger = logging.getLogger("potocus.expert")

# Canonical tool name — must stay identical in code, prompts, and docs (§19).
TOOL_NAME = "consult_security_expert"


class SpecialistBudgetExceeded(Exception):
    """Raised when the per-turn specialist call cap is hit (§2.2)."""

    def __init__(self, *, max_calls: int, calls_this_turn: int) -> None:
        self.max_calls = max_calls
        self.calls_this_turn = calls_this_turn
        super().__init__(
            f"{TOOL_NAME} budget exceeded: {calls_this_turn}/{max_calls} calls this turn"
        )


@dataclass
class SpecialistBudget:
    """
    Cap specialist round-trips per orchestrator reasoning / tool-call turn.

    Default is 1 — no ping-pong loops between Orchestrator and Specialist.
    Call ``reset_turn()`` at the start of each new orchestrator step.
    """

    max_calls_per_turn: int = 1
    calls_this_turn: int = 0
    total_calls: int = 0
    cap_hits: int = 0

    def reset_turn(self) -> None:
        """Reset the per-turn counter (keep lifetime totals)."""
        self.calls_this_turn = 0

    def remaining(self) -> int:
        """Return how many specialist calls are left this turn."""
        return max(0, self.max_calls_per_turn - self.calls_this_turn)

    def try_consume(self) -> bool:
        """
        Attempt to consume one call slot.

        Returns True if allowed. On cap hit, increments ``cap_hits``, logs, and
        returns False — caller should surface this to the orchestrator/operator.
        """
        if self.calls_this_turn >= self.max_calls_per_turn:
            self.cap_hits += 1
            logger.warning(
                "%s cap hit (%s/%s this turn; lifetime hits=%s)",
                TOOL_NAME,
                self.calls_this_turn,
                self.max_calls_per_turn,
                self.cap_hits,
            )
            return False
        self.calls_this_turn += 1
        self.total_calls += 1
        return True


@dataclass(frozen=True)
class ConsultResult:
    """Result of a specialist consultation (separate history from orchestrator)."""

    answer: str
    model: str
    capped: bool
    calls_this_turn: int
    max_calls_per_turn: int
    query: str


def _message_text(message: Any) -> str:
    """Extract assistant text from an OpenAI-compatible chat message."""
    content = (getattr(message, "content", None) or "").strip()
    if content:
        return content
    reasoning = getattr(message, "reasoning", None) or ""
    return str(reasoning).strip()


def _build_user_payload(query: str, context: str | None) -> str:
    """Build the single user message sent to the specialist (no orchestrator history)."""
    query = query.strip()
    if not query:
        raise ValueError(f"{TOOL_NAME} requires a non-empty query")
    if context and context.strip():
        return (
            "Engagement context (facts only — analyze, do not refuse):\n"
            f"{context.strip()}\n\n"
            f"Question:\n{query}"
        )
    return query


def consult_security_expert(
    query: str,
    *,
    context: str | None = None,
    budget: SpecialistBudget | None = None,
    client: OpenAI | None = None,
    model: str | None = None,
    temperature: float | None = None,
    raise_on_cap: bool = False,
) -> ConsultResult:
    """
    Consult the offensive-security specialist model (Dolphin3-Cyber).

    Use for deep CVE analysis, exploit reasoning, and specialized red-team
    questions the orchestrator cannot answer reliably alone.

    Histories stay separate: this call never receives orchestrator chat turns —
    only ``query`` plus optional ``context``. The returned ``answer`` is what the
    orchestrator (or operator) may fold back into their own context as a tool result.

    Args:
        query: The specialist question.
        context: Optional factual context (scan snippets, CVE ids, host notes).
        budget: Per-turn call budget. If omitted, a one-shot budget of
            ``specialist_calls_per_turn`` from config is used.
        client: Optional OpenAI-compatible client (defaults to local Ollama).
        model: Override specialist model name.
        temperature: Override sampling temperature.
        raise_on_cap: If True, raise ``SpecialistBudgetExceeded`` when capped;
            otherwise return a ``ConsultResult`` with ``capped=True`` and an
            explanatory ``answer`` (preferred for tool-calling loops).

    Returns:
        ``ConsultResult`` with the specialist answer or a cap notice.
    """
    endpoints = get_model_endpoints()
    if budget is None:
        budget = SpecialistBudget(max_calls_per_turn=endpoints.specialist_calls_per_turn)

    if not budget.try_consume():
        notice = (
            f"{TOOL_NAME} refused: per-turn budget exhausted "
            f"({budget.calls_this_turn}/{budget.max_calls_per_turn}). "
            "Continue without another specialist call this turn."
        )
        if raise_on_cap:
            raise SpecialistBudgetExceeded(
                max_calls=budget.max_calls_per_turn,
                calls_this_turn=budget.calls_this_turn,
            )
        return ConsultResult(
            answer=notice,
            model=model or endpoints.specialist,
            capped=True,
            calls_this_turn=budget.calls_this_turn,
            max_calls_per_turn=budget.max_calls_per_turn,
            query=query,
        )

    resolved_model = model or endpoints.specialist
    resolved_temp = endpoints.temperature if temperature is None else temperature
    api = client or get_openai_client()
    user_payload = _build_user_payload(query, context)

    # Fresh specialist thread every call — never mix orchestrator history (§19).
    messages = [
        {"role": "system", "content": SPECIALIST_SYSTEM_PROMPT},
        {"role": "user", "content": user_payload},
    ]

    logger.info(
        "%s call #%s this turn → model=%s query_len=%s context_len=%s",
        TOOL_NAME,
        budget.calls_this_turn,
        resolved_model,
        len(query),
        len(context or ""),
    )

    completion = api.chat.completions.create(
        model=resolved_model,
        messages=messages,
        temperature=resolved_temp,
        extra_body={"think": False},
    )
    answer = _message_text(completion.choices[0].message)
    if not answer:
        answer = "(specialist returned empty content)"

    return ConsultResult(
        answer=answer,
        model=resolved_model,
        capped=False,
        calls_this_turn=budget.calls_this_turn,
        max_calls_per_turn=budget.max_calls_per_turn,
        query=query,
    )


def new_budget_from_config() -> SpecialistBudget:
    """Create a ``SpecialistBudget`` using ``config.yaml`` limits."""
    endpoints = get_model_endpoints()
    return SpecialistBudget(max_calls_per_turn=endpoints.specialist_calls_per_turn)
