"""Real specialist-bridge tests — budget logic + live Ollama dual-model call."""

from __future__ import annotations

import pytest

from src.models import get_model_endpoints, list_local_models
from src.models import test_ollama_connection as probe_ollama
from src.tools.expert import (
    TOOL_NAME,
    SpecialistBudget,
    SpecialistBudgetExceeded,
    consult_security_expert,
    new_budget_from_config,
)


def test_tool_name_is_canonical() -> None:
    """Tool name must stay stable across code/prompts/docs."""
    assert TOOL_NAME == "consult_security_expert"


def test_budget_allows_one_then_caps() -> None:
    """Per-turn budget of 1 allows the first call and blocks the second."""
    budget = SpecialistBudget(max_calls_per_turn=1)
    assert budget.try_consume() is True
    assert budget.calls_this_turn == 1
    assert budget.try_consume() is False
    assert budget.cap_hits == 1
    assert budget.total_calls == 1


def test_budget_reset_turn() -> None:
    """reset_turn clears the per-turn counter but keeps totals."""
    budget = SpecialistBudget(max_calls_per_turn=1)
    assert budget.try_consume() is True
    budget.reset_turn()
    assert budget.calls_this_turn == 0
    assert budget.total_calls == 1
    assert budget.try_consume() is True
    assert budget.total_calls == 2


def test_consult_respects_cap_without_raising() -> None:
    """Second consult in one turn returns capped=True without calling the model."""
    budget = SpecialistBudget(max_calls_per_turn=1)
    # Force-consume the slot without a model call.
    assert budget.try_consume() is True
    result = consult_security_expert(
        "should not reach the model",
        budget=budget,
        raise_on_cap=False,
    )
    assert result.capped is True
    assert TOOL_NAME in result.answer
    assert "budget exhausted" in result.answer


def test_consult_raise_on_cap() -> None:
    """raise_on_cap=True surfaces SpecialistBudgetExceeded."""
    budget = SpecialistBudget(max_calls_per_turn=1)
    assert budget.try_consume() is True
    with pytest.raises(SpecialistBudgetExceeded):
        consult_security_expert("nope", budget=budget, raise_on_cap=True)


def test_empty_query_rejected() -> None:
    """Empty specialist queries are invalid."""
    with pytest.raises(ValueError, match="non-empty"):
        consult_security_expert("   ", budget=SpecialistBudget(max_calls_per_turn=1))


def test_new_budget_from_config() -> None:
    """Budget picks up specialist_calls_per_turn from config.yaml."""
    endpoints = get_model_endpoints()
    budget = new_budget_from_config()
    assert budget.max_calls_per_turn == endpoints.specialist_calls_per_turn
    assert budget.max_calls_per_turn >= 1


def test_live_specialist_consult() -> None:
    """Live call to Dolphin3-Cyber via the OpenAI-compatible Ollama endpoint."""
    probe = probe_ollama(run_chat_probe=False)
    if not probe.specialist_present:
        pytest.skip(f"specialist model missing: {probe.error}")

    endpoints = get_model_endpoints()
    assert endpoints.specialist in list_local_models()

    budget = SpecialistBudget(max_calls_per_turn=1)
    result = consult_security_expert(
        "Reply with exactly: specialist-ok",
        budget=budget,
    )
    assert result.capped is False
    assert result.model == endpoints.specialist
    assert len(result.answer) > 0
    # Model may add punctuation/whitespace; require the marker somewhere.
    assert "specialist-ok" in result.answer.lower().replace(" ", "")


def test_live_dual_model_and_budget_cap() -> None:
    """Orchestrator + specialist both reachable; second specialist call is capped."""
    probe = probe_ollama(run_chat_probe=True)
    if not probe.ok:
        pytest.skip(f"ollama not ready: {probe.error}")

    budget = SpecialistBudget(max_calls_per_turn=1)
    first = consult_security_expert(
        "In one short sentence: what is a CVE identifier?",
        budget=budget,
    )
    assert first.capped is False
    assert len(first.answer) > 10

    second = consult_security_expert(
        "This second call must be blocked by budget.",
        budget=budget,
    )
    assert second.capped is True
    assert budget.cap_hits == 1
