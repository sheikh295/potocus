"""Ollama / OpenAI-compatible client initialization and health checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from openai import OpenAI

from src.utils.config import load_global_config


@dataclass(frozen=True)
class ModelEndpoints:
    """Resolved model + endpoint configuration."""

    base_url: str
    native_url: str
    orchestrator: str
    specialist: str
    temperature: float
    timeout_seconds: float
    specialist_calls_per_turn: int


def get_model_endpoints() -> ModelEndpoints:
    """Load model endpoints from global config (with env overrides)."""
    cfg = load_global_config()
    ollama = cfg.get("ollama", {})
    models = cfg.get("models", {})
    return ModelEndpoints(
        base_url=str(ollama.get("base_url", "http://127.0.0.1:11434/v1")).rstrip("/"),
        native_url=str(ollama.get("native_url", "http://127.0.0.1:11434")).rstrip("/"),
        orchestrator=str(models.get("orchestrator", "qwen3:8b")),
        specialist=str(
            models.get(
                "specialist",
                "hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M",
            )
        ),
        temperature=float(models.get("temperature", 0.2)),
        timeout_seconds=float(ollama.get("timeout_seconds", 120)),
        specialist_calls_per_turn=int(models.get("specialist_calls_per_turn", 1)),
    )


def get_openai_client() -> OpenAI:
    """
    Return an OpenAI SDK client pointed at the local Ollama OpenAI-compatible API.

    Ollama does not require a real API key; a placeholder satisfies the SDK.
    """
    endpoints = get_model_endpoints()
    return OpenAI(
        base_url=endpoints.base_url,
        api_key="ollama",
        timeout=endpoints.timeout_seconds,
    )


def list_local_models() -> list[str]:
    """List model names available via the native Ollama ``/api/tags`` endpoint."""
    endpoints = get_model_endpoints()
    url = f"{endpoints.native_url}/api/tags"
    with httpx.Client(timeout=endpoints.timeout_seconds) as client:
        response = client.get(url)
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
    models = payload.get("models") or []
    names: list[str] = []
    for item in models:
        if isinstance(item, dict) and item.get("name"):
            names.append(str(item["name"]))
    return names


@dataclass(frozen=True)
class ConnectionTestResult:
    """Result of an Ollama connectivity + model availability check."""

    ok: bool
    native_url: str
    base_url: str
    available_models: list[str]
    orchestrator_present: bool
    specialist_present: bool
    chat_ok: bool
    chat_preview: str
    error: str | None = None


def test_ollama_connection(*, run_chat_probe: bool = True) -> ConnectionTestResult:
    """
    Verify Ollama is reachable and both configured models are available.

    Optionally sends a tiny chat completion to the orchestrator to confirm
    the OpenAI-compatible endpoint works end-to-end.
    """
    endpoints = get_model_endpoints()
    try:
        available = list_local_models()
    except Exception as exc:  # noqa: BLE001 — surface any connectivity failure cleanly
        return ConnectionTestResult(
            ok=False,
            native_url=endpoints.native_url,
            base_url=endpoints.base_url,
            available_models=[],
            orchestrator_present=False,
            specialist_present=False,
            chat_ok=False,
            chat_preview="",
            error=f"Failed to reach Ollama at {endpoints.native_url}: {exc}",
        )

    orch_ok = endpoints.orchestrator in available
    spec_ok = endpoints.specialist in available

    chat_ok = False
    chat_preview = ""
    error: str | None = None

    if run_chat_probe and orch_ok:
        try:
            client = get_openai_client()
            # Qwen3 may spend tokens on a `reasoning` channel before content;
            # give it enough headroom and prefer think=False when the backend supports it.
            completion = client.chat.completions.create(
                model=endpoints.orchestrator,
                messages=[
                    {
                        "role": "user",
                        "content": "Reply with exactly: potocus-ok",
                    }
                ],
                temperature=0,
                max_tokens=256,
                extra_body={"think": False},
            )
            message = completion.choices[0].message
            chat_preview = (message.content or "").strip()
            if not chat_preview:
                reasoning = getattr(message, "reasoning", None) or ""
                chat_preview = str(reasoning).strip()[:120]
            chat_ok = bool(chat_preview)
            if not chat_ok:
                error = "Chat probe returned empty content"
        except Exception as exc:  # noqa: BLE001
            error = f"Chat probe failed: {exc}"
    elif run_chat_probe and not orch_ok:
        error = f"Orchestrator model not found: {endpoints.orchestrator}"

    ok = orch_ok and spec_ok and (chat_ok if run_chat_probe else True) and error is None
    if not orch_ok or not spec_ok:
        missing = []
        if not orch_ok:
            missing.append(f"orchestrator={endpoints.orchestrator}")
        if not spec_ok:
            missing.append(f"specialist={endpoints.specialist}")
        error = (error + "; " if error else "") + "Missing models: " + ", ".join(missing)
    elif run_chat_probe and not chat_ok and not error:
        error = "Chat probe failed with empty response"

    return ConnectionTestResult(
        ok=ok,
        native_url=endpoints.native_url,
        base_url=endpoints.base_url,
        available_models=available,
        orchestrator_present=orch_ok,
        specialist_present=spec_ok,
        chat_ok=chat_ok,
        chat_preview=chat_preview,
        error=error,
    )
