"""Ollama / OpenAI-compatible client initialization and health checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from openai import OpenAI

from src.utils.config import load_global_config


@dataclass(frozen=True)
class ModelEndpoints:
    """Resolved model + endpoint configuration (single security-expert model)."""

    base_url: str
    native_url: str
    primary: str
    temperature: float
    timeout_seconds: float
    context_window: int


def get_model_endpoints() -> ModelEndpoints:
    """Load model endpoints from global config (with env overrides).

    Potocus now uses a single security-expert model (``models.primary``)
    instead of a dual orchestrator/specialist pair.
    """
    cfg = load_global_config()
    ollama = cfg.get("ollama", {})
    models = cfg.get("models", {})
    return ModelEndpoints(
        base_url=str(ollama.get("base_url", "http://127.0.0.1:11434/v1")).rstrip("/"),
        native_url=str(ollama.get("native_url", "http://127.0.0.1:11434")).rstrip("/"),
        primary=str(models.get("primary", "hf.co/mradermacher/Cyber-Ornith-1.5-9B-OBLITERATED-GGUF:Q3_K_S")),
        temperature=float(models.get("temperature", 0.2)),
        timeout_seconds=float(ollama.get("timeout_seconds", 120)),
        context_window=int(models.get("context_window", 0)),
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


def list_local_models_detail() -> list[dict[str, Any]]:
    """List full model detail dicts from Ollama ``/api/tags`` (name, capabilities, context_length)."""
    endpoints = get_model_endpoints()
    url = f"{endpoints.native_url}/api/tags"
    with httpx.Client(timeout=endpoints.timeout_seconds) as client:
        response = client.get(url)
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
    return payload.get("models") or []


@dataclass(frozen=True)
class ConnectionTestResult:
    """Result of an Ollama connectivity + model availability check (single model)."""

    ok: bool
    native_url: str
    base_url: str
    available_models: list[str]
    primary_present: bool
    chat_ok: bool
    chat_preview: str
    context_window: int
    error: str | None = None


def test_ollama_connection(*, run_chat_probe: bool = True) -> ConnectionTestResult:
    """
    Verify Ollama is reachable and the configured primary model is available.

    Optionally sends a tiny chat completion to the primary model to confirm
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
            primary_present=False,
            chat_ok=False,
            chat_preview="",
            context_window=0,
            error=f"Failed to reach Ollama at {endpoints.native_url}: {exc}",
        )

    primary_ok = endpoints.primary in available

    # Probe Ollama /api/tags details for the advertised context window of the primary model.
    context_window = endpoints.context_window
    try:
        for detail in list_local_models_detail():
            if isinstance(detail, dict) and str(detail.get("name")) == endpoints.primary:
                context_window = int(detail.get("details", {}).get("context_length", 0) or 0)
                break
    except Exception:  # noqa: BLE001
        pass

    chat_ok = False
    chat_preview = ""
    error: str | None = None

    if run_chat_probe and primary_ok:
        try:
            client = get_openai_client()
            completion = client.chat.completions.create(
                model=endpoints.primary,
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
    elif run_chat_probe and not primary_ok:
        error = f"Primary model not found: {endpoints.primary}"

    ok = primary_ok and (chat_ok if run_chat_probe else True) and error is None
    if not primary_ok:
        error = (error + "; " if error else "") + f"Missing model: primary={endpoints.primary}"
    elif run_chat_probe and not chat_ok and not error:
        error = "Chat probe failed with empty response"

    return ConnectionTestResult(
        ok=ok,
        native_url=endpoints.native_url,
        base_url=endpoints.base_url,
        available_models=available,
        primary_present=primary_ok,
        chat_ok=chat_ok,
        chat_preview=chat_preview,
        context_window=context_window,
        error=error,
    )
