"""Helpers to surface model thinking / tool events in the CLI."""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage


def _get(obj: Any, *keys: str) -> Any:
    cur = obj
    for key in keys:
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(key)
        elif isinstance(cur, (list, tuple)):
            return None
        else:
            cur = getattr(cur, key, None)
    return cur



def extract_reasoning(message: Any, strip: bool = True) -> str:
    """Pull model 'thinking' / reasoning text from an AIMessage or chunk.

    Checks (in order):
      1. ``reasoning`` / ``reasoning_content`` attributes
      2. ``additional_kwargs`` for reasoning / reasoning_content / thinking
      3. ``response_metadata`` for reasoning / thinking
      4. ``<think>...</think>`` tags inside ``content`` (Qwen3 on Ollama streams
         reasoning wrapped in these tags)
    """
    # 0. Raw OpenAI / Ollama streaming chunk shape.
    choices = _get(message, "choices")
    if isinstance(choices, (list, tuple)) and choices:
        delta = _get(choices[0], "delta")
        if delta is not None:
            for key in ("reasoning", "reasoning_content", "thinking"):
                value = _get(delta, key)
                if isinstance(value, str) and value.strip():
                    return value.strip() if strip else value

    # 1. Direct attributes (AIMessage / AIMessageChunk)
    for attr in ("reasoning", "reasoning_content", "thinking"):
        value = _get(message, attr)
        if isinstance(value, str) and value.strip():
            return value.strip() if strip else value

    # 2. additional_kwargs
    additional = _get(message, "additional_kwargs") or {}
    if isinstance(additional, dict):
        for key in ("reasoning", "reasoning_content", "thinking"):
            value = additional.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip() if strip else value

    # 3. response_metadata
    meta = _get(message, "response_metadata") or {}
    if isinstance(meta, dict):
        for key in ("reasoning", "reasoning_content", "thinking"):
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip() if strip else value

    # 4. <think>...</think> tags inside content (Qwen3 / Ollama)
    content = _get(message, "content")
    if isinstance(content, str) and content.strip():
        import re
        match = re.search(r"<think>(.*?)</think>", content, re.DOTALL)
        if match:
            return match.group(1).strip() if strip else match.group(1)
        # Also handle unclosed <think> tag (streaming mid-thought)
        stripped = content.lstrip()
        if stripped.startswith("<think>"):
            inner = stripped[len("<think>") :]
            if inner.strip():
                return inner.strip() if strip else inner

    return ""


def messages_to_events(messages: list[BaseMessage]) -> list[dict[str, Any]]:
    """Convert graph messages into UI event dicts."""
    events: list[dict[str, Any]] = []
    for message in messages:
        if isinstance(message, AIMessage):
            reasoning = extract_reasoning(message)
            if reasoning:
                events.append({"type": "thinking", "text": reasoning})
            if message.tool_calls:
                for call in message.tool_calls:
                    events.append(
                        {
                            "type": "tool_call",
                            "name": call.get("name", "tool"),
                            "args": call.get("args", {}),
                            "id": call.get("id"),
                        }
                    )
            content = message.content
            text = content if isinstance(content, str) else str(content or "")
            if text.strip() and not message.tool_calls:
                events.append({"type": "assistant", "text": text.strip()})
            elif text.strip() and message.tool_calls:
                events.append({"type": "thinking", "text": f"(plan) {text.strip()}"})
        elif isinstance(message, ToolMessage):
            events.append(
                {
                    "type": "tool_result",
                    "name": message.name or "tool",
                    "content": message.content,
                }
            )
    return events
