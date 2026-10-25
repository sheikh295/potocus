"""Tests for extract_reasoning helper (offline, no Ollama required)."""

from types import SimpleNamespace

from src.utils.llm_display import extract_reasoning


def test_direct_attribute():
    m = SimpleNamespace(reasoning="  deep thought  ")
    assert extract_reasoning(m) == "deep thought"


def test_additional_kwargs():
    m = SimpleNamespace(additional_kwargs={"thinking": "planning step"})
    assert extract_reasoning(m) == "planning step"


def test_reasoning_content_attr():
    m = SimpleNamespace(reasoning_content="r")
    assert extract_reasoning(m) == "r"


def test_response_metadata():
    m = SimpleNamespace(response_metadata={"reasoning": "meta-r"})
    assert extract_reasoning(m) == "meta-r"


def test_closed_think_tags():
    m = SimpleNamespace(content="<think>inner reasoning</think>answer")
    assert extract_reasoning(m) == "inner reasoning"


def test_unclosed_think_tag():
    m = SimpleNamespace(content="<think>still thinking")
    assert extract_reasoning(m) == "still thinking"


def test_unclosed_with_leading_whitespace():
    m = SimpleNamespace(content="  <think>  spaced  ")
    assert extract_reasoning(m) == "spaced"


def test_raw_openai_chunk():
    chunk = {"choices": [{"delta": {"reasoning": "token"}}]}
    assert extract_reasoning(chunk) == "token"


def test_raw_chunk_reasoning_content():
    chunk = {"choices": [{"delta": {"reasoning_content": "rc"}}]}
    assert extract_reasoning(chunk) == "rc"


def test_empty_returns_empty():
    m = SimpleNamespace(content="no tags here")
    assert extract_reasoning(m) == ""


def test_thinking_attr_direct():
    m = SimpleNamespace(thinking="t")
    assert extract_reasoning(m) == "t"