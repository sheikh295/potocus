"""Global and environment-aware configuration loading."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

# Project root = repo root (parent of src/)
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
GLOBAL_CONFIG_PATH: Path = PROJECT_ROOT / "config.yaml"
GLOBAL_STATE_DIR: Path = Path.home() / ".potocus"
GLOBAL_STATE_PATH: Path = GLOBAL_STATE_DIR / "state.yaml"


def load_env() -> None:
    """Load ``.env`` from the project root if present."""
    load_dotenv(PROJECT_ROOT / ".env", override=False)


def _read_yaml(path: Path) -> dict[str, Any]:
    """Read a YAML file into a dict; return empty dict if missing."""
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected mapping in {path}, got {type(data).__name__}")
    return data


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    """Write a dict to YAML, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, default_flow_style=False, sort_keys=False)


def load_global_config() -> dict[str, Any]:
    """
    Load ``config.yaml`` and apply environment overrides.

    Environment variables (secrets / runtime overrides):
      - POTOCUS_OLLAMA_BASE_URL
      - POTOCUS_OLLAMA_NATIVE_URL
    """
    load_env()
    config = _read_yaml(GLOBAL_CONFIG_PATH)
    if not config:
        raise FileNotFoundError(f"Missing global config at {GLOBAL_CONFIG_PATH}")

    ollama = config.setdefault("ollama", {})
    if base := os.getenv("POTOCUS_OLLAMA_BASE_URL"):
        ollama["base_url"] = base.rstrip("/")
    if native := os.getenv("POTOCUS_OLLAMA_NATIVE_URL"):
        ollama["native_url"] = native.rstrip("/")

    return config


def load_active_state() -> dict[str, Any]:
    """Load active workspace/session pointers from ``~/.potocus/state.yaml``."""
    return _read_yaml(GLOBAL_STATE_PATH)


def save_active_state(state: dict[str, Any]) -> None:
    """Persist active workspace/session pointers."""
    GLOBAL_STATE_DIR.mkdir(parents=True, exist_ok=True)
    _write_yaml(GLOBAL_STATE_PATH, state)


def get_active_workspace_path() -> Path | None:
    """Return the active workspace root, or None if unset."""
    state = load_active_state()
    raw = state.get("workspace")
    if not raw:
        return None
    return Path(raw).expanduser().resolve()


def set_active_workspace(path: Path) -> None:
    """Set the active workspace root path."""
    state = load_active_state()
    state["workspace"] = str(path.resolve())
    # Switching workspace clears the active session pointer.
    state["session"] = None
    save_active_state(state)


def get_active_session_id() -> str | None:
    """Return the active session id within the current workspace, or None."""
    state = load_active_state()
    raw = state.get("session")
    return str(raw) if raw else None


def set_active_session(session_id: str | None) -> None:
    """Set (or clear) the active session id."""
    state = load_active_state()
    state["session"] = session_id
    save_active_state(state)
