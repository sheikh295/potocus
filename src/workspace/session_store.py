"""Session metadata + LangGraph checkpoint inspection helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from src.workspace.manager import Workspace


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def session_dir(workspace: Workspace, session_id: str) -> Path:
    """Return the on-disk directory for a session."""
    return workspace.sessions_dir / session_id


def session_yaml_path(workspace: Workspace, session_id: str) -> Path:
    """Return path to ``session.yaml``."""
    return session_dir(workspace, session_id) / "session.yaml"


def checkpoint_db_path(workspace: Workspace, session_id: str) -> Path:
    """Return path to the LangGraph SQLite checkpoint DB."""
    return session_dir(workspace, session_id) / "checkpoints" / "langgraph.sqlite"


def read_session_meta(workspace: Workspace, session_id: str) -> dict[str, Any]:
    """Load session.yaml; raises FileNotFoundError if missing."""
    path = session_yaml_path(workspace, session_id)
    if not path.exists():
        raise FileNotFoundError(f"Unknown session: {session_id}")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        data = {}
    data["id"] = session_id
    return data


def write_session_meta(workspace: Workspace, session_id: str, meta: dict[str, Any]) -> None:
    """Persist session.yaml."""
    path = session_yaml_path(workspace, session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(meta)
    payload["id"] = session_id
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, default_flow_style=False, sort_keys=False)


def touch_session(
    workspace: Workspace,
    session_id: str,
    **updates: Any,
) -> dict[str, Any]:
    """
    Merge updates into session.yaml and bump ``updated_at``.

    Common keys: phase, target_focus, status, pacing, message_count.
    """
    meta = read_session_meta(workspace, session_id)
    for key, value in updates.items():
        if value is not None:
            meta[key] = value
    meta["updated_at"] = _utcnow()
    write_session_meta(workspace, session_id, meta)
    return meta


def list_session_ids(workspace: Workspace) -> list[str]:
    """Return session ids that have a session.yaml."""
    if not workspace.sessions_dir.exists():
        return []
    ids: list[str] = []
    for entry in sorted(workspace.sessions_dir.iterdir()):
        if entry.is_dir() and (entry / "session.yaml").exists():
            ids.append(entry.name)
    return ids


@dataclass(frozen=True)
class CheckpointSnapshot:
    """Summary of LangGraph checkpoint state for a session."""

    exists: bool
    message_count: int = 0
    phase: str | None = None
    context_tokens_approx: int = 0
    seen_targets: tuple[str, ...] = ()
    tier2_confirmed: bool = False
    pending_interrupt: bool = False
    path: str | None = None


def inspect_checkpoint(workspace: Workspace, session_id: str) -> CheckpointSnapshot:
    """
    Open the session's compiled graph and read the latest checkpoint values.

    Safe to call when no checkpoint exists yet (returns ``exists=False``).
    """
    db_path = checkpoint_db_path(workspace, session_id)
    if not db_path.exists() or db_path.stat().st_size == 0:
        return CheckpointSnapshot(exists=False, path=str(db_path))

    # Lazy import to avoid circular import at module load.
    from src.graph import create_agent

    meta = read_session_meta(workspace, session_id)
    agent = create_agent(
        workspace,
        session_id=session_id,
        phase=str(meta.get("phase") or "RECON"),
    )
    try:
        snap = agent.graph.get_state(agent.config())
        values = snap.values if snap else {}
        messages = list(values.get("messages") or [])
        interrupts = list(getattr(snap, "interrupts", ()) or ())
        targets = tuple(values.get("seen_targets") or ())
        return CheckpointSnapshot(
            exists=True,
            message_count=len(messages),
            phase=str(values.get("phase")) if values.get("phase") else None,
            context_tokens_approx=int(values.get("context_tokens_approx") or 0),
            seen_targets=targets,
            tier2_confirmed=bool(values.get("tier2_confirmed")),
            pending_interrupt=bool(interrupts),
            path=str(db_path),
        )
    finally:
        agent.close()


def sync_meta_from_checkpoint(
    workspace: Workspace,
    session_id: str,
) -> tuple[dict[str, Any], CheckpointSnapshot]:
    """
    Pull phase / message_count from the checkpoint into session.yaml.

    Returns the updated meta and the snapshot.
    """
    snap = inspect_checkpoint(workspace, session_id)
    updates: dict[str, Any] = {
        "message_count": snap.message_count,
        "checkpoint_exists": snap.exists,
    }
    if snap.phase:
        updates["phase"] = snap.phase
    if snap.seen_targets:
        updates["last_seen_targets"] = list(snap.seen_targets)
    meta = touch_session(workspace, session_id, **updates)
    return meta, snap
