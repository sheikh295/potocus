"""Workspace init/load and directory layout enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import yaml

from src.utils.config import load_global_config, set_active_workspace

Mode = Literal["scoped", "unscoped"]
Pacing = Literal["stealth", "normal", "aggressive"]


class WorkspaceError(Exception):
    """Raised when workspace operations fail."""


class EngagementPhase(str, Enum):
    """Engagement phase state machine (§12)."""

    RECON = "RECON"
    ENUMERATION = "ENUMERATION"
    VULN_IDENTIFICATION = "VULN_IDENTIFICATION"
    EXPLOITATION = "EXPLOITATION"
    POST_EXPLOITATION = "POST_EXPLOITATION"
    REPORTING = "REPORTING"


@dataclass(frozen=True)
class Workspace:
    """In-memory representation of a Potocus workspace."""

    root: Path
    name: str
    mode: Mode
    output_dir: Path
    pacing: Pacing
    created_at: str
    models: dict[str, str]

    @property
    def potocus_dir(self) -> Path:
        """Return the ``.potocus`` metadata directory."""
        return self.root / ".potocus"

    @property
    def workspace_yaml(self) -> Path:
        """Return path to ``workspace.yaml``."""
        return self.potocus_dir / "workspace.yaml"

    @property
    def scope_yaml(self) -> Path:
        """Return path to ``scope.yaml`` (scoped mode only)."""
        return self.potocus_dir / "scope.yaml"

    @property
    def findings_db(self) -> Path:
        """Return path to the findings SQLite database."""
        return self.potocus_dir / "findings.db"

    @property
    def vectorstore_dir(self) -> Path:
        """Return path to the workspace-scoped ChromaDB directory."""
        return self.potocus_dir / "vectorstore"

    @property
    def sessions_dir(self) -> Path:
        """Return path to the sessions directory."""
        return self.potocus_dir / "sessions"

    @property
    def log_path(self) -> Path:
        """Return path to the workspace audit log."""
        return self.potocus_dir / "potocus.log"


def _read_yaml(path: Path) -> dict[str, Any]:
    """Read YAML into a dict."""
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise WorkspaceError(f"Expected mapping in {path}")
    return data


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    """Write a dict as YAML."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, default_flow_style=False, sort_keys=False)


def _ensure_layout(root: Path, mode: Mode, output_dir: Path) -> None:
    """Create the full workspace directory layout from §5.1."""
    potocus = root / ".potocus"
    (potocus / "vectorstore").mkdir(parents=True, exist_ok=True)
    (potocus / "sessions").mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    from src.memory.findings_db import FindingsDB

    FindingsDB(potocus / "findings.db").close()
    (potocus / "potocus.log").touch(exist_ok=True)
    if mode == "scoped":
        scope_path = potocus / "scope.yaml"
        if not scope_path.exists():
            _write_yaml(
                scope_path,
                {
                    "targets": [],
                    "notes": "Add targets with `potocus scope add`.",
                },
            )


def init_workspace(
    path: Path,
    *,
    mode: Mode = "scoped",
    output_dir: Path | None = None,
    pacing: Pacing | None = None,
    name: str | None = None,
    activate: bool = True,
) -> Workspace:
    """
    Initialize a new workspace at ``path``.

    Creates ``.potocus/`` layout, writes ``workspace.yaml``, and optionally
    sets this workspace as the active context.
    """
    root = path.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)

    potocus_marker = root / ".potocus" / "workspace.yaml"
    if potocus_marker.exists():
        raise WorkspaceError(f"Workspace already exists at {root}")

    global_cfg = load_global_config()
    models_cfg = global_cfg.get("models", {})
    defaults = global_cfg.get("defaults", {})

    resolved_output = (output_dir or Path(defaults.get("output_dir", "./reports")))
    if not resolved_output.is_absolute():
        resolved_output = (root / resolved_output).resolve()

    resolved_pacing: Pacing = pacing or defaults.get("pacing", "normal")  # type: ignore[assignment]
    if resolved_pacing not in ("stealth", "normal", "aggressive"):
        raise WorkspaceError(f"Invalid pacing: {resolved_pacing}")

    if mode not in ("scoped", "unscoped"):
        raise WorkspaceError(f"Invalid mode: {mode}")

    workspace_name = name or root.name
    created_at = date.today().isoformat()

    _ensure_layout(root, mode, resolved_output)

    payload: dict[str, Any] = {
        "name": workspace_name,
        "mode": mode,
        "output_dir": str(resolved_output),
        "pacing": resolved_pacing,
        "created_at": created_at,
        "models": {
            "primary": models_cfg.get(
                "primary",
                "hf.co/mradermacher/Cyber-Ornith-1.5-9B-OBLITERATED-GGUF:Q3_K_S",
            ),
        },
    }
    _write_yaml(root / ".potocus" / "workspace.yaml", payload)

    workspace = load_workspace(root)
    if activate:
        set_active_workspace(root)
    return workspace


def load_workspace(path: Path) -> Workspace:
    """Load an existing workspace from disk."""
    root = path.expanduser().resolve()
    yaml_path = root / ".potocus" / "workspace.yaml"
    if not yaml_path.exists():
        raise WorkspaceError(f"Not a Potocus workspace: {root} (missing .potocus/workspace.yaml)")

    data = _read_yaml(yaml_path)
    mode = data.get("mode", "scoped")
    if mode not in ("scoped", "unscoped"):
        raise WorkspaceError(f"Invalid mode in workspace.yaml: {mode}")

    pacing = data.get("pacing", "normal")
    if pacing not in ("stealth", "normal", "aggressive"):
        raise WorkspaceError(f"Invalid pacing in workspace.yaml: {pacing}")

    output_raw = Path(data.get("output_dir", "./reports"))
    output_dir = output_raw if output_raw.is_absolute() else (root / output_raw).resolve()

    models = data.get("models") or {}
    if not isinstance(models, dict):
        raise WorkspaceError("workspace.yaml models must be a mapping")

    _ensure_layout(root, mode, output_dir)

    return Workspace(
        root=root,
        name=str(data.get("name") or root.name),
        mode=mode,
        output_dir=output_dir,
        pacing=pacing,
        created_at=str(data.get("created_at") or ""),
        models={str(k): str(v) for k, v in models.items()},
    )


def save_workspace_config(workspace: Workspace, updates: dict[str, Any]) -> Workspace:
    """Merge ``updates`` into ``workspace.yaml`` and reload."""
    data = _read_yaml(workspace.workspace_yaml)
    data.update(updates)
    _write_yaml(workspace.workspace_yaml, data)
    return load_workspace(workspace.root)


def set_workspace_mode(workspace: Workspace, mode: Mode, *, confirm: bool) -> Workspace:
    """
    Change workspace mode (scoped ↔ unscoped).

    Requires ``confirm=True`` — mode changes are deliberate (§7.3).
    """
    if not confirm:
        raise WorkspaceError("Mode change requires explicit confirmation")
    if mode not in ("scoped", "unscoped"):
        raise WorkspaceError(f"Invalid mode: {mode}")

    updated = save_workspace_config(workspace, {"mode": mode})
    if mode == "scoped" and not updated.scope_yaml.exists():
        _write_yaml(
            updated.scope_yaml,
            {"targets": [], "notes": "Add targets with `potocus scope add`."},
        )
    return load_workspace(updated.root)


def list_sessions(workspace: Workspace) -> list[dict[str, Any]]:
    """List session metadata dicts for a workspace."""
    sessions: list[dict[str, Any]] = []
    if not workspace.sessions_dir.exists():
        return sessions
    for entry in sorted(workspace.sessions_dir.iterdir()):
        meta = entry / "session.yaml"
        if entry.is_dir() and meta.exists():
            sessions.append({"id": entry.name, **_read_yaml(meta)})
    return sessions
