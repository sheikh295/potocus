"""Tests for workspace init/load layout."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.workspace.manager import WorkspaceError, init_workspace, load_workspace


def test_init_scoped_workspace(tmp_path: Path) -> None:
    """Scoped init creates layout + empty scope.yaml and activates."""
    root = tmp_path / "client-x"
    ws = init_workspace(root, mode="scoped", activate=False)

    assert ws.mode == "scoped"
    assert ws.workspace_yaml.exists()
    assert ws.scope_yaml.exists()
    assert ws.sessions_dir.is_dir()
    assert ws.vectorstore_dir.is_dir()
    assert ws.findings_db.exists()
    assert ws.log_path.exists()
    assert ws.output_dir.is_dir()


def test_init_unscoped_has_no_scope_requirement(tmp_path: Path) -> None:
    """Unscoped workspaces still get layout; scope.yaml is optional."""
    root = tmp_path / "htb-lab"
    ws = init_workspace(root, mode="unscoped", activate=False)
    assert ws.mode == "unscoped"
    assert ws.workspace_yaml.exists()


def test_reinit_raises(tmp_path: Path) -> None:
    """Second init on the same path fails."""
    root = tmp_path / "dup"
    init_workspace(root, mode="unscoped", activate=False)
    with pytest.raises(WorkspaceError, match="already exists"):
        init_workspace(root, mode="unscoped", activate=False)


def test_load_roundtrip(tmp_path: Path) -> None:
    """workspace.yaml round-trips through load_workspace."""
    root = tmp_path / "round"
    created = init_workspace(
        root,
        mode="scoped",
        name="Round Trip",
        pacing="stealth",
        activate=False,
    )
    loaded = load_workspace(created.root)
    assert loaded.name == "Round Trip"
    assert loaded.pacing == "stealth"
    assert loaded.mode == "scoped"
