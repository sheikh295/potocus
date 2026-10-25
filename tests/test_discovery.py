"""Real tool-discovery tests (Mac-safe with seed manuals) — no mocks."""

from __future__ import annotations

from pathlib import Path

from src.memory.vectorstore import WorkspaceVectorStore
from src.tools.discovery import (
    TOOL_NAME,
    collect_manuals,
    index_tools,
    search_kali_tools,
    seed_dir,
)
from src.workspace.manager import init_workspace


def test_seed_dir_has_manuals() -> None:
    """Shipped seed corpus exists for Mac/dev indexing."""
    path = seed_dir()
    assert path.is_dir()
    assert (path / "nmap.txt").exists()
    assert (path / "gobuster.txt").exists()
    assert len(list(path.glob("*.txt"))) >= 20


def test_collect_manuals_includes_seeds_on_mac() -> None:
    """Without Kali packages, seed manuals still populate the catalog."""
    manuals = collect_manuals(include_seed_fallback=True)
    names = {m.name.lower() for m in manuals}
    assert "nmap" in names
    assert any(m.source == "seed" for m in manuals)
    # At least some live tools exist on macOS (curl/dig/ssh/…).
    assert any(m.source == "live" for m in manuals)


def test_index_and_search_network_scanner(tmp_path: Path) -> None:
    """Index into a real workspace ChromaDB and search for a network scanner."""
    ws = init_workspace(tmp_path / "tools-lab", mode="unscoped", activate=False)
    store = WorkspaceVectorStore(ws.vectorstore_dir)
    report = index_tools(store, reset=True, include_seed_fallback=True)
    assert report.total_upserted > 0
    assert store.count(WorkspaceVectorStore.TOOLS_COLLECTION) == report.total_upserted

    result = search_kali_tools("network port scanner", store=store, n_results=3)
    assert TOOL_NAME == "search_kali_tools"
    assert "nmap" in result.lower() or "masscan" in result.lower()
    assert "result 1:" in result


def test_search_empty_index_message(tmp_path: Path) -> None:
    """Empty collection returns an actionable message."""
    store = WorkspaceVectorStore(tmp_path / "empty-vs")
    msg = search_kali_tools("web fuzzer", store=store)
    assert "potocus tools index" in msg


def test_live_only_skips_missing_binaries(tmp_path: Path) -> None:
    """``--live-only`` style collection never invents missing tools."""
    manuals = collect_manuals(include_seed_fallback=False)
    assert all(m.source == "live" for m in manuals)
    assert all(m.binary_path for m in manuals)
