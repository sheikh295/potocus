"""Real multi-session + checkpoint resume tests — no mocks."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.graph import create_agent
from src.models import test_ollama_connection as probe_ollama
from src.workspace.manager import init_workspace
from src.workspace.session_store import (
    inspect_checkpoint,
    list_session_ids,
    read_session_meta,
    sync_meta_from_checkpoint,
    touch_session,
    write_session_meta,
)


def _make_session(ws, session_id: str, *, name: str, phase: str = "RECON") -> None:
    path = ws.sessions_dir / session_id
    (path / "checkpoints").mkdir(parents=True)
    (path / "raw_output").mkdir(parents=True)
    write_session_meta(
        ws,
        session_id,
        {
            "id": session_id,
            "name": name,
            "phase": phase,
            "target_focus": "",
            "status": "open",
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    )


def test_sessions_are_isolated_on_disk(tmp_path: Path) -> None:
    """Two sessions in one workspace do not share raw message history files."""
    ws = init_workspace(tmp_path / "multi", mode="unscoped", activate=False)
    _make_session(ws, "aaaa11111111", name="recon-a")
    _make_session(ws, "bbbb22222222", name="recon-b")
    assert set(list_session_ids(ws)) == {"aaaa11111111", "bbbb22222222"}
    assert (ws.sessions_dir / "aaaa11111111" / "checkpoints").is_dir()
    assert (ws.sessions_dir / "bbbb22222222" / "checkpoints").is_dir()


def test_touch_and_focus(tmp_path: Path) -> None:
    """Metadata updates persist to session.yaml."""
    ws = init_workspace(tmp_path / "focus", mode="unscoped", activate=False)
    _make_session(ws, "cccc33333333", name="web")
    meta = touch_session(
        ws, "cccc33333333", target_focus="10.10.20.5", pacing="stealth", phase="ENUMERATION"
    )
    assert meta["target_focus"] == "10.10.20.5"
    assert meta["pacing"] == "stealth"
    assert meta["phase"] == "ENUMERATION"
    reloaded = read_session_meta(ws, "cccc33333333")
    assert reloaded["target_focus"] == "10.10.20.5"


def test_checkpoint_resume_across_agent_instances(tmp_path: Path) -> None:
    """Closing and reopening the same session thread restores messages."""
    probe = probe_ollama(run_chat_probe=True)
    if not probe.ok:
        pytest.skip(f"ollama not ready: {probe.error}")

    ws = init_workspace(tmp_path / "resume-lab", mode="unscoped", activate=False)
    sid = "dddd44444444"
    _make_session(ws, sid, name="persist", phase="RECON")

    agent = create_agent(ws, session_id=sid, phase="RECON")
    try:
        agent.invoke_turn("Remember codeword: cedar-9. Reply with: noted")
    finally:
        agent.close()

    snap = inspect_checkpoint(ws, sid)
    assert snap.exists is True
    assert snap.message_count >= 2

    meta, snap2 = sync_meta_from_checkpoint(ws, sid)
    assert meta["checkpoint_exists"] is True
    assert meta["message_count"] == snap2.message_count

    agent2 = create_agent(ws, session_id=sid)
    try:
        state = agent2.invoke_turn(
            "What codeword did I ask you to remember? Reply with only the codeword."
        )
        text = agent2.latest_ai_text(state).lower()
        assert "cedar-9" in text.replace(" ", "")
    finally:
        agent2.close()


def test_two_sessions_do_not_share_message_history(tmp_path: Path) -> None:
    """Session B cannot see Session A's private conversation."""
    probe = probe_ollama(run_chat_probe=True)
    if not probe.ok:
        pytest.skip(f"ollama not ready: {probe.error}")

    ws = init_workspace(tmp_path / "isolate", mode="unscoped", activate=False)
    _make_session(ws, "eeee55555555", name="alpha")
    _make_session(ws, "ffff66666666", name="beta")

    a = create_agent(ws, session_id="eeee55555555")
    try:
        a.invoke_turn("Secret for alpha only: mango-77. Reply: ok")
    finally:
        a.close()

    b = create_agent(ws, session_id="ffff66666666")
    try:
        state = b.invoke_turn(
            "What secret codeword was shared earlier in this chat? "
            "If none, reply exactly: none"
        )
        text = b.latest_ai_text(state).lower()
        assert "mango-77" not in text.replace(" ", "")
        assert "none" in text
    finally:
        b.close()

    # Alpha still has its own history.
    snap_a = inspect_checkpoint(ws, "eeee55555555")
    snap_b = inspect_checkpoint(ws, "ffff66666666")
    assert snap_a.message_count >= 2
    assert snap_b.message_count >= 2
    assert snap_a.path != snap_b.path
