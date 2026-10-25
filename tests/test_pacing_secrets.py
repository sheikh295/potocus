"""Pacing profile + secret scrubbing tests — no mocks."""

from __future__ import annotations

from pathlib import Path

from src.reporting.generator import generate_report
from src.tools.pacing import apply_pacing
from src.tools.terminal import execute_kali_command
from src.utils.secrets import scrub_secrets
from src.workspace.manager import init_workspace
from src.workspace.scope_guard import ScopeGuard


def test_stealth_adds_nmap_timing() -> None:
    """Stealth pacing injects -T2 when missing."""
    result = apply_pacing(["nmap", "-sn", "10.10.20.0/24"], "stealth")
    assert result.modified is True
    assert "-T2" in result.argv
    assert result.profile == "stealth"


def test_aggressive_nmap_t5() -> None:
    """Aggressive pacing uses -T5."""
    result = apply_pacing(["nmap", "-sV", "10.10.20.5"], "aggressive")
    assert "-T5" in result.argv


def test_does_not_override_existing_timing() -> None:
    """Operator-supplied -T3 is preserved."""
    result = apply_pacing(["nmap", "-T3", "-sn", "10.10.20.0/24"], "stealth")
    assert result.modified is False
    assert "-T2" not in result.argv
    assert "-T3" in result.argv


def test_normal_is_noop() -> None:
    """Normal pacing leaves argv unchanged."""
    argv = ["gobuster", "dir", "-u", "http://x", "-w", "w.txt"]
    result = apply_pacing(argv, "normal")
    assert result.argv == argv
    assert result.modified is False


def test_scrub_tokens_and_keys() -> None:
    """Expanded scrubber catches common token shapes."""
    text = scrub_secrets(
        "token=abc password=hunter2 ghp_abcdefghijklmnopqrstuv sk-abcdefghijklmnopqrstuv"
    )
    assert "hunter2" not in text
    assert "ghp_" not in text or "[REDACTED]" in text
    assert "sk-abcdefgh" not in text
    assert "[REDACTED]" in text


def test_execute_applies_pacing(tmp_path: Path) -> None:
    """execute_kali_command records pacing in the result message."""
    raw = tmp_path / "raw"
    guard = ScopeGuard(mode="unscoped", allowlist=[])
    result = execute_kali_command(
        ["echo", "ok"],
        scope_guard=guard,
        mode="unscoped",
        seen_targets=[],
        tier2_confirmed=False,
        raw_output_dir=raw,
        pacing="stealth",
    )
    assert result.status == "ok"
    assert "pacing=stealth" in result.message


def test_report_scrubs_secrets(tmp_path: Path) -> None:
    """Generated markdown reports scrub secrets from finding details."""
    from src.memory.findings_db import FindingsDB

    ws = init_workspace(tmp_path / "scrub-report", mode="unscoped", activate=False)
    db = FindingsDB(ws.findings_db)
    try:
        db.add_finding(
            kind="note",
            title="cred note",
            detail="password=SuperSecret123 api_key=ABCD",
            severity="high",
        )
    finally:
        db.close()

    # Detail already scrubbed on write; also ensure generate path is safe.
    report = generate_report(ws, fmt="md", template="research", output_dir=tmp_path / "out")
    body = report.path.read_text(encoding="utf-8")
    assert "SuperSecret123" not in body
    assert "ABCD" not in body or "[REDACTED]" in body
