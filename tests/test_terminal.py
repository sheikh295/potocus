"""Real execute_kali_command tests — subprocess + scope + HITL, no mocks."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.tools.risk_classification import RiskTier
from src.tools.terminal import execute_kali_command, parse_command
from src.workspace.scope_guard import ScopeGuard


def test_parse_command_rejects_empty() -> None:
    """Empty commands are invalid."""
    with pytest.raises(ValueError):
        parse_command("   ")


def test_parse_command_splits_safely() -> None:
    """Quoted arguments survive shlex splitting."""
    assert parse_command("echo 'hello world'") == ["echo", "hello world"]


def test_tier1_runs_without_hitl(tmp_path: Path) -> None:
    """Passive commands auto-run when no new network targets are present."""
    raw = tmp_path / "raw"
    guard = ScopeGuard(mode="unscoped", allowlist=[])
    hitl_calls: list[dict] = []

    result = execute_kali_command(
        ["uname", "-s"],
        scope_guard=guard,
        mode="unscoped",
        seen_targets=[],
        tier2_confirmed=False,
        raw_output_dir=raw,
        hitl=lambda payload: hitl_calls.append(payload) or "deny",
    )
    assert result.status == "ok"
    assert result.exit_code == 0
    assert result.stdout.strip()  # Darwin / Linux
    assert hitl_calls == []
    assert result.raw_output_path
    assert Path(result.raw_output_path).exists()


def test_scope_blocks_before_hitl(tmp_path: Path) -> None:
    """Out-of-scope targets never reach HITL or execution."""
    raw = tmp_path / "raw"
    guard = ScopeGuard(mode="scoped", allowlist=["10.10.20.0/24"])
    hitl_calls: list[dict] = []

    result = execute_kali_command(
        ["nmap", "-sn", "8.8.8.8"],
        scope_guard=guard,
        mode="scoped",
        seen_targets=[],
        tier2_confirmed=False,
        raw_output_dir=raw,
        hitl=lambda payload: hitl_calls.append(payload) or "approve",
    )
    assert result.status == "blocked_scope"
    assert hitl_calls == []
    assert "8.8.8.8" in result.scope.blocked


def test_tier3_requires_hitl_and_can_deny(tmp_path: Path) -> None:
    """Unknown/exploit-tier binaries always require confirmation."""
    raw = tmp_path / "raw"
    guard = ScopeGuard(mode="unscoped", allowlist=[])

    denied = execute_kali_command(
        ["hydra", "-h"],
        scope_guard=guard,
        mode="unscoped",
        seen_targets=[],
        tier2_confirmed=False,
        raw_output_dir=raw,
        hitl=lambda _payload: "deny",
    )
    assert denied.status == "denied_hitl"
    assert denied.tier == RiskTier.TIER_3_EXPLOIT


def test_new_target_escalates_hitl_even_for_tier1(tmp_path: Path) -> None:
    """First touch of a host triggers HITL even for passive tools."""
    raw = tmp_path / "raw"
    guard = ScopeGuard(mode="scoped", allowlist=["10.10.20.0/24"])
    seen: list[str] = []

    result = execute_kali_command(
        # dig may or may not be installed; we only need to reach HITL before exec.
        # Use echo with a target-like arg that extract_targets finds — actually echo
        # won't extract IP from free text unless it's a separate token.
        ["ping", "-c", "1", "10.10.20.5"],
        scope_guard=guard,
        mode="scoped",
        seen_targets=[],
        tier2_confirmed=False,
        raw_output_dir=raw,
        hitl=lambda payload: (
            "approve"
            if "10.10.20.5" in (payload.get("new_targets") or [])
            else "deny"
        ),
        on_targets_seen=lambda ts: seen.extend(ts),
        timeout_seconds=5,
    )
    # ping may fail (no network / permission) but must not be scope/HITL blocked.
    assert result.status in {"ok", "error", "timeout"}
    assert "10.10.20.5" in seen


def test_tier2_unscoped_one_time_confirmation(tmp_path: Path) -> None:
    """First Tier-2 in unscoped mode asks once; later Tier-2 does not."""
    raw = tmp_path / "raw"
    guard = ScopeGuard(mode="unscoped", allowlist=[])
    confirmed = {"value": False}
    calls = 0

    def hitl(_payload: dict) -> str:
        nonlocal calls
        calls += 1
        confirmed["value"] = True
        return "approve"

    # gobuster may be missing — deny path after HITL still proves gating.
    first = execute_kali_command(
        ["gobuster", "version"],
        scope_guard=guard,
        mode="unscoped",
        seen_targets=[],
        tier2_confirmed=False,
        raw_output_dir=raw,
        hitl=hitl,
        on_tier2_confirmed=lambda: confirmed.__setitem__("value", True),
    )
    assert calls == 1
    assert first.status in {"ok", "error", "denied_hitl"}

    second = execute_kali_command(
        ["gobuster", "version"],
        scope_guard=guard,
        mode="unscoped",
        seen_targets=[],
        tier2_confirmed=True,
        raw_output_dir=raw,
        hitl=hitl,
    )
    # Second call should not invoke HITL for Tier-2 when already confirmed.
    assert calls == 1
