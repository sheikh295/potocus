"""Real ScopeGuard tests — no mocks."""

from __future__ import annotations

from pathlib import Path

import yaml

from src.workspace.scope_guard import (
    ScopeGuard,
    extract_targets_from_command,
    load_allowlist_from_scope_yaml,
    target_in_allowlist,
)


def test_extract_ip_and_cidr() -> None:
    """IPs and CIDRs are pulled from argv."""
    targets = extract_targets_from_command(
        ["nmap", "-sn", "10.10.20.0/24", "192.168.1.10"]
    )
    assert "10.10.20.0/24" in targets
    assert "192.168.1.10" in targets


def test_extract_hostname_and_url() -> None:
    """Hostnames and URL hosts are extracted."""
    targets = extract_targets_from_command(
        ["curl", "-s", "https://api.clientx-staging.com/v1/health"]
    )
    assert "api.clientx-staging.com" in targets


def test_unscoped_always_allows() -> None:
    """Unscoped mode is a pass-through even for arbitrary targets."""
    guard = ScopeGuard(mode="unscoped", allowlist=[])
    result = guard.check_command(["nmap", "-sn", "8.8.8.8"])
    assert result.decision == "allow"


def test_scoped_empty_allowlist_blocks() -> None:
    """Scoped with no targets fails closed."""
    guard = ScopeGuard(mode="scoped", allowlist=[])
    result = guard.check_command(["nmap", "-sn", "10.10.20.5"])
    assert result.decision == "block"
    assert "empty allowlist" in result.reason


def test_scoped_cidr_allows_host_inside() -> None:
    """Host inside an allowlisted CIDR is allowed."""
    guard = ScopeGuard(mode="scoped", allowlist=["10.10.20.0/24"])
    result = guard.check_command(["nmap", "-sn", "10.10.20.55"])
    assert result.decision == "allow"
    assert result.blocked == ()


def test_scoped_blocks_out_of_range_ip() -> None:
    """Host outside the allowlisted CIDR is blocked."""
    guard = ScopeGuard(mode="scoped", allowlist=["10.10.20.0/24"])
    result = guard.check_command(["nmap", "-sn", "10.10.99.1"])
    assert result.decision == "block"
    assert "10.10.99.1" in result.blocked


def test_wildcard_domain() -> None:
    """``*.example.com`` matches subdomains and the apex."""
    assert target_in_allowlist("api.example.com", ["*.example.com"])
    assert target_in_allowlist("example.com", ["*.example.com"])
    assert not target_in_allowlist("evil.com", ["*.example.com"])


def test_local_command_no_targets_allowed_when_scoped() -> None:
    """Commands with no network targets are allowed (risk tier still applies)."""
    guard = ScopeGuard(mode="scoped", allowlist=["10.10.20.0/24"])
    result = guard.check_command(["ls", "-la", "/tmp"])
    assert result.decision == "allow"
    assert result.targets == ()


def test_from_workspace_reads_scope_yaml(tmp_path: Path) -> None:
    """ScopeGuard.from_workspace loads allowlist from a real scope.yaml."""
    scope_path = tmp_path / "scope.yaml"
    with scope_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(
            {"targets": [{"target": "10.10.20.0/24", "note": "roe"}]},
            handle,
        )
    assert load_allowlist_from_scope_yaml(scope_path) == ["10.10.20.0/24"]
    guard = ScopeGuard.from_workspace(mode="scoped", scope_yaml=scope_path)
    assert guard.check_command(["dig", "10.10.20.9"]).decision == "allow"
