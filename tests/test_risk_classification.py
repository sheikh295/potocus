"""Real risk-classification tests — no mocks."""

from __future__ import annotations

from src.tools.risk_classification import (
    RiskTier,
    classify_command,
    tier_requires_hitl,
)


def test_whois_is_tier1() -> None:
    """Passive recon binaries are Tier 1."""
    result = classify_command(["whois", "example.com"])
    assert result.tier == RiskTier.TIER_1_PASSIVE


def test_nmap_sn_is_tier1() -> None:
    """Host-discovery-only nmap is Tier 1."""
    result = classify_command(["nmap", "-sn", "10.10.20.0/24"])
    assert result.tier == RiskTier.TIER_1_PASSIVE
    assert result.matched_rule == "nmap-passive-only"


def test_nmap_sv_is_tier2() -> None:
    """Service scan nmap is Tier 2."""
    result = classify_command(["nmap", "-sV", "10.10.20.5"])
    assert result.tier == RiskTier.TIER_2_ACTIVE


def test_nmap_sn_plus_sv_stays_tier2() -> None:
    """Intrusive flags win over -sn when both are present."""
    result = classify_command(["nmap", "-sn", "-sV", "10.10.20.5"])
    assert result.tier == RiskTier.TIER_2_ACTIVE
    assert result.matched_rule == "nmap-intrusive"


def test_hydra_is_tier3() -> None:
    """Credential spraying is always Tier 3."""
    result = classify_command(["hydra", "-l", "admin", "-P", "rockyou.txt", "ssh://10.1.1.1"])
    assert result.tier == RiskTier.TIER_3_EXPLOIT


def test_unknown_binary_fail_closed() -> None:
    """Unknown tools default to Tier 3."""
    result = classify_command(["totally-unknown-tool", "10.1.1.1"])
    assert result.tier == RiskTier.TIER_3_EXPLOIT
    assert result.matched_rule == "unknown-binary"


def test_hitl_rules() -> None:
    """HITL gating matches §9 mode behavior."""
    assert tier_requires_hitl(RiskTier.TIER_1_PASSIVE, mode="scoped", first_tier2_in_session=True) is False
    assert tier_requires_hitl(RiskTier.TIER_3_EXPLOIT, mode="scoped", first_tier2_in_session=False) is True
    assert tier_requires_hitl(RiskTier.TIER_2_ACTIVE, mode="scoped", first_tier2_in_session=True) is False
    assert tier_requires_hitl(RiskTier.TIER_2_ACTIVE, mode="unscoped", first_tier2_in_session=True) is True
    assert tier_requires_hitl(RiskTier.TIER_2_ACTIVE, mode="unscoped", first_tier2_in_session=False) is False
