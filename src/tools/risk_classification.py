"""Static Tier 1/2/3 command risk classification — code-level, never LLM-inferred."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Pattern


class RiskTier(str, Enum):
    """Static risk tiers for command execution (§9)."""

    TIER_1_PASSIVE = "tier1"
    TIER_2_ACTIVE = "tier2"
    TIER_3_EXPLOIT = "tier3"


@dataclass(frozen=True)
class ClassificationResult:
    """Full classification outcome with human-readable reasoning."""

    tier: RiskTier
    reason: str
    matched_rule: str


# Binary → default tier when no more-specific flag rule matches.
_BINARY_DEFAULTS: dict[str, RiskTier] = {
    # Tier 1 — passive / recon
    "whois": RiskTier.TIER_1_PASSIVE,
    "dig": RiskTier.TIER_1_PASSIVE,
    "host": RiskTier.TIER_1_PASSIVE,
    "nslookup": RiskTier.TIER_1_PASSIVE,
    "traceroute": RiskTier.TIER_1_PASSIVE,
    "traceroute6": RiskTier.TIER_1_PASSIVE,
    "ping": RiskTier.TIER_1_PASSIVE,
    "ping6": RiskTier.TIER_1_PASSIVE,
    "curl": RiskTier.TIER_1_PASSIVE,
    "wget": RiskTier.TIER_1_PASSIVE,
    "whatweb": RiskTier.TIER_1_PASSIVE,
    "httpx": RiskTier.TIER_1_PASSIVE,
    "cat": RiskTier.TIER_1_PASSIVE,
    "less": RiskTier.TIER_1_PASSIVE,
    "head": RiskTier.TIER_1_PASSIVE,
    "tail": RiskTier.TIER_1_PASSIVE,
    "ls": RiskTier.TIER_1_PASSIVE,
    "pwd": RiskTier.TIER_1_PASSIVE,
    "which": RiskTier.TIER_1_PASSIVE,
    "man": RiskTier.TIER_1_PASSIVE,
    # Tier 2 — active / intrusive
    "nmap": RiskTier.TIER_2_ACTIVE,
    "masscan": RiskTier.TIER_2_ACTIVE,
    "gobuster": RiskTier.TIER_2_ACTIVE,
    "feroxbuster": RiskTier.TIER_2_ACTIVE,
    "ffuf": RiskTier.TIER_2_ACTIVE,
    "dirb": RiskTier.TIER_2_ACTIVE,
    "dirbuster": RiskTier.TIER_2_ACTIVE,
    "nikto": RiskTier.TIER_2_ACTIVE,
    "nuclei": RiskTier.TIER_2_ACTIVE,
    "wpscan": RiskTier.TIER_2_ACTIVE,
    "enum4linux": RiskTier.TIER_2_ACTIVE,
    "enum4linux-ng": RiskTier.TIER_2_ACTIVE,
    "smbclient": RiskTier.TIER_2_ACTIVE,
    "smbmap": RiskTier.TIER_2_ACTIVE,
    "rpcclient": RiskTier.TIER_2_ACTIVE,
    "snmpwalk": RiskTier.TIER_2_ACTIVE,
    "onesixtyone": RiskTier.TIER_2_ACTIVE,
    # Tier 3 — exploitation / destructive
    "msfconsole": RiskTier.TIER_3_EXPLOIT,
    "msfvenom": RiskTier.TIER_3_EXPLOIT,
    "exploit": RiskTier.TIER_3_EXPLOIT,
    "sqlmap": RiskTier.TIER_3_EXPLOIT,
    "hydra": RiskTier.TIER_3_EXPLOIT,
    "medusa": RiskTier.TIER_3_EXPLOIT,
    "ncrack": RiskTier.TIER_3_EXPLOIT,
    "john": RiskTier.TIER_3_EXPLOIT,
    "hashcat": RiskTier.TIER_3_EXPLOIT,
    "responder": RiskTier.TIER_3_EXPLOIT,
    "bettercap": RiskTier.TIER_3_EXPLOIT,
    "ettercap": RiskTier.TIER_3_EXPLOIT,
    "impacket-psexec": RiskTier.TIER_3_EXPLOIT,
    "impacket-wmiexec": RiskTier.TIER_3_EXPLOIT,
    "impacket-smbexec": RiskTier.TIER_3_EXPLOIT,
    "evil-winrm": RiskTier.TIER_3_EXPLOIT,
    "searchsploit": RiskTier.TIER_1_PASSIVE,
}

# Ordered flag/pattern rules applied after binary defaults (first match wins among
# escalations). Patterns are matched against the full joined command string.
_ESCALATION_RULES: list[tuple[str, Pattern[str], RiskTier, str]] = [
    (
        "destructive-shell",
        re.compile(r"(?:^|\s)(?:rm|mkfs|dd|shred|wipefs|chmod\s+777)\b"),
        RiskTier.TIER_3_EXPLOIT,
        "destructive filesystem / wipe command",
    ),
    (
        "credential-spray",
        re.compile(r"\b(?:hydra|medusa|ncrack|crowbar)\b"),
        RiskTier.TIER_3_EXPLOIT,
        "credential spraying / brute-force tool",
    ),
    (
        "sqlmap-attack",
        re.compile(r"\bsqlmap\b"),
        RiskTier.TIER_3_EXPLOIT,
        "sqlmap exploitation tooling",
    ),
    (
        "metasploit",
        re.compile(r"\b(?:msfconsole|msfvenom|exploit/)\b"),
        RiskTier.TIER_3_EXPLOIT,
        "Metasploit / exploit framework",
    ),
    (
        "nmap-intrusive",
        re.compile(r"\bnmap\b.*(?:\s-A\b|\s-sV\b|\s-sC\b|\s--script\b|\s-O\b)"),
        RiskTier.TIER_2_ACTIVE,
        "nmap service/version/script/OS scan",
    ),
    (
        "nmap-passive-only",
        re.compile(r"\bnmap\b.*(?:\s-sn\b|\s-sL\b|\s--list-scan\b)"),
        RiskTier.TIER_1_PASSIVE,
        "nmap host-discovery / list-scan only",
    ),
]


def _binary_name(command: list[str]) -> str:
    """Return the basename of argv[0] without path."""
    if not command:
        return ""
    name = command[0].rsplit("/", 1)[-1]
    return name.strip().lower()


def classify_command(command: list[str]) -> ClassificationResult:
    """
    Classify a command into a risk tier using the static rule table.

    Unknown binaries default to Tier 3 (fail-closed). The LLM never influences
    this decision.
    """
    if not command:
        return ClassificationResult(
            tier=RiskTier.TIER_3_EXPLOIT,
            reason="empty command — fail-closed",
            matched_rule="empty",
        )

    joined = " ".join(command)
    binary = _binary_name(command)

    # Escalation / specialization rules first (order matters).
    for rule_id, pattern, tier, reason in _ESCALATION_RULES:
        if pattern.search(joined):
            # nmap-passive-only must win over binary default / intrusive.
            return ClassificationResult(
                tier=tier,
                reason=reason,
                matched_rule=rule_id,
            )

    if binary in _BINARY_DEFAULTS:
        tier = _BINARY_DEFAULTS[binary]
        return ClassificationResult(
            tier=tier,
            reason=f"binary default for `{binary}`",
            matched_rule=f"binary:{binary}",
        )

    return ClassificationResult(
        tier=RiskTier.TIER_3_EXPLOIT,
        reason=f"unknown binary `{binary}` — fail-closed to Tier 3",
        matched_rule="unknown-binary",
    )


def tier_requires_hitl(tier: RiskTier, *, mode: str, first_tier2_in_session: bool) -> bool:
    """
    Decide whether HITL confirmation is required for this tier/mode.

    - Tier 1: never
    - Tier 2: one-time session confirmation in unscoped; auto in scoped (logged)
    - Tier 3: always
    """
    if tier == RiskTier.TIER_1_PASSIVE:
        return False
    if tier == RiskTier.TIER_3_EXPLOIT:
        return True
    # Tier 2
    if mode == "unscoped":
        return first_tier2_in_session
    return False
