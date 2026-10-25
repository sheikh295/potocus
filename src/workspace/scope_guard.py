"""ScopeGuard — code-level scope enforcement against workspace allowlists."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal

import yaml

ScopeDecision = Literal["allow", "block"]

# Host-like tokens: IPv4, IPv4/CIDR, hostnames, wildcard domains.
_IPV4_CIDR_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:/(?:3[0-2]|[12]?\d))?\b"
)
_HOSTNAME_RE = re.compile(
    r"\b(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)
# Also catch bare hostnames / short labels passed as dedicated argv tokens.
_SIMPLE_HOST_RE = re.compile(r"^(?:\*\.)?[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$")

# Flags whose following argument is a URL/file path, not a network target.
_SKIP_VALUE_FLAGS = {
    "-o",
    "-oN",
    "-oX",
    "-oG",
    "-oA",
    "--output",
    "-iL",
    "--excludefile",
    "-S",
}


@dataclass(frozen=True)
class ScopeCheckResult:
    """Result of a scope check against the workspace allowlist."""

    decision: ScopeDecision
    reason: str
    targets: tuple[str, ...] = ()
    blocked: tuple[str, ...] = ()


def load_allowlist_from_scope_yaml(scope_yaml: Path) -> list[str]:
    """
    Load target strings from a ``scope.yaml`` file.

    Supports either ``[{target, note}, ...]`` or plain string entries.
    """
    if not scope_yaml.exists():
        return []
    with scope_yaml.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        return []
    targets: list[str] = []
    for entry in data.get("targets") or []:
        if isinstance(entry, dict) and entry.get("target"):
            targets.append(str(entry["target"]).strip())
        elif isinstance(entry, str) and entry.strip():
            targets.append(entry.strip())
    return targets


def extract_targets_from_command(command: list[str]) -> tuple[str, ...]:
    """
    Extract implied network targets from a argv-style command list.

    Looks at positional tokens and common ``host=`` / ``RHOSTS=`` style values.
    Skips flag names and known file/output flag values.
    """
    if not command:
        return ()

    found: list[str] = []
    skip_next = False
    for token in command[1:]:  # skip binary name
        if skip_next:
            skip_next = False
            continue
        if token in _SKIP_VALUE_FLAGS:
            skip_next = True
            continue
        if token.startswith("-") and "=" not in token:
            # Flag without inline value (e.g. -sV). Not a target.
            continue

        candidates = _candidates_from_token(token)
        for candidate in candidates:
            if candidate not in found:
                found.append(candidate)

    return tuple(found)


def _candidates_from_token(token: str) -> list[str]:
    """Pull host/IP/CIDR-looking strings out of a single argv token."""
    # Strip common KEY=value wrappers used by Metasploit-style CLIs.
    value = token
    if "=" in token and not token.startswith("-"):
        _, _, rhs = token.partition("=")
        value = rhs or token
    if value.startswith("--") and "=" in value:
        _, _, rhs = value.partition("=")
        value = rhs

    # URL → hostname
    if "://" in value:
        after_scheme = value.split("://", 1)[1]
        hostport = after_scheme.split("/", 1)[0]
        value = hostport.split("@")[-1]  # drop userinfo
        if value.startswith("[") and "]" in value:
            value = value[1 : value.index("]")]
        elif ":" in value and value.count(":") == 1:
            # host:port (not IPv6)
            host, _, port = value.partition(":")
            if port.isdigit():
                value = host

    hits: list[str] = []
    for match in _IPV4_CIDR_RE.findall(value):
        if match not in hits:
            hits.append(match)
    for match in _HOSTNAME_RE.findall(value):
        if match.lower() not in {h.lower() for h in hits}:
            hits.append(match.lower())

    # Bare hostname tokens must look domain-like (contain a dot). This avoids
    # treating tool subcommands like ``version`` / ``dir`` as network targets.
    stripped = value.strip().strip("'\"")
    if (
        not hits
        and "." in stripped
        and "/" not in stripped
        and not stripped.startswith("-")
        and _SIMPLE_HOST_RE.match(stripped)
        and not stripped.endswith((".txt", ".lst", ".json", ".xml", ".csv", ".log"))
    ):
        hits.append(stripped.lower())

    return hits


def _ip_in_cidr(ip_or_cidr: str, allowed_cidr: str) -> bool:
    """Return True if ``ip_or_cidr`` is contained in ``allowed_cidr``."""
    try:
        allowed = ipaddress.ip_network(allowed_cidr, strict=False)
        target = ipaddress.ip_network(ip_or_cidr, strict=False)
        return target.subnet_of(allowed) or target == allowed
    except ValueError:
        return False


def _hostname_allowed(hostname: str, pattern: str) -> bool:
    """Match hostname against an allowlist pattern (exact or ``*.domain``)."""
    host = hostname.lower().rstrip(".")
    pat = pattern.lower().rstrip(".")
    if pat.startswith("*."):
        suffix = pat[1:]  # ".example.com"
        return host.endswith(suffix) or host == pat[2:]
    return host == pat


def target_in_allowlist(target: str, allowlist: Iterable[str]) -> bool:
    """Return True if ``target`` is permitted by any allowlist entry."""
    t = target.strip()
    if not t:
        return False

    for entry in allowlist:
        allowed = entry.strip()
        if not allowed:
            continue

        # IP / CIDR vs IP / CIDR
        try:
            ipaddress.ip_network(t, strict=False)
            ipaddress.ip_network(allowed, strict=False)
            if _ip_in_cidr(t, allowed):
                return True
            continue
        except ValueError:
            pass

        # Hostname / wildcard domain
        if _hostname_allowed(t, allowed):
            return True

    return False


class ScopeGuard:
    """
    Hard gate between tool-call decisions and network-touching execution.

    Unscoped workspaces are a pass-through. Scoped workspaces require every
    extracted target to match the allowlist. Commands with no extractable
    targets are allowed (local-only tooling); the risk classifier still applies.
    """

    def __init__(self, *, mode: str, allowlist: list[str] | None = None) -> None:
        """Initialize with workspace mode and target allowlist strings."""
        if mode not in ("scoped", "unscoped"):
            raise ValueError(f"Invalid mode: {mode}")
        self.mode = mode
        self.allowlist = [a.strip() for a in (allowlist or []) if a and str(a).strip()]

    @classmethod
    def from_workspace(cls, *, mode: str, scope_yaml: Path | None) -> ScopeGuard:
        """Build a ScopeGuard from workspace mode + optional scope.yaml path."""
        allowlist: list[str] = []
        if mode == "scoped" and scope_yaml is not None:
            allowlist = load_allowlist_from_scope_yaml(scope_yaml)
        return cls(mode=mode, allowlist=allowlist)

    def check_targets(self, targets: Iterable[str]) -> ScopeCheckResult:
        """Check already-extracted targets against the allowlist."""
        target_list = tuple(t for t in targets if t)
        if self.mode == "unscoped":
            return ScopeCheckResult(
                decision="allow",
                reason="unscoped workspace — ScopeGuard pass-through",
                targets=target_list,
            )

        if not self.allowlist:
            return ScopeCheckResult(
                decision="block",
                reason="scoped workspace has an empty allowlist — add targets with `potocus scope add`",
                targets=target_list,
                blocked=target_list,
            )

        if not target_list:
            return ScopeCheckResult(
                decision="allow",
                reason="no network targets extracted — local/non-network command",
                targets=(),
            )

        blocked = tuple(t for t in target_list if not target_in_allowlist(t, self.allowlist))
        if blocked:
            return ScopeCheckResult(
                decision="block",
                reason=f"out-of-scope target(s): {', '.join(blocked)}",
                targets=target_list,
                blocked=blocked,
            )
        return ScopeCheckResult(
            decision="allow",
            reason="all extracted targets are in scope",
            targets=target_list,
        )

    def check_command(self, command: list[str]) -> ScopeCheckResult:
        """Parse implied targets from ``command`` and check against scope."""
        if not command:
            return ScopeCheckResult(decision="block", reason="empty command")
        targets = extract_targets_from_command(command)
        return self.check_targets(targets)
