"""Secret scrubbing for findings, reports, and operator-facing logs."""

from __future__ import annotations

import re

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)(authorization\s*:\s*bearer\s+)[a-z0-9\-._~+/]+=*",
    ),
    re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*"),
    re.compile(
        r"(?i)(api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|"
        r"auth[_-]?token|x-api-key)\s*[:=]\s*\S+"
    ),
    re.compile(
        r"(?i)(password|passwd|pwd|passphrase)\s*[:=]\s*\S+",
    ),
    re.compile(
        r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*\S+",
    ),
    re.compile(r"(?i)ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)sk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(
        r"(?i)-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        r"[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
)


def scrub_secrets(text: str | None) -> str:
    """
    Redact common secret patterns from text destined for findings/reports/logs.

    Returns empty string for None/blank input.
    """
    if not text:
        return ""
    scrubbed = text
    for pattern in _SECRET_PATTERNS:
        scrubbed = pattern.sub("[REDACTED]", scrubbed)
    return scrubbed
