"""Apply workspace/session pacing profiles to timing-sensitive tool argv."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

PacingProfile = Literal["stealth", "normal", "aggressive"]


@dataclass(frozen=True)
class PacingResult:
    """Result of applying a pacing profile to a command."""

    argv: list[str]
    profile: PacingProfile
    modified: bool
    notes: tuple[str, ...] = ()


def _has_flag(argv: list[str], *flags: str) -> bool:
    """Return True if any flag is already present (exact or ``-T4`` style)."""
    for token in argv[1:]:
        for flag in flags:
            if token == flag or token.startswith(f"{flag}="):
                return True
            # nmap timing: -T0 .. -T5
            if flag == "-T" and len(token) == 3 and token.startswith("-T") and token[2].isdigit():
                return True
    return False


def _insert_after_binary(argv: list[str], *flags: str) -> list[str]:
    """Insert flags immediately after argv[0]."""
    return [argv[0], *flags, *argv[1:]]


def apply_pacing(argv: list[str], profile: str) -> PacingResult:
    """
    Inject timing/throttle flags based on the active pacing profile.

    Does not remove operator-supplied timing flags — if the command already
    sets timing, it is left alone. Unknown binaries are unchanged.
    """
    if not argv:
        return PacingResult(argv=[], profile="normal", modified=False)

    resolved: PacingProfile
    if profile in ("stealth", "normal", "aggressive"):
        resolved = profile  # type: ignore[assignment]
    else:
        resolved = "normal"

    if resolved == "normal":
        return PacingResult(argv=list(argv), profile=resolved, modified=False)

    binary = argv[0].rsplit("/", 1)[-1].lower()
    notes: list[str] = []
    out = list(argv)

    if binary == "nmap":
        if not _has_flag(out, "-T"):
            timing = "-T2" if resolved == "stealth" else "-T5"
            out = _insert_after_binary(out, timing)
            notes.append(f"nmap {timing}")
            if resolved == "stealth" and not _has_flag(out, "--max-retries"):
                out = _insert_after_binary(out, "--max-retries", "2")
                notes.append("nmap --max-retries 2")

    elif binary == "masscan":
        if not _has_flag(out, "--rate"):
            rate = "100" if resolved == "stealth" else "10000"
            out = _insert_after_binary(out, "--rate", rate)
            notes.append(f"masscan --rate {rate}")

    elif binary in {"gobuster", "feroxbuster"}:
        if not _has_flag(out, "-t", "--threads"):
            threads = "10" if resolved == "stealth" else "50"
            flag = "-t"
            out = _insert_after_binary(out, flag, threads)
            notes.append(f"{binary} {flag} {threads}")

    elif binary == "ffuf":
        if resolved == "stealth" and not _has_flag(out, "-rate"):
            out = _insert_after_binary(out, "-rate", "10")
            notes.append("ffuf -rate 10")
        if not _has_flag(out, "-t"):
            threads = "10" if resolved == "stealth" else "40"
            out = _insert_after_binary(out, "-t", threads)
            notes.append(f"ffuf -t {threads}")

    elif binary == "nuclei":
        if not _has_flag(out, "-rate-limit", "-rl"):
            rate = "25" if resolved == "stealth" else "150"
            out = _insert_after_binary(out, "-rate-limit", rate)
            notes.append(f"nuclei -rate-limit {rate}")

    elif binary == "hydra":
        if not _has_flag(out, "-t"):
            tasks = "4" if resolved == "stealth" else "16"
            out = _insert_after_binary(out, "-t", tasks)
            notes.append(f"hydra -t {tasks}")

    elif binary in {"sqlmap"}:
        if resolved == "stealth" and not _has_flag(out, "--delay"):
            out = _insert_after_binary(out, "--delay", "1")
            notes.append("sqlmap --delay 1")

    modified = out != argv
    return PacingResult(
        argv=out,
        profile=resolved,
        modified=modified,
        notes=tuple(notes),
    )
