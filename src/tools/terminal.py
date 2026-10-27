"""``execute_kali_command`` — subprocess execution gated by ScopeGuard + risk HITL."""

from __future__ import annotations

import logging
import os
import pty
import select
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

from langgraph.types import interrupt

from src.tools.pacing import apply_pacing
from src.tools.risk_classification import (
    ClassificationResult,
    RiskTier,
    classify_command,
    tier_requires_hitl,
)
from src.utils.secrets import scrub_secrets
from src.workspace.scope_guard import ScopeCheckResult, ScopeGuard, extract_targets_from_command

logger = logging.getLogger("potocus.terminal")

TOOL_NAME = "execute_kali_command"

HitlDecision = Literal["approve", "deny"]
HitlCallback = Callable[[dict[str, Any]], HitlDecision]
OutputSink = Callable[[str, bool], None]  # (line, is_stderr)


class CommandBlockedError(Exception):
    """Raised when a command is blocked by scope (not used for HITL deny)."""


@dataclass(frozen=True)
class ExecutionResult:
    """Structured result of a gated command execution attempt."""

    status: Literal["ok", "blocked_scope", "denied_hitl", "timeout", "error", "started"]
    command: list[str]
    tier: RiskTier
    tier_reason: str
    scope: ScopeCheckResult
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    raw_output_path: str | None = None
    pid: int | None = None
    message: str = ""

    def as_tool_text(self, *, max_chars: int = 8000) -> str:
        """Format a compact string for the orchestrator context window."""
        lines = [
            f"status={self.status}",
            f"command={shlex.join(self.command)}",
            f"tier={self.tier.value} ({self.tier_reason})",
            f"scope={self.scope.decision}: {self.scope.reason}",
        ]
        if self.scope.targets:
            lines.append(f"targets={', '.join(self.scope.targets)}")
        if self.exit_code is not None:
            lines.append(f"exit_code={self.exit_code}")
        if self.pid is not None:
            lines.append(f"pid={self.pid}")
        if self.raw_output_path:
            lines.append(f"raw_output={self.raw_output_path}")
        if self.message:
            lines.append(f"message={self.message}")

        def _clip(label: str, text: str) -> str:
            text = text or ""
            if len(text) > max_chars // 2:
                return f"{label} (truncated):\n{text[: max_chars // 2]}\n… [{len(text)} chars total]"
            return f"{label}:\n{text}" if text else f"{label}: (empty)"

        if self.status in {"ok", "error", "timeout"}:
            lines.append(_clip("stdout", scrub_secrets(self.stdout)))
            lines.append(_clip("stderr", scrub_secrets(self.stderr)))
        return "\n".join(lines)


def parse_command(command: str | list[str]) -> list[str]:
    """
    Parse a command into argv for ``subprocess`` with ``shell=False``.

    Strings are split with ``shlex`` (POSIX). Empty commands raise ValueError.
    """
    if isinstance(command, list):
        argv = [str(part) for part in command if str(part).strip() != ""]
    else:
        argv = shlex.split(command, posix=True)
    if not argv:
        raise ValueError(f"{TOOL_NAME} requires a non-empty command")

    # Privilege escalation normalization: `sudo su` (interactive root shell) is
    # rewritten to `sudo -i` (login root shell) so a spawned sub-terminal behaves
    # consistently whether or not the parent was already elevated.
    if len(argv) >= 2 and argv[0] == "sudo" and argv[1] == "su":
        logger.info("rewriting 'sudo su' → 'sudo -i'")
        argv = ["sudo", "-i"] + argv[2:]

    return argv


def _write_raw_output(
    raw_dir: Path,
    *,
    argv: list[str],
    stdout: str,
    stderr: str,
    exit_code: int | None,
    status: str,
) -> Path:
    """Persist full stdout/stderr under the session raw_output directory."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = raw_dir / f"{stamp}_{argv[0].replace('/', '_')}.txt"
    body = (
        f"status={status}\n"
        f"command={shlex.join(argv)}\n"
        f"exit_code={exit_code}\n"
        f"{'=' * 60}\nSTDOUT\n{'=' * 60}\n{stdout}\n"
        f"{'=' * 60}\nSTDERR\n{'=' * 60}\n{stderr}\n"
    )
    # Scrub secrets in archived raw output (shareable/audit logs).
    path.write_text(scrub_secrets(body), encoding="utf-8")
    return path


def _hitl_via_interrupt(payload: dict[str, Any]) -> HitlDecision:
    """Pause the graph and wait for an operator resume value."""
    decision = interrupt(payload)
    if decision in ("approve", "deny"):
        return decision  # type: ignore[return-value]
    # Accept common truthy affirmatives from CLI / tests.
    if isinstance(decision, str) and decision.strip().lower() in {"y", "yes", "approve"}:
        return "approve"
    return "deny"


def execute_kali_command(
    command: str | list[str],
    *,
    scope_guard: ScopeGuard,
    mode: str,
    seen_targets: list[str],
    tier2_confirmed: bool,
    raw_output_dir: Path,
    timeout_seconds: float = 120.0,
    background: bool = False,
    pacing: str = "normal",
    hitl: HitlCallback | None = None,
    on_targets_seen: Callable[[list[str]], None] | None = None,
    on_tier2_confirmed: Callable[[], None] | None = None,
    on_output: OutputSink | None = None,
) -> ExecutionResult:
    """
    Gate and execute a host command for the agent.

    Order of controls (all in Python — never delegated to the LLM):
      1. Parse argv (``shell=False``)
      2. Apply pacing profile (stealth/normal/aggressive timing flags)
      3. ScopeGuard — block out-of-scope targets
      4. Risk classification — Tier 1/2/3
      5. New-target escalation — first touch of an in-scope host still needs HITL
      6. HITL interrupt when required
      7. ``subprocess.run`` / ``Popen`` execution
      8. Full raw output archival (secret-scrubbed); truncated text to the model
    """
    requested = parse_command(command)
    paced = apply_pacing(requested, pacing)
    argv = paced.argv
    pacing_note = (
        f"pacing={paced.profile}"
        + (f" applied[{', '.join(paced.notes)}]" if paced.notes else "")
    )

    classification: ClassificationResult = classify_command(argv)
    scope = scope_guard.check_command(argv)

    if scope.decision == "block":
        logger.warning("scope block cmd=%s reason=%s", argv, scope.reason)
        return ExecutionResult(
            status="blocked_scope",
            command=argv,
            tier=classification.tier,
            tier_reason=classification.reason,
            scope=scope,
            message=f"{scope.reason} | {pacing_note}",
        )

    targets = list(scope.targets) or list(extract_targets_from_command(argv))
    new_targets = [t for t in targets if t not in seen_targets]
    needs_hitl = tier_requires_hitl(
        classification.tier,
        mode=mode,
        first_tier2_in_session=(not tier2_confirmed),
    ) or bool(new_targets)

    hitl_reason = classification.reason
    if new_targets and not tier_requires_hitl(
        classification.tier, mode=mode, first_tier2_in_session=(not tier2_confirmed)
    ):
        hitl_reason = f"new target(s) not previously acted on: {', '.join(new_targets)}"

    if needs_hitl:
        payload = {
            "type": "hitl_confirmation",
            "tool": TOOL_NAME,
            "command": argv,
            "command_display": shlex.join(argv),
            "requested_command": shlex.join(requested),
            "pacing": paced.profile,
            "pacing_notes": list(paced.notes),
            "tier": classification.tier.value,
            "tier_name": classification.tier.name,
            "tier_reason": hitl_reason,
            "matched_rule": classification.matched_rule,
            "targets": targets,
            "new_targets": new_targets,
            "scope_decision": scope.decision,
            "scope_reason": scope.reason,
            "mode": mode,
            "background": background,
            "timeout_seconds": timeout_seconds,
        }
        callback = hitl or _hitl_via_interrupt
        decision = callback(payload)
        if decision != "approve":
            logger.info("HITL deny cmd=%s", argv)
            return ExecutionResult(
                status="denied_hitl",
                command=argv,
                tier=classification.tier,
                tier_reason=hitl_reason,
                scope=scope,
                message=f"Operator denied execution | {pacing_note}",
            )
        if classification.tier == RiskTier.TIER_2_ACTIVE and on_tier2_confirmed:
            on_tier2_confirmed()

    def _mark_seen() -> None:
        if on_targets_seen and targets:
            on_targets_seen(targets)

    if background:
        log_path = raw_output_dir / f"bg_{int(time.time())}_{argv[0].replace('/', '_')}.log"
        raw_output_dir.mkdir(parents=True, exist_ok=True)
        log_handle = log_path.open("w", encoding="utf-8")
        try:
            proc = subprocess.Popen(  # noqa: S603 — argv list, shell=False
                argv,
                shell=False,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except FileNotFoundError:
            log_handle.close()
            return ExecutionResult(
                status="error",
                command=argv,
                tier=classification.tier,
                tier_reason=classification.reason,
                scope=scope,
                message=(
                    f"command not found: {argv[0]} — not installed on this host "
                    f"(expected on Kali). | {pacing_note}"
                ),
            )
        except OSError as exc:
            log_handle.close()
            return ExecutionResult(
                status="error",
                command=argv,
                tier=classification.tier,
                tier_reason=classification.reason,
                scope=scope,
                message=f"failed to start: {exc} | {pacing_note}",
            )
        _mark_seen()
        logger.info("background start pid=%s cmd=%s log=%s", proc.pid, argv, log_path)
        return ExecutionResult(
            status="started",
            command=argv,
            tier=classification.tier,
            tier_reason=classification.reason,
            scope=scope,
            pid=proc.pid,
            raw_output_path=str(log_path),
            message=f"background process started; output → {log_path} | {pacing_note}",
        )

    # Foreground execution with a live pseudo-terminal so output streams while
    # the command runs (stdout+stderr are merged on the pty, as in a real terminal).
    stdout_parts: list[str] = []
    exit_code: int | None = None
    timed_out = False
    raw_path: str | None = None

    def _emit(line: str, is_stderr: bool) -> None:
        if on_output is not None:
            try:
                on_output(line, is_stderr)
            except Exception:  # noqa: BLE001 — UI must never break execution
                logger.debug("output sink failed", exc_info=True)

    master_fd, slave_fd = pty.openpty()
    try:
        proc = subprocess.Popen(  # noqa: S603 — argv list, shell=False
            argv,
            shell=False,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
        )
    finally:
        os.close(slave_fd)

    read_buf = ""
    lock = threading.Lock()
    stop_reader = threading.Event()

    def _reader() -> None:
        nonlocal read_buf, exit_code
        while not stop_reader.is_set():
            ready, _, _ = select.select([master_fd], [], [], 0.2)
            if not ready:
                if proc.poll() is not None:
                    # Drain any remaining bytes after exit.
                    try:
                        while True:
                            data = os.read(master_fd, 4096)
                            if not data:
                                break
                            text = data.decode("utf-8", errors="replace")
                            with lock:
                                read_buf += text
                    except OSError:
                        pass
                    break
                continue
            try:
                data = os.read(master_fd, 4096)
            except OSError:
                break
            if not data:
                break
            text = data.decode("utf-8", errors="replace")
            with lock:
                read_buf += text
            while "\n" in read_buf:
                line, read_buf = read_buf.split("\n", 1)
                line = scrub_secrets(line)
                _emit(line + "\n", False)
                with lock:
                    stdout_parts.append(line + "\n")
        # Flush any trailing partial line.
        with lock:
            if read_buf.strip():
                line = scrub_secrets(read_buf)
                _emit(line, False)
                stdout_parts.append(line)
        try:
            proc.wait()
        except Exception:  # noqa: BLE001
            pass
        exit_code = proc.returncode

    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()

    try:
        proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
        try:
            os.close(master_fd)
        except OSError:
            pass
    reader.join(timeout=5)

    full_stdout = "".join(stdout_parts)

    if timed_out:
        raw_path = _write_raw_output(
            raw_output_dir,
            argv=argv,
            stdout=full_stdout,
            stderr=f"timed out after {timeout_seconds}s",
            exit_code=None,
            status="timeout",
        )
        _mark_seen()
        logger.error("timeout after %ss cmd=%s", timeout_seconds, argv)
        return ExecutionResult(
            status="timeout",
            command=argv,
            tier=classification.tier,
            tier_reason=classification.reason,
            scope=scope,
            stdout=full_stdout,
            stderr=f"timed out after {timeout_seconds}s",
            raw_output_path=str(raw_path),
            message=(
                f"command timed out after {timeout_seconds}s — try a narrower scan "
                f"or raise timeout_seconds | {pacing_note}"
            ),
        )

    # Write the complete (scrubbed) raw output for audit.
    raw_path = _write_raw_output(
        raw_output_dir,
        argv=argv,
        stdout=full_stdout,
        stderr="",
        exit_code=exit_code,
        status="ok" if exit_code == 0 else "error",
    )
    _mark_seen()

    status: Literal["ok", "error"] = "ok" if exit_code == 0 else "error"
    logger.info(
        "executed status=%s code=%s cmd=%s raw=%s pacing=%s",
        status,
        exit_code,
        argv,
        raw_path,
        paced.profile,
    )
    hint = ""
    if status == "error":
        hint = " — inspect stderr and adjust flags; output was archived for audit"
    return ExecutionResult(
        status=status,
        command=argv,
        tier=classification.tier,
        tier_reason=classification.reason,
        scope=scope,
        stdout=full_stdout,
        stderr="",
        exit_code=exit_code,
        raw_output_path=str(raw_path),
        message=f"{pacing_note}{hint}",
    )
