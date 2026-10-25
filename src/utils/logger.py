"""Per-workspace logging setup and audit helpers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from src.utils.secrets import scrub_secrets


def setup_workspace_logger(workspace_root: Path, name: str = "potocus") -> logging.Logger:
    """
    Configure a logger that writes to ``<workspace>/.potocus/potocus.log``.

    Also mirrors INFO+ to stderr so CLI users see activity without opening the log.
    Secret-like values in log messages are scrubbed via ``SecretFilter``.
    """
    log_path = workspace_root / ".potocus" / "potocus.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(SecretFilter())
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(SecretFilter())
    logger.addHandler(stream_handler)

    return logger


class SecretFilter(logging.Filter):
    """Scrub secret patterns from log records before they hit handlers."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Mutate ``record.msg`` / args into scrubbed strings."""
        try:
            if isinstance(record.msg, str):
                record.msg = scrub_secrets(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {
                        k: scrub_secrets(v) if isinstance(v, str) else v
                        for k, v in record.args.items()
                    }
                elif isinstance(record.args, tuple):
                    record.args = tuple(
                        scrub_secrets(a) if isinstance(a, str) else a for a in record.args
                    )
        except Exception:  # noqa: BLE001 — never break logging
            return True
        return True


def audit(logger: logging.Logger, event: str, **fields: Any) -> None:
    """Write a structured one-line audit event (secrets scrubbed by the filter)."""
    parts = [f"event={event}"]
    for key, value in fields.items():
        parts.append(f"{key}={value}")
    logger.info("AUDIT " + " ".join(parts))
