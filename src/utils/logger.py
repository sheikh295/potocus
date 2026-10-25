"""Per-workspace logging setup."""

from __future__ import annotations

import logging
from pathlib import Path


def setup_workspace_logger(workspace_root: Path, name: str = "potocus") -> logging.Logger:
    """
    Configure a logger that writes to ``<workspace>/.potocus/potocus.log``.

    Also mirrors INFO+ to stderr so CLI users see activity without opening the log.
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
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger
