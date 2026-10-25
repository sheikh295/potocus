"""Kali tool discovery — index manuals into ChromaDB and ``search_kali_tools``."""

from __future__ import annotations

import logging
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal

from src.memory.vectorstore import WorkspaceVectorStore
from src.utils.config import PROJECT_ROOT

logger = logging.getLogger("potocus.discovery")

TOOL_NAME = "search_kali_tools"

# Project-shipped seed manuals used when a binary is not on PATH (Mac/dev).
# On Kali, live ``--help`` capture replaces these during ``tools index``.
SEED_DIR = PROJECT_ROOT / "data" / "kali_tools"

SourceKind = Literal["live", "seed"]

# High-signal Kali / common offensive tools. Indexer probes PATH for each name.
KALI_TOOL_CATALOG: tuple[str, ...] = (
    "nmap",
    "masscan",
    "rustscan",
    "amass",
    "subfinder",
    "httpx",
    "whatweb",
    "gobuster",
    "feroxbuster",
    "ffuf",
    "dirb",
    "nikto",
    "nuclei",
    "wpscan",
    "sqlmap",
    "hydra",
    "medusa",
    "ncrack",
    "john",
    "hashcat",
    "enum4linux",
    "enum4linux-ng",
    "smbclient",
    "smbmap",
    "rpcclient",
    "snmpwalk",
    "onesixtyone",
    "Responder",
    "responder",
    "impacket-psexec",
    "impacket-wmiexec",
    "impacket-smbexec",
    "evil-winrm",
    "msfconsole",
    "msfvenom",
    "searchsploit",
    "crackmapexec",
    "netexec",
    "bloodhound-python",
    "ldapsearch",
    "dig",
    "whois",
    "host",
    "traceroute",
    "curl",
    "wget",
    "nc",
    "ncat",
    "tcpdump",
    "tshark",
    "wireshark",
    "chisel",
    "ssh",
    "proxychains4",
    "proxychains",
)


@dataclass(frozen=True)
class ToolManual:
    """One tool manual document ready for embedding."""

    name: str
    text: str
    source: SourceKind
    binary_path: str | None = None


@dataclass(frozen=True)
class IndexReport:
    """Summary of a tool-index run."""

    platform: str
    live_count: int
    seed_count: int
    skipped: int
    total_upserted: int
    collection_size: int
    tools: tuple[str, ...]


def seed_dir() -> Path:
    """Return the path to shipped seed manuals."""
    return SEED_DIR


def capture_help(binary: str, *, timeout_seconds: float = 8.0) -> str | None:
    """
    Capture ``--help`` / ``-h`` / ``help`` output for an installed binary.

    Returns None when nothing useful is produced.
    """
    path = shutil.which(binary)
    if not path:
        return None

    candidates: list[list[str]] = [
        [path, "--help"],
        [path, "-h"],
        [path, "help"],
    ]
    for argv in candidates:
        try:
            completed = subprocess.run(  # noqa: S603
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        text = ((completed.stdout or "") + "\n" + (completed.stderr or "")).strip()
        if len(text) >= 40:
            return text[:50_000]
    return None


def load_seed_manual(name: str, directory: Path | None = None) -> str | None:
    """Load a seed manual for ``name`` if present."""
    root = directory or seed_dir()
    path = root / f"{name}.txt"
    if not path.exists():
        # Case-insensitive fallback (e.g. Responder vs responder).
        matches = list(root.glob(f"{name}.txt")) + [
            p for p in root.glob("*.txt") if p.stem.lower() == name.lower()
        ]
        if not matches:
            return None
        path = matches[0]
    text = path.read_text(encoding="utf-8").strip()
    return text if text else None


def collect_manuals(
    *,
    catalog: Iterable[str] = KALI_TOOL_CATALOG,
    prefer_live: bool = True,
    include_seed_fallback: bool = True,
    seed_directory: Path | None = None,
) -> list[ToolManual]:
    """
    Build manuals for catalog tools.

    - **live**: binary on PATH → capture help (preferred on Kali).
    - **seed**: not installed → use shipped ``data/kali_tools/<name>.txt`` (Mac/dev).

    Set ``include_seed_fallback=False`` on Kali if you only want real installs.
    """
    manuals: list[ToolManual] = []
    seen: set[str] = set()
    for name in catalog:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)

        live_text = capture_help(name) if prefer_live else None
        if live_text:
            manuals.append(
                ToolManual(
                    name=name,
                    text=live_text,
                    source="live",
                    binary_path=shutil.which(name),
                )
            )
            continue

        if include_seed_fallback:
            seed_text = load_seed_manual(name, seed_directory)
            if seed_text:
                manuals.append(
                    ToolManual(name=name, text=seed_text, source="seed", binary_path=None)
                )
    return manuals


def index_tools(
    store: WorkspaceVectorStore,
    *,
    manuals: list[ToolManual] | None = None,
    reset: bool = False,
    include_seed_fallback: bool = True,
) -> IndexReport:
    """
    Embed tool manuals into the workspace ``kali_tools`` collection.

    ``reset=True`` drops the collection first (clean reindex on Kali).
    """
    if reset:
        store.delete_collection(WorkspaceVectorStore.TOOLS_COLLECTION)

    docs = manuals if manuals is not None else collect_manuals(
        include_seed_fallback=include_seed_fallback
    )
    ids = [f"tool:{m.name.lower()}" for m in docs]
    documents = [f"Tool: {m.name}\nSource: {m.source}\n\n{m.text}" for m in docs]
    metadatas = [
        {
            "name": m.name,
            "source": m.source,
            "binary_path": m.binary_path or "",
            "platform": platform.system().lower(),
        }
        for m in docs
    ]
    upserted = store.upsert_documents(
        collection=WorkspaceVectorStore.TOOLS_COLLECTION,
        ids=ids,
        documents=documents,
        metadatas=metadatas,
    )
    live_count = sum(1 for m in docs if m.source == "live")
    seed_count = sum(1 for m in docs if m.source == "seed")
    skipped = len(set(n.lower() for n in KALI_TOOL_CATALOG)) - len(docs)
    report = IndexReport(
        platform=platform.platform(),
        live_count=live_count,
        seed_count=seed_count,
        skipped=max(0, skipped),
        total_upserted=upserted,
        collection_size=store.count(WorkspaceVectorStore.TOOLS_COLLECTION),
        tools=tuple(m.name for m in docs),
    )
    logger.info(
        "indexed tools live=%s seed=%s total=%s platform=%s",
        report.live_count,
        report.seed_count,
        report.total_upserted,
        report.platform,
    )
    return report


def search_kali_tools(
    query: str,
    *,
    store: WorkspaceVectorStore,
    n_results: int = 5,
) -> str:
    """
    Search the workspace tool-manual vector DB for Kali tools matching ``query``.

    Returns a formatted string the orchestrator can use to build
    ``execute_kali_command`` invocations.
    """
    q = query.strip()
    if not q:
        raise ValueError(f"{TOOL_NAME} requires a non-empty query")

    hits = store.search(
        collection=WorkspaceVectorStore.TOOLS_COLLECTION,
        query=q,
        n_results=n_results,
    )
    if not hits:
        return (
            "No tool manuals indexed yet. Run `potocus tools index` in this workspace "
            "(on Kali use `--live-only` after install for full coverage)."
        )

    blocks: list[str] = [f"search_kali_tools query={q!r} results={len(hits)}"]
    for i, hit in enumerate(hits, start=1):
        name = hit.metadata.get("name", hit.id)
        source = hit.metadata.get("source", "?")
        dist = f"{hit.distance:.4f}" if hit.distance is not None else "n/a"
        # Keep each hit bounded so the orchestrator context stays healthy.
        snippet = hit.document.strip()
        if len(snippet) > 2500:
            snippet = snippet[:2500] + "\n… [truncated]"
        blocks.append(
            f"--- result {i}: {name} (source={source}, distance={dist}) ---\n{snippet}"
        )
    return "\n\n".join(blocks)
