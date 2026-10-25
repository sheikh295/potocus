"""Workspace-scoped ChromaDB vector store for tool manuals and memory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import chromadb
from chromadb.api.models.Collection import Collection


@dataclass(frozen=True)
class VectorHit:
    """One similarity-search hit from the workspace vector store."""

    id: str
    document: str
    metadata: dict[str, Any]
    distance: float | None


class WorkspaceVectorStore:
    """
    Persistent ChromaDB store rooted at ``<workspace>/.potocus/vectorstore/``.

    Collections stay inside the workspace so engagement memory never leaks
    across clients/labs (§5.3).
    """

    TOOLS_COLLECTION = "kali_tools"

    def __init__(self, root: Path) -> None:
        """Open (or create) a persistent client under ``root``."""
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(self.root))

    def get_or_create_collection(self, name: str) -> Collection:
        """Return a named collection, creating it if needed."""
        return self._client.get_or_create_collection(
            name=name,
            metadata={"hnsw:space": "cosine"},
        )

    def upsert_documents(
        self,
        *,
        collection: str,
        ids: Sequence[str],
        documents: Sequence[str],
        metadatas: Sequence[dict[str, Any]] | None = None,
    ) -> int:
        """Upsert documents by id. Returns the number of documents written."""
        if not ids:
            return 0
        if len(ids) != len(documents):
            raise ValueError("ids and documents length mismatch")
        coll = self.get_or_create_collection(collection)
        coll.upsert(
            ids=list(ids),
            documents=list(documents),
            metadatas=list(metadatas) if metadatas is not None else None,
        )
        return len(ids)

    def search(
        self,
        *,
        collection: str,
        query: str,
        n_results: int = 5,
        where: dict[str, Any] | None = None,
    ) -> list[VectorHit]:
        """Similarity search within a collection."""
        q = query.strip()
        if not q:
            raise ValueError("search query must be non-empty")
        coll = self.get_or_create_collection(collection)
        if coll.count() == 0:
            return []
        kwargs: dict[str, Any] = {
            "query_texts": [q],
            "n_results": min(n_results, max(1, coll.count())),
        }
        if where:
            kwargs["where"] = where
        raw = coll.query(**kwargs)
        ids = (raw.get("ids") or [[]])[0]
        docs = (raw.get("documents") or [[]])[0]
        metas = (raw.get("metadatas") or [[]])[0]
        dists = (raw.get("distances") or [[]])[0]
        hits: list[VectorHit] = []
        for idx, doc_id in enumerate(ids):
            hits.append(
                VectorHit(
                    id=str(doc_id),
                    document=str(docs[idx] or ""),
                    metadata=dict(metas[idx] or {}),
                    distance=float(dists[idx]) if dists and dists[idx] is not None else None,
                )
            )
        return hits

    def count(self, collection: str) -> int:
        """Return document count for a collection."""
        return int(self.get_or_create_collection(collection).count())

    def delete_collection(self, collection: str) -> None:
        """Drop a collection if it exists."""
        try:
            self._client.delete_collection(collection)
        except Exception:  # noqa: BLE001 — missing collection is fine
            return
