"""Workspace-scoped SQLite findings store (hosts, services, vulns, notes)."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from src.utils.output_parser import ParsedOutput

Severity = Literal["info", "low", "medium", "high", "critical", "unknown"]
FindingKind = Literal["host", "service", "path", "vuln", "cred", "note"]

_SECRET_PATTERNS = (
    re.compile(
        r"(?i)(authorization\s*:\s*bearer\s+)[a-z0-9\-._~+/]+=*",
    ),
    re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*"),
    re.compile(
        r"(?i)(api[_-]?key|token|secret|password|passwd)\s*[:=]\s*\S+",
    ),
    re.compile(
        r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END"
    ),
)


def scrub_secrets(text: str | None) -> str:
    """Redact common secret patterns before persisting to findings.db."""
    if not text:
        return ""
    scrubbed = text
    for pattern in _SECRET_PATTERNS:
        scrubbed = pattern.sub("[REDACTED]", scrubbed)
    return scrubbed


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class HostRecord:
    """A discovered host."""

    id: int
    address: str
    hostname: str | None
    os_guess: str | None
    first_seen: str
    last_seen: str


@dataclass(frozen=True)
class ServiceRecord:
    """An open/filtered service on a host."""

    id: int
    host_id: int
    port: int
    protocol: str
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    extra: str | None


@dataclass(frozen=True)
class FindingRecord:
    """A structured finding (path, vuln, note, …)."""

    id: int
    host_id: int | None
    kind: str
    title: str
    detail: str | None
    severity: str
    cvss: float | None
    evidence_path: str | None
    session_id: str | None
    source_tool: str | None
    created_at: str


class FindingsDB:
    """SQLite-backed findings store for one workspace."""

    def __init__(self, path: Path) -> None:
        """Open (or create) the findings database at ``path``."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self.ensure_schema()

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    def ensure_schema(self) -> None:
        """Create tables if missing."""
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY,
                address TEXT NOT NULL UNIQUE,
                hostname TEXT,
                os_guess TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY,
                host_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                service_name TEXT,
                product TEXT,
                version TEXT,
                extra TEXT,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
                UNIQUE(host_id, port, protocol)
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                host_id INTEGER,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT,
                severity TEXT NOT NULL DEFAULT 'unknown',
                cvss REAL,
                evidence_path TEXT,
                session_id TEXT,
                source_tool TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_kind ON findings(kind);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_hosts_address ON hosts(address);
            """
        )
        self._conn.commit()

    def upsert_host(
        self,
        address: str,
        *,
        hostname: str | None = None,
        os_guess: str | None = None,
    ) -> int:
        """Insert or update a host; return host id."""
        address = address.strip()
        if not address:
            raise ValueError("host address required")
        now = _utcnow()
        row = self._conn.execute(
            "SELECT id, hostname, os_guess FROM hosts WHERE address = ?",
            (address,),
        ).fetchone()
        if row is None:
            cur = self._conn.execute(
                """
                INSERT INTO hosts(address, hostname, os_guess, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                """,
                (address, hostname, os_guess, now, now),
            )
            self._conn.commit()
            return int(cur.lastrowid)
        new_hostname = hostname or row["hostname"]
        new_os = os_guess or row["os_guess"]
        self._conn.execute(
            """
            UPDATE hosts
            SET hostname = ?, os_guess = ?, last_seen = ?
            WHERE id = ?
            """,
            (new_hostname, new_os, now, row["id"]),
        )
        self._conn.commit()
        return int(row["id"])

    def upsert_service(
        self,
        host_id: int,
        *,
        port: int,
        protocol: str = "tcp",
        state: str = "open",
        service_name: str | None = None,
        product: str | None = None,
        version: str | None = None,
        extra: str | None = None,
    ) -> int:
        """Insert or update a service row; return service id."""
        protocol = (protocol or "tcp").lower()
        state = state or "open"
        row = self._conn.execute(
            """
            SELECT id FROM services
            WHERE host_id = ? AND port = ? AND protocol = ?
            """,
            (host_id, port, protocol),
        ).fetchone()
        if row is None:
            cur = self._conn.execute(
                """
                INSERT INTO services(
                    host_id, port, protocol, state, service_name, product, version, extra
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    host_id,
                    port,
                    protocol,
                    state,
                    service_name,
                    product,
                    version,
                    scrub_secrets(extra),
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)
        self._conn.execute(
            """
            UPDATE services
            SET state = ?, service_name = COALESCE(?, service_name),
                product = COALESCE(?, product),
                version = COALESCE(?, version),
                extra = COALESCE(?, extra)
            WHERE id = ?
            """,
            (
                state,
                service_name,
                product,
                version,
                scrub_secrets(extra) if extra else None,
                row["id"],
            ),
        )
        self._conn.commit()
        return int(row["id"])

    def add_finding(
        self,
        *,
        kind: FindingKind | str,
        title: str,
        detail: str | None = None,
        host_id: int | None = None,
        severity: Severity | str = "unknown",
        cvss: float | None = None,
        evidence_path: str | None = None,
        session_id: str | None = None,
        source_tool: str | None = None,
    ) -> int:
        """Insert a finding row; return its id."""
        cur = self._conn.execute(
            """
            INSERT INTO findings(
                host_id, kind, title, detail, severity, cvss,
                evidence_path, session_id, source_tool, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                host_id,
                str(kind),
                scrub_secrets(title)[:500],
                scrub_secrets(detail),
                str(severity or "unknown"),
                cvss,
                evidence_path,
                session_id,
                source_tool,
                _utcnow(),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def list_hosts(self) -> list[HostRecord]:
        """Return all hosts ordered by address."""
        rows = self._conn.execute(
            "SELECT * FROM hosts ORDER BY address"
        ).fetchall()
        return [
            HostRecord(
                id=int(r["id"]),
                address=r["address"],
                hostname=r["hostname"],
                os_guess=r["os_guess"],
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
            )
            for r in rows
        ]

    def list_services(self, host_id: int | None = None) -> list[ServiceRecord]:
        """Return services, optionally filtered by host."""
        if host_id is None:
            rows = self._conn.execute(
                "SELECT * FROM services ORDER BY host_id, port"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM services WHERE host_id = ? ORDER BY port",
                (host_id,),
            ).fetchall()
        return [
            ServiceRecord(
                id=int(r["id"]),
                host_id=int(r["host_id"]),
                port=int(r["port"]),
                protocol=r["protocol"],
                state=r["state"],
                service_name=r["service_name"],
                product=r["product"],
                version=r["version"],
                extra=r["extra"],
            )
            for r in rows
        ]

    def list_findings(
        self,
        *,
        kind: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[FindingRecord]:
        """Return recent findings with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self._conn.execute(
            f"""
            SELECT * FROM findings
            {where}
            ORDER BY id DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
        return [
            FindingRecord(
                id=int(r["id"]),
                host_id=int(r["host_id"]) if r["host_id"] is not None else None,
                kind=r["kind"],
                title=r["title"],
                detail=r["detail"],
                severity=r["severity"],
                cvss=float(r["cvss"]) if r["cvss"] is not None else None,
                evidence_path=r["evidence_path"],
                session_id=r["session_id"],
                source_tool=r["source_tool"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def search(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """
        Simple full-text-ish search across hosts/services/findings titles+details.

        Used by ``search_past_engagements`` for workspace-scoped recall.
        """
        q = f"%{query.strip()}%"
        if query.strip() == "":
            return []
        results: list[dict[str, Any]] = []

        for row in self._conn.execute(
            """
            SELECT id, address, hostname, os_guess FROM hosts
            WHERE address LIKE ? OR IFNULL(hostname,'') LIKE ? OR IFNULL(os_guess,'') LIKE ?
            LIMIT ?
            """,
            (q, q, q, limit),
        ):
            results.append(
                {
                    "type": "host",
                    "id": row["id"],
                    "address": row["address"],
                    "hostname": row["hostname"],
                    "os_guess": row["os_guess"],
                }
            )

        for row in self._conn.execute(
            """
            SELECT s.id, s.port, s.protocol, s.state, s.service_name, s.product, s.version,
                   h.address
            FROM services s JOIN hosts h ON h.id = s.host_id
            WHERE IFNULL(s.service_name,'') LIKE ?
               OR IFNULL(s.product,'') LIKE ?
               OR IFNULL(s.version,'') LIKE ?
               OR h.address LIKE ?
            LIMIT ?
            """,
            (q, q, q, q, limit),
        ):
            results.append(
                {
                    "type": "service",
                    "id": row["id"],
                    "address": row["address"],
                    "port": row["port"],
                    "protocol": row["protocol"],
                    "state": row["state"],
                    "service_name": row["service_name"],
                    "product": row["product"],
                    "version": row["version"],
                }
            )

        for row in self._conn.execute(
            """
            SELECT id, kind, title, detail, severity, source_tool, created_at
            FROM findings
            WHERE title LIKE ? OR IFNULL(detail,'') LIKE ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (q, q, limit),
        ):
            results.append(
                {
                    "type": "finding",
                    "id": row["id"],
                    "kind": row["kind"],
                    "title": row["title"],
                    "detail": (row["detail"] or "")[:500],
                    "severity": row["severity"],
                    "source_tool": row["source_tool"],
                    "created_at": row["created_at"],
                }
            )
        return results[:limit]

    def ingest_parsed(
        self,
        parsed: ParsedOutput,
        *,
        session_id: str | None = None,
        evidence_path: str | None = None,
    ) -> dict[str, int]:
        """
        Persist a ``ParsedOutput`` from the output parser.

        Returns counts of rows written/updated.
        """
        counts = {"hosts": 0, "services": 0, "findings": 0}
        host_ids: dict[str, int] = {}

        for host in parsed.hosts:
            hid = self.upsert_host(
                host.address, hostname=host.hostname, os_guess=host.os_guess
            )
            host_ids[host.address] = hid
            counts["hosts"] += 1

        for svc in parsed.services:
            hid = host_ids.get(svc.address) or self.upsert_host(svc.address)
            host_ids[svc.address] = hid
            self.upsert_service(
                hid,
                port=svc.port,
                protocol=svc.protocol,
                state=svc.state,
                service_name=svc.service_name,
                product=svc.product,
                version=svc.version,
                extra=svc.extra,
            )
            counts["services"] += 1
            # Also record a compact finding for open services.
            if svc.state == "open":
                title = f"{svc.address}:{svc.port}/{svc.protocol} open"
                detail_parts = [
                    p
                    for p in (svc.service_name, svc.product, svc.version)
                    if p
                ]
                self.add_finding(
                    kind="service",
                    title=title,
                    detail=" ".join(detail_parts) or None,
                    host_id=hid,
                    severity="info",
                    evidence_path=evidence_path,
                    session_id=session_id,
                    source_tool=parsed.source_tool,
                )
                counts["findings"] += 1

        for finding in parsed.findings:
            hid = None
            if finding.address:
                hid = host_ids.get(finding.address) or self.upsert_host(finding.address)
                host_ids[finding.address] = hid
                counts["hosts"] += 1
            self.add_finding(
                kind=finding.kind,
                title=finding.title,
                detail=finding.detail,
                host_id=hid,
                severity=finding.severity,
                cvss=finding.cvss,
                evidence_path=evidence_path,
                session_id=session_id,
                source_tool=parsed.source_tool or finding.source_tool,
            )
            counts["findings"] += 1

        return counts

    def summary(self) -> dict[str, int]:
        """Return basic counts for status displays."""
        hosts = self._conn.execute("SELECT COUNT(*) AS c FROM hosts").fetchone()["c"]
        services = self._conn.execute("SELECT COUNT(*) AS c FROM services").fetchone()["c"]
        findings = self._conn.execute("SELECT COUNT(*) AS c FROM findings").fetchone()["c"]
        return {
            "hosts": int(hosts),
            "services": int(services),
            "findings": int(findings),
        }

    def update_finding_severity(
        self,
        finding_id: int,
        *,
        severity: str,
        cvss: float | None = None,
    ) -> bool:
        """Update severity/CVSS for a finding. Returns False if id missing."""
        row = self._conn.execute(
            "SELECT id FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
        if row is None:
            return False
        self._conn.execute(
            "UPDATE findings SET severity = ?, cvss = ? WHERE id = ?",
            (severity, cvss, finding_id),
        )
        self._conn.commit()
        return True
