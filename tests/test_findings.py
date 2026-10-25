"""Real findings DB + output parser tests — no mocks."""

from __future__ import annotations

from pathlib import Path

from src.memory.findings_db import FindingsDB, scrub_secrets
from src.utils.output_parser import (
    format_parse_for_llm,
    parse_nmap_text,
    parse_nmap_xml,
    parse_path_discovery,
    parse_tool_output,
)
from src.workspace.manager import init_workspace

SAMPLE_NMAP = """
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for web.lab (10.10.20.5)
Host is up (0.0010s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
80/tcp   open  http    nginx 1.18.0
443/tcp  filtered https
OS details: Linux 5.4
"""

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.20.8" addrtype="ipv4"/>
    <hostnames><hostname name="db.lab"/></hostnames>
    <ports>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="8.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_scrub_secrets() -> None:
    """Secret-looking values are redacted before persistence."""
    text = scrub_secrets("Authorization: Bearer abc.def.ghi password=supersecret")
    assert "supersecret" not in text
    assert "abc.def.ghi" not in text
    assert "[REDACTED]" in text


def test_parse_nmap_text_extracts_hosts_and_ports() -> None:
    """Classic nmap text yields hosts + services."""
    parsed = parse_nmap_text(SAMPLE_NMAP)
    assert any(h.address == "10.10.20.5" for h in parsed.hosts)
    assert any(h.hostname == "web.lab" for h in parsed.hosts)
    ports = {(s.port, s.state) for s in parsed.services}
    assert (22, "open") in ports
    assert (80, "open") in ports
    assert (443, "filtered") in ports


def test_parse_nmap_xml() -> None:
    """nmap -oX XML parses into structured services."""
    parsed = parse_nmap_xml(SAMPLE_NMAP_XML)
    assert parsed.hosts[0].address == "10.10.20.8"
    assert parsed.hosts[0].hostname == "db.lab"
    assert parsed.services[0].port == 3306
    assert parsed.services[0].service_name == "mysql"


def test_parse_gobuster_paths() -> None:
    """Directory busting status lines become path findings."""
    text = """
    /admin (Status: 200)
    /login (Status: 302)
    """
    parsed = parse_path_discovery(text, source_tool="gobuster")
    titles = {f.title for f in parsed.findings}
    assert "/admin" in titles
    assert "/login" in titles


def test_findings_db_ingest_and_search(tmp_path: Path) -> None:
    """Parsed nmap output lands in SQLite and is searchable."""
    ws = init_workspace(tmp_path / "findings-lab", mode="unscoped", activate=False)
    db = FindingsDB(ws.findings_db)
    try:
        parsed = parse_tool_output(["nmap", "-sV", "10.10.20.5"], SAMPLE_NMAP)
        counts = db.ingest_parsed(parsed, session_id="sess1", evidence_path="/tmp/raw.txt")
        assert counts["hosts"] >= 1
        assert counts["services"] >= 1
        assert db.summary()["hosts"] >= 1
        hits = db.search("nginx")
        assert any(h.get("type") == "service" for h in hits) or any(
            "nginx" in str(h).lower() for h in hits
        )
        assert "10.10.20.5" in format_parse_for_llm(parsed)
    finally:
        db.close()


def test_secret_scrubbed_on_finding_write(tmp_path: Path) -> None:
    """Finding details scrub API-key shaped secrets."""
    db = FindingsDB(tmp_path / "scrub.db")
    try:
        db.add_finding(
            kind="note",
            title="leak",
            detail="api_key=ABCDEF123456 password=hunter2",
            severity="high",
        )
        row = db.list_findings()[0]
        assert "ABCDEF123456" not in (row.detail or "")
        assert "hunter2" not in (row.detail or "")
        assert "[REDACTED]" in (row.detail or "")
    finally:
        db.close()
