"""Real report generation tests — writes md/pdf/docx from findings.db."""

from __future__ import annotations

from pathlib import Path

from src.memory.findings_db import FindingsDB
from src.reporting.generator import generate_report, list_templates, render_markdown
from src.utils.output_parser import parse_nmap_text
from src.workspace.manager import init_workspace
from src.workspace.session_store import write_session_meta

SAMPLE_NMAP = """
Nmap scan report for app.lab (10.10.20.50)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9
80/tcp   open  http    nginx 1.22
"""


def _seed_workspace(tmp_path: Path):
    ws = init_workspace(tmp_path / "report-lab", mode="scoped", activate=False)
    db = FindingsDB(ws.findings_db)
    try:
        parsed = parse_nmap_text(SAMPLE_NMAP)
        db.ingest_parsed(parsed, session_id="sessreport01")
        fid = db.add_finding(
            kind="vuln",
            title="Outdated nginx",
            detail="nginx 1.22 may be outdated",
            severity="medium",
            cvss=5.3,
            source_tool="manual",
            session_id="sessreport01",
        )
        assert fid > 0
    finally:
        db.close()

    sid = "sessreport01"
    (ws.sessions_dir / sid / "checkpoints").mkdir(parents=True)
    write_session_meta(
        ws,
        sid,
        {
            "id": sid,
            "name": "external",
            "phase": "ENUMERATION",
            "target_focus": "10.10.20.50",
            "status": "open",
            "updated_at": "2026-01-02T00:00:00+00:00",
            "message_count": 4,
        },
    )
    return ws


def test_list_templates() -> None:
    """Shipped templates are discoverable."""
    names = list_templates()
    assert "pentest" in names
    assert "bug_bounty" in names
    assert "research" in names


def test_render_markdown_includes_findings(tmp_path: Path) -> None:
    """Markdown report contains hosts and vuln content from the DB."""
    ws = _seed_workspace(tmp_path)
    md = render_markdown(ws, template="pentest")
    assert "10.10.20.50" in md
    assert "Outdated nginx" in md
    assert "Penetration Test Report" in md


def test_generate_md_pdf_docx(tmp_path: Path) -> None:
    """All three formats write non-empty files under output_dir."""
    ws = _seed_workspace(tmp_path)
    out = tmp_path / "out"
    md = generate_report(ws, fmt="md", template="pentest", output_dir=out)
    pdf = generate_report(ws, fmt="pdf", template="bug_bounty", output_dir=out)
    docx = generate_report(ws, fmt="docx", template="research", output_dir=out)

    assert md.path.exists() and md.path.stat().st_size > 100
    assert pdf.path.exists() and pdf.path.stat().st_size > 100
    assert docx.path.exists() and docx.path.stat().st_size > 100
    assert md.path.suffix == ".md"
    assert pdf.path.suffix == ".pdf"
    assert docx.path.suffix == ".docx"
    assert "Outdated nginx" in md.markdown
