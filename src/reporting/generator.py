"""Compile workspace findings.db (+ session metas) into deliverable reports."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.memory.findings_db import FindingsDB
from src.utils.secrets import scrub_secrets
from src.workspace.manager import Workspace
from src.workspace.session_store import list_session_ids, read_session_meta

ReportFormat = Literal["md", "pdf", "docx"]
TemplateName = Literal["pentest", "bug_bounty", "research"]

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


@dataclass(frozen=True)
class ReportResult:
    """Path and metadata for a generated report."""

    path: Path
    format: ReportFormat
    template: TemplateName
    markdown: str


def _templates_env() -> Environment:
    """Jinja environment rooted at the shipped (editable) templates dir."""
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(enabled_extensions=()),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _load_scope_targets(workspace: Workspace) -> list[dict[str, str]]:
    """Read scope.yaml targets when present."""
    if workspace.mode != "scoped" or not workspace.scope_yaml.exists():
        return []
    with workspace.scope_yaml.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    targets: list[dict[str, str]] = []
    for entry in data.get("targets") or []:
        if isinstance(entry, dict) and entry.get("target"):
            targets.append(
                {"target": str(entry["target"]), "note": str(entry.get("note") or "")}
            )
        elif isinstance(entry, str):
            targets.append({"target": entry, "note": ""})
    return targets


def _session_rows(workspace: Workspace) -> list[dict[str, Any]]:
    """Collect session.yaml rows for the report appendix."""
    rows: list[dict[str, Any]] = []
    for sid in list_session_ids(workspace):
        try:
            rows.append(read_session_meta(workspace, sid))
        except FileNotFoundError:
            continue
    return rows


def build_report_context(workspace: Workspace) -> dict[str, Any]:
    """Assemble the template context from findings.db and session metadata."""
    db = FindingsDB(workspace.findings_db)
    try:
        hosts = db.list_hosts()
        services = db.list_services()
        findings = db.list_findings(limit=10_000)
        summary = db.summary()
    finally:
        db.close()

    findings_sorted = sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), -f.id),
    )
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }
    for finding in findings_sorted:
        key = finding.severity if finding.severity in severity_counts else "unknown"
        severity_counts[key] += 1

    return {
        "workspace": {
            "name": workspace.name,
            "root": str(workspace.root),
            "mode": workspace.mode,
            "pacing": workspace.pacing,
            "output_dir": str(workspace.output_dir),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hosts": hosts,
        "services": services,
        "findings": findings_sorted,
        "summary": summary,
        "severity_counts": severity_counts,
        "scope_targets": _load_scope_targets(workspace),
        "sessions": _session_rows(workspace),
    }


def render_markdown(
    workspace: Workspace,
    *,
    template: TemplateName = "pentest",
) -> str:
    """Render the engagement report as Markdown using a Jinja template."""
    template_file = f"{template}.md.j2"
    path = TEMPLATES_DIR / template_file
    if not path.exists():
        available = sorted(p.stem.replace(".md", "") for p in TEMPLATES_DIR.glob("*.md.j2"))
        raise FileNotFoundError(
            f"Unknown template {template!r}. Available: {available}"
        )
    env = _templates_env()
    tmpl = env.get_template(template_file)
    return tmpl.render(**build_report_context(workspace))


def _safe_slug(name: str) -> str:
    """Filesystem-safe slug from workspace name."""
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip()).strip("-").lower()
    return slug or "potocus-report"


def _write_markdown(path: Path, markdown: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown, encoding="utf-8")


def _write_docx(path: Path, markdown: str, title: str) -> None:
    """Write a simple DOCX by splitting markdown into paragraphs/headings."""
    from docx import Document

    doc = Document()
    doc.add_heading(title, level=0)
    for line in markdown.splitlines():
        if line.startswith("# "):
            doc.add_heading(line[2:].strip(), level=1)
        elif line.startswith("## "):
            doc.add_heading(line[3:].strip(), level=2)
        elif line.startswith("### "):
            doc.add_heading(line[4:].strip(), level=3)
        elif line.startswith("|") or line.startswith("---") or line.strip() == "":
            # Tables stay as plain lines for fidelity without a full MD table parser.
            if line.strip():
                doc.add_paragraph(line)
        elif line.startswith("- "):
            doc.add_paragraph(line[2:].strip(), style="List Bullet")
        else:
            doc.add_paragraph(line)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(path))


def _write_pdf(path: Path, markdown: str, title: str) -> None:
    """Write a PDF using fpdf2 (Unicode-safe via built-in core fonts + latin fallback)."""
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)

    def _line(text: str, *, height: float = 5) -> None:
        # multi_cell can leave the cursor at the right margin; always reset X.
        pdf.set_x(pdf.l_margin)
        usable = max(20, int(pdf.epw))
        # Hard-wrap absurdly long table rows so fpdf never stalls.
        chunk = text if len(text) <= 500 else text[:500] + "..."
        pdf.multi_cell(usable, height, chunk)

    _line(_pdf_safe(title), height=10)
    pdf.ln(4)
    pdf.set_font("Helvetica", size=11)

    for line in markdown.splitlines():
        text = _pdf_safe(line)
        if line.startswith("# "):
            pdf.set_font("Helvetica", "B", 14)
            _line(text[2:].strip(), height=8)
            pdf.set_font("Helvetica", size=11)
        elif line.startswith("## "):
            pdf.set_font("Helvetica", "B", 12)
            _line(text[3:].strip(), height=7)
            pdf.set_font("Helvetica", size=11)
        elif line.startswith("### "):
            pdf.set_font("Helvetica", "B", 11)
            _line(text[4:].strip(), height=6)
            pdf.set_font("Helvetica", size=11)
        elif not line.strip():
            pdf.ln(3)
        else:
            _line(text, height=5)
    path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(path))


def _pdf_safe(text: str) -> str:
    """Replace characters outside latin-1 so core PDF fonts do not crash."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def generate_report(
    workspace: Workspace,
    *,
    fmt: ReportFormat = "md",
    template: TemplateName = "pentest",
    output_dir: Path | None = None,
) -> ReportResult:
    """
    Generate a report into the workspace output directory.

    Always renders Markdown from the selected template, then writes the requested
    format (``md``, ``pdf``, or ``docx``).
    """
    if fmt not in ("md", "pdf", "docx"):
        raise ValueError(f"Unsupported format: {fmt}")
    if template not in ("pentest", "bug_bounty", "research"):
        raise ValueError(f"Unsupported template: {template}")

    markdown = scrub_secrets(render_markdown(workspace, template=template))
    out_dir = Path(output_dir) if output_dir else workspace.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"{_safe_slug(workspace.name)}-{template}-{stamp}"

    if fmt == "md":
        path = out_dir / f"{base}.md"
        _write_markdown(path, markdown)
    elif fmt == "docx":
        path = out_dir / f"{base}.docx"
        _write_docx(path, markdown, title=f"{workspace.name} — {template}")
    else:
        path = out_dir / f"{base}.pdf"
        _write_pdf(path, markdown, title=f"{workspace.name} — {template}")

    return ReportResult(path=path, format=fmt, template=template, markdown=markdown)


def list_templates() -> list[str]:
    """Return available report template names."""
    return sorted(p.name.replace(".md.j2", "") for p in TEMPLATES_DIR.glob("*.md.j2"))
