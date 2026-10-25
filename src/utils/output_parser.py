"""Structured extraction from tool stdout/stderr into findings-ready records."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ParsedHost:
    """Host discovered in tool output."""

    address: str
    hostname: str | None = None
    os_guess: str | None = None


@dataclass(frozen=True)
class ParsedService:
    """Service/port discovered in tool output."""

    address: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra: str | None = None


@dataclass(frozen=True)
class ParsedFinding:
    """Generic finding (path, vuln note, etc.)."""

    kind: str
    title: str
    detail: str | None = None
    address: str | None = None
    severity: str = "info"
    cvss: float | None = None
    source_tool: str | None = None


@dataclass
class ParsedOutput:
    """Aggregate structured extraction from one tool execution."""

    source_tool: str
    hosts: list[ParsedHost] = field(default_factory=list)
    services: list[ParsedService] = field(default_factory=list)
    findings: list[ParsedFinding] = field(default_factory=list)
    summary: str = ""

    @property
    def empty(self) -> bool:
        """True when nothing structured was extracted."""
        return not (self.hosts or self.services or self.findings)


_NMAP_PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$"
)
_NMAP_OS_RE = re.compile(r"^OS details:\s*(.+)$", re.IGNORECASE)
_NMAP_HOST_IP_RE = re.compile(r"^(.+) \((\d+\.\d+\.\d+\.\d+)\)$")
_NMAP_IP_ONLY_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+)$")
_STATUS_PATH_RE = re.compile(
    r"(?P<code>\d{3})\s+(?P<url>https?://\S+|/\S+)"
)


def _tool_name(argv: list[str]) -> str:
    if not argv:
        return "unknown"
    return Path(argv[0]).name.lower()


def parse_nmap_xml(text: str, *, source_tool: str = "nmap") -> ParsedOutput:
    """Parse nmap ``-oX`` XML into hosts/services."""
    out = ParsedOutput(source_tool=source_tool)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        if addr_el is None or not addr_el.get("addr"):
            continue
        address = addr_el.get("addr", "").strip()
        hostname = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name")
        os_guess = None
        os_el = host.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_guess = match.get("name")
        out.hosts.append(ParsedHost(address=address, hostname=hostname, os_guess=os_guess))

        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            portid = int(port.get("portid", "0"))
            proto = port.get("protocol", "tcp")
            service_el = port.find("service")
            service_name = product = version = extra = None
            if service_el is not None:
                service_name = service_el.get("name")
                product = service_el.get("product")
                version = service_el.get("version")
                extra = service_el.get("extrainfo")
            out.services.append(
                ParsedService(
                    address=address,
                    port=portid,
                    protocol=proto,
                    state=state or "unknown",
                    service_name=service_name,
                    product=product,
                    version=version,
                    extra=extra,
                )
            )
    out.summary = (
        f"nmap xml: {len(out.hosts)} host(s), {len(out.services)} service(s)"
    )
    return out


def parse_nmap_text(text: str, *, source_tool: str = "nmap") -> ParsedOutput:
    """Parse classic nmap normal output."""
    out = ParsedOutput(source_tool=source_tool)
    current_addr: str | None = None
    current_host: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("Nmap scan report for "):
            rest = line[len("Nmap scan report for ") :].strip()
            host_ip = _NMAP_HOST_IP_RE.match(rest)
            ip_only = _NMAP_IP_ONLY_RE.match(rest)
            if host_ip:
                current_host, current_addr = host_ip.group(1), host_ip.group(2)
            elif ip_only:
                current_addr, current_host = ip_only.group(1), None
            else:
                current_addr, current_host = rest, rest
            out.hosts.append(
                ParsedHost(address=current_addr, hostname=current_host)
            )
            continue
        if current_addr is None:
            continue
        os_m = _NMAP_OS_RE.match(line)
        if os_m:
            last = out.hosts[-1]
            out.hosts[-1] = ParsedHost(
                address=last.address, hostname=last.hostname, os_guess=os_m.group(1)
            )
            continue
        pm = _NMAP_PORT_RE.match(line)
        if pm:
            port, proto, state, service, rest = pm.groups()
            product = version = None
            if rest:
                parts = rest.split()
                if parts:
                    product = parts[0]
                if len(parts) > 1:
                    version = parts[1]
            out.services.append(
                ParsedService(
                    address=current_addr,
                    port=int(port),
                    protocol=proto,
                    state=state,
                    service_name=service if service != "unknown" else None,
                    product=product,
                    version=version,
                    extra=rest,
                )
            )
    out.summary = (
        f"nmap text: {len(out.hosts)} host(s), {len(out.services)} service(s)"
    )
    return out


def parse_json_blob(text: str, *, source_tool: str) -> ParsedOutput:
    """Best-effort parse of JSON tool output (arrays/objects with common keys)."""
    out = ParsedOutput(source_tool=source_tool)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out

    items: list[Any]
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        # ffuf-style / nuclei-style wrappers
        for key in ("results", "matches", "hosts", "data"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
        else:
            items = [data]
    else:
        return out

    for item in items:
        if not isinstance(item, dict):
            continue
        host = (
            item.get("host")
            or item.get("ip")
            or item.get("address")
            or item.get("hostip")
        )
        port = item.get("port")
        if host and port is not None:
            try:
                port_i = int(port)
            except (TypeError, ValueError):
                port_i = None
            if port_i is not None:
                out.hosts.append(ParsedHost(address=str(host)))
                out.services.append(
                    ParsedService(
                        address=str(host),
                        port=port_i,
                        protocol=str(item.get("protocol") or item.get("proto") or "tcp"),
                        state=str(item.get("state") or "open"),
                        service_name=item.get("service") or item.get("name"),
                        product=item.get("product"),
                        version=item.get("version"),
                    )
                )
        url = item.get("url") or item.get("input") or item.get("matched-at")
        if url:
            out.findings.append(
                ParsedFinding(
                    kind="path",
                    title=str(url),
                    detail=json.dumps(
                        {k: item.get(k) for k in ("status", "status-code", "length", "words", "template-id", "info") if k in item},
                        default=str,
                    ),
                    severity="info",
                    source_tool=source_tool,
                )
            )
        template = item.get("template-id") or item.get("templateID")
        if template:
            info = item.get("info") if isinstance(item.get("info"), dict) else {}
            severity = str((info or {}).get("severity") or item.get("severity") or "unknown")
            out.findings.append(
                ParsedFinding(
                    kind="vuln",
                    title=str(template),
                    detail=str((info or {}).get("name") or item.get("matched-at") or ""),
                    address=str(host) if host else None,
                    severity=severity.lower(),
                    source_tool=source_tool,
                )
            )
    out.summary = (
        f"json: {len(out.hosts)} host(s), {len(out.services)} service(s), "
        f"{len(out.findings)} finding(s)"
    )
    return out


def parse_path_discovery(text: str, *, source_tool: str) -> ParsedOutput:
    """Parse gobuster/ferox/ffuf-like path discovery lines."""
    out = ParsedOutput(source_tool=source_tool)
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        sm = _STATUS_PATH_RE.search(line)
        if sm:
            url = sm.group("url")
            code = sm.group("code")
            key = f"{code}:{url}"
            if key in seen:
                continue
            seen.add(key)
            out.findings.append(
                ParsedFinding(
                    kind="path",
                    title=url,
                    detail=f"status={code} raw={line[:200]}",
                    severity="info",
                    source_tool=source_tool,
                )
            )
            continue
        # gobuster dir: /admin (Status: 200)
        gm = re.search(r"(/\S+)\s+\(Status:\s*(\d{3})\)", line)
        if gm:
            path, code = gm.group(1), gm.group(2)
            key = f"{code}:{path}"
            if key in seen:
                continue
            seen.add(key)
            out.findings.append(
                ParsedFinding(
                    kind="path",
                    title=path,
                    detail=f"status={code}",
                    severity="info",
                    source_tool=source_tool,
                )
            )
    out.summary = f"paths: {len(out.findings)} finding(s)"
    return out


def _merge(a: ParsedOutput, b: ParsedOutput) -> ParsedOutput:
    """Merge two parse results (prefer non-empty summaries)."""
    return ParsedOutput(
        source_tool=a.source_tool or b.source_tool,
        hosts=[*a.hosts, *b.hosts],
        services=[*a.services, *b.services],
        findings=[*a.findings, *b.findings],
        summary=a.summary or b.summary,
    )


def parse_tool_output(
    argv: list[str],
    stdout: str,
    stderr: str = "",
) -> ParsedOutput:
    """
    Extract structured findings from a command's captured output.

    Prefers machine-readable forms (nmap XML, JSON) then falls back to text
    parsers. Returns an empty ``ParsedOutput`` when nothing matches.
    """
    tool = _tool_name(argv)
    blob = (stdout or "").strip()
    err = (stderr or "").strip()
    combined = blob if blob else err
    if not combined:
        return ParsedOutput(source_tool=tool, summary="empty output")

    # XML nmap
    if combined.lstrip().startswith("<?xml") or "<nmaprun" in combined[:2000]:
        parsed = parse_nmap_xml(combined, source_tool=tool)
        if not parsed.empty:
            return parsed

    # JSON
    if combined.lstrip()[:1] in "{[":
        parsed = parse_json_blob(combined, source_tool=tool)
        if not parsed.empty:
            return parsed

    result = ParsedOutput(source_tool=tool)

    if tool.startswith("nmap") or "Nmap scan report" in combined:
        result = _merge(result, parse_nmap_text(combined, source_tool=tool))

    if tool in {"gobuster", "feroxbuster", "ffuf", "dirb", "dirbuster"} or "Status:" in combined:
        result = _merge(result, parse_path_discovery(combined, source_tool=tool))

    if tool in {"nuclei"} and not result.findings:
        # nuclei often emits JSONL
        for line in combined.splitlines():
            line = line.strip()
            if line.startswith("{"):
                result = _merge(result, parse_json_blob(line, source_tool=tool))

    if not result.summary:
        result.summary = (
            f"{tool}: {len(result.hosts)} host(s), {len(result.services)} service(s), "
            f"{len(result.findings)} finding(s)"
        )
    return result


def format_parse_for_llm(parsed: ParsedOutput) -> str:
    """Compact structured digest for the orchestrator context."""
    if parsed.empty:
        return "structured_extract: (none)"
    lines = [f"structured_extract: {parsed.summary}"]
    for host in parsed.hosts[:20]:
        hn = f" ({host.hostname})" if host.hostname else ""
        os_g = f" os={host.os_guess}" if host.os_guess else ""
        lines.append(f"  host {host.address}{hn}{os_g}")
    for svc in parsed.services[:50]:
        svc_bits = " ".join(
            p for p in (svc.service_name, svc.product, svc.version) if p
        )
        lines.append(
            f"  service {svc.address}:{svc.port}/{svc.protocol} {svc.state} {svc_bits}".rstrip()
        )
    for finding in parsed.findings[:40]:
        lines.append(
            f"  finding[{finding.kind}/{finding.severity}] {finding.title}"
        )
    return "\n".join(lines)
