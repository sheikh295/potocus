"""Web & OSINT tools — free web search, URL fetch, CVE details."""

from __future__ import annotations

import os
import warnings
from typing import Any

MAX_CHARS = 12000


def web_search(query: str, max_results: int = 5) -> str:
    """Search the web (DuckDuckGo) for free."""
    if not query or not str(query).strip():
        return "web_search: query required"
    max_results = max(1, min(int(max_results), 10))
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from duckduckgo_search import DDGS

            with DDGS() as ddgs:
                results = list(ddgs.text(str(query), max_results=max_results))
    except Exception as exc:  # noqa: BLE001
        return f"web_search: error: {exc}"
    if not results:
        return f"web_search: no results for {query!r}"
    lines = [f"web_search: query={query!r} results={len(results)}"]
    for r in results:
        lines.append(
            f"- {r.get('title', '')}\n  {r.get('href', '')}\n  {r.get('body', '')}"
        )
    return "\n".join(lines)


def fetch_url(url: str, max_chars: int = MAX_CHARS) -> str:
    """Fetch and extract readable text from a URL."""
    if not url or not str(url).strip():
        return "fetch_url: url required"
    url = str(url).strip()
    text = ""
    try:
        import trafilatura

        downloaded = trafilatura.fetch_url(url)
        if downloaded:
            text = trafilatura.extract(downloaded) or ""
    except Exception as exc:  # noqa: BLE001
        text = ""
    if not text.strip():
        try:
            import requests

            resp = requests.get(url, timeout=20, headers={"User-Agent": "potocus/0.1"})
            resp.raise_for_status()
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup(["script", "style", "nav", "footer"]):
                tag.decompose()
            text = soup.get_text("\n", strip=True)
        except Exception as exc:  # noqa: BLE001
            return f"fetch_url: error fetching {url}: {exc}"
    if not text.strip():
        return f"fetch_url: no readable content from {url}"
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n... [{len(text)} chars total, truncated]"
    return f"fetch_url: {url}\n{text}"


def get_cve_details(cve_id: str) -> str:
    """Look up CVE details from NIST NVD (uses NVD_API_KEY if set)."""
    cve_id = str(cve_id).strip().upper()
    if not cve_id:
        return "get_cve_details: cve_id required"
    import httpx

    api_key = os.getenv("NVD_API_KEY") or os.getenv("NIST_NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    try:
        resp = httpx.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            headers=headers,
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return f"get_cve_details: error: {exc}"
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return f"get_cve_details: not found: {cve_id}"
    cve = vulns[0].get("cve", {})
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    metrics = cve.get("metrics", {})
    cvss = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            cvss = m.get("cvssData", {}).get("baseScore", "")
            if cvss:
                cvss = f"{cvss} ({m.get('cvssData', {}).get('baseSeverity', '')})"
            break
    lines = [f"get_cve_details: {cve_id}"]
    if cvss:
        lines.append(f"CVSS: {cvss}")
    if desc:
        lines.append(f"Description: {desc}")
    # references
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    if refs:
        lines.append("References:")
        for r in refs[:10]:
            lines.append(f"  - {r}")
    return "\n".join(lines)


def build_web_tools(runtime=None):
    from langchain_core.tools import tool as lc_tool

    @lc_tool("web_search")
    def web_search_tool(query: str, max_results: int = 5) -> str:
        """Search the web for information (DuckDuckGo, free).

        Args:
            query: Search query.
            max_results: Number of results.
        """
        return web_search(query, max_results=max_results)

    @lc_tool("fetch_url")
    def fetch_url_tool(url: str) -> str:
        """Fetch and read text content from a URL.

        Args:
            url: URL to fetch.
        """
        return fetch_url(url)

    @lc_tool("get_cve_details")
    def get_cve_details_tool(cve_id: str) -> str:
        """Look up CVE details from NIST NVD.

        Args:
            cve_id: CVE identifier, e.g. CVE-2021-44228.
        """
        return get_cve_details(cve_id)

    return [web_search_tool, fetch_url_tool, get_cve_details_tool]
