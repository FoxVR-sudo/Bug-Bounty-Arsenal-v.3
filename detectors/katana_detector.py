"""detectors/katana_detector.py

JS-aware web crawling via katana (ProjectDiscovery).
Crawls the target and emits findings for hidden endpoints, API routes,
and form action URLs discovered via JS parsing.
Runs once per origin (scheme+host) per scan session.
"""
from __future__ import annotations

import asyncio
import shutil
from typing import Any, Dict, List
from urllib.parse import urlparse

from detectors.registry import register_active, DetectorSkip

_INTERESTING = {
    "api", "admin", "internal", "graphql", "upload", "debug",
    "download", "export", "import", "token", "auth", "login",
    "register", "reset", "password", "config", "settings",
    "v1", "v2", "v3",
}


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.hostname}"


def _is_interesting(endpoint: str) -> bool:
    low = endpoint.lower()
    return any(kw in low for kw in _INTERESTING)


@register_active
async def katana_detector(session, url: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Crawl the target with katana and surface hidden/interesting endpoints."""
    origin = _origin(url)
    if not origin:
        raise DetectorSkip("cannot extract origin from URL")

    cache_key = f"_katana_done_{origin}"
    if context.get(cache_key):
        raise DetectorSkip("already ran katana for this origin")
    context[cache_key] = True

    binary = shutil.which("katana")
    if not binary:
        raise DetectorSkip("`katana` binary not found in PATH")

    cmd = [
        binary,
        "-u", url,
        "-d", "3",
        "-js-crawl",
        "-silent",
        "-c", "10",
        "-rate-limit", "150",
        "-timeout", "10",
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise DetectorSkip("katana timed out after 300s")

    all_endpoints = [
        ln.strip() for ln in
        (stdout or b"").decode("utf-8", errors="replace").splitlines()
        if ln.strip() and ln.strip().startswith("http")
    ]
    interesting = [e for e in all_endpoints if _is_interesting(e)]

    findings: List[Dict[str, Any]] = []

    if not all_endpoints:
        return []

    # Summary finding
    findings.append({
        "type": "Web Crawl Summary",
        "severity": "info",
        "url": url,
        "detector": "katana_detector",
        "title": f"Katana: {len(all_endpoints)} endpoints crawled ({len(interesting)} interesting)",
        "description": (
            f"Katana JS-aware crawl discovered {len(all_endpoints)} unique endpoints. "
            f"{len(interesting)} endpoints contain keywords associated with sensitive functionality."
        ),
        "evidence": "\n".join(all_endpoints[:50]),
        "confidence": "high",
        "category": "recon",
    })

    # Keep interesting endpoints visible, but aggregate them as recon context
    # instead of emitting one low-severity finding per endpoint.
    if interesting:
        findings.append({
            "type": "Interesting Endpoints Discovered",
            "severity": "info",
            "url": url,
            "detector": "katana_detector",
            "title": f"[katana] {len(interesting[:50])} interesting endpoints discovered",
            "description": (
                "Katana crawl found endpoints whose paths contain keywords "
                "associated with sensitive functionality. Review them as recon "
                "leads, not confirmed vulnerabilities."
            ),
            "evidence": "\n".join(interesting[:50]),
            "confidence": "medium",
            "category": "recon",
        })

    return findings
