"""detectors/subfinder_detector.py

Subdomain enumeration via subfinder (ProjectDiscovery).
Runs once per root domain and emits informational findings for each
discovered subdomain so they appear in the UI results panel.
"""
from __future__ import annotations

import asyncio
import shutil
from typing import Any, Dict, List
from urllib.parse import urlparse

from detectors.registry import register_active, DetectorSkip


def _root_domain(url: str) -> str:
    host = urlparse(url).hostname or ""
    return host


@register_active
async def subfinder_detector(session, url: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Enumerate subdomains for the target domain using subfinder."""
    domain = _root_domain(url)
    if not domain:
        raise DetectorSkip("cannot extract domain from URL")

    # Run once per domain per scan session
    cache_key = f"_subfinder_done_{domain}"
    if context.get(cache_key):
        raise DetectorSkip("already ran subfinder for this domain")
    context[cache_key] = True

    binary = shutil.which("subfinder")
    if not binary:
        raise DetectorSkip("`subfinder` binary not found in PATH")

    cmd = [binary, "-d", domain, "-silent", "-timeout", "30"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise DetectorSkip("subfinder timed out after 120s")

    lines = (stdout or b"").decode("utf-8", errors="replace").strip().splitlines()
    subdomains = [ln.strip() for ln in lines if ln.strip() and domain in ln]

    if not subdomains:
        return []

    findings: List[Dict[str, Any]] = [
        {
            "type": "Subdomain Enumeration",
            "severity": "info",
            "url": url,
            "detector": "subfinder_detector",
            "title": f"Subfinder: {len(subdomains)} subdomains found for {domain}",
            "description": (
                f"Subfinder discovered {len(subdomains)} subdomains under {domain}. "
                "Each subdomain is an additional attack surface."
            ),
            "evidence": "\n".join(subdomains),
            "subdomains": subdomains,
            "confidence": "high",
            "category": "recon",
        }
    ]
    for sub in subdomains:
        findings.append({
            "type": "Subdomain Discovered",
            "severity": "info",
            "url": f"https://{sub}",
            "detector": "subfinder_detector",
            "title": f"Subdomain: {sub}",
            "description": f"Subfinder found subdomain: {sub}",
            "evidence": sub,
            "confidence": "high",
            "category": "recon",
        })
    return findings
