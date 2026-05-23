"""detectors/amass_detector.py

Subdomain enumeration via OWASP Amass (passive mode).
Complements subfinder by using a different set of data sources.
Runs once per root domain.
"""
from __future__ import annotations

import asyncio
import shutil
from typing import Any, Dict, List
from urllib.parse import urlparse

from detectors.registry import register_active, DetectorSkip


def _root_domain(url: str) -> str:
    return urlparse(url).hostname or ""


@register_active
async def amass_detector(session, url: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Enumerate subdomains for the target domain using Amass (passive)."""
    domain = _root_domain(url)
    if not domain:
        raise DetectorSkip("cannot extract domain from URL")

    cache_key = f"_amass_done_{domain}"
    if context.get(cache_key):
        raise DetectorSkip("already ran amass for this domain")
    context[cache_key] = True

    binary = shutil.which("amass")
    if not binary:
        raise DetectorSkip("`amass` binary not found in PATH")

    cmd = [binary, "enum", "-passive", "-d", domain]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise DetectorSkip("amass timed out after 180s")

    lines = (stdout or b"").decode("utf-8", errors="replace").strip().splitlines()
    subdomains = [ln.strip() for ln in lines if ln.strip() and domain in ln]

    if not subdomains:
        return []

    findings: List[Dict[str, Any]] = [
        {
            "type": "Subdomain Enumeration (Amass)",
            "severity": "info",
            "url": url,
            "detector": "amass_detector",
            "title": f"Amass: {len(subdomains)} subdomains found for {domain}",
            "description": (
                f"OWASP Amass (passive) discovered {len(subdomains)} subdomains under {domain} "
                "from public data sources (certificates, DNS, search engines)."
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
            "detector": "amass_detector",
            "title": f"Subdomain (amass): {sub}",
            "description": f"Amass (passive) found subdomain: {sub}",
            "evidence": sub,
            "confidence": "high",
            "category": "recon",
        })
    return findings
