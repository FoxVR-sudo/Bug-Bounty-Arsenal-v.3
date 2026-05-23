"""detectors/httpx_detector.py

HTTP probing via httpx (ProjectDiscovery).
Probes a list of hosts (discovered from subfinder/amass stored in context)
and reports live hosts with technology stack, server version, status codes,
and titles — useful for quickly triaging the attack surface.
Runs once per scan session.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import os
from typing import Any, Dict, List
from urllib.parse import urlparse

from detectors.registry import register_active, DetectorSkip


def _root_domain(url: str) -> str:
    return urlparse(url).hostname or ""


@register_active
async def httpx_detector(session, url: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Probe discovered subdomains with httpx to find live hosts and enumerate tech stack."""
    domain = _root_domain(url)
    if not domain:
        raise DetectorSkip("cannot extract domain from URL")

    cache_key = f"_httpx_done_{domain}"
    if context.get(cache_key):
        raise DetectorSkip("already ran httpx for this domain")
    context[cache_key] = True

    binary = shutil.which("httpx")
    if not binary:
        raise DetectorSkip("`httpx` binary not found in PATH")

    # Gather all subdomains discovered by subfinder/amass in this session
    subfinder_subs = context.get(f"_subfinder_subs_{domain}", [])
    amass_subs = context.get(f"_amass_subs_{domain}", [])
    all_subs = list(dict.fromkeys([domain] + subfinder_subs + amass_subs))

    # Write hosts to temp file
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    try:
        tmp.write("\n".join(all_subs))
        tmp.close()

        cmd = [
            binary,
            "-list", tmp.name,
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-content-length",
            "-follow-redirects",
            "-threads", "50",
            "-timeout", "10",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=len(all_subs) * 2 + 60
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            raise DetectorSkip("httpx timed out")
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

    findings: List[Dict[str, Any]] = []
    live_count = 0

    for line in (stdout or b"").decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        host_url = data.get("url") or data.get("host") or ""
        if not host_url:
            continue

        status = data.get("status_code", 0)
        title = data.get("title", "")
        techs = data.get("technologies") or []
        webserver = data.get("webserver", "")
        content_length = data.get("content_length", 0)
        live_count += 1

        tech_str = ", ".join(techs) if techs else "unknown"
        evidence_parts = [
            f"URL: {host_url}",
            f"Status: {status}",
            f"Title: {title}" if title else "",
            f"Technologies: {tech_str}",
            f"Server: {webserver}" if webserver else "",
            f"Content-Length: {content_length}",
        ]
        evidence = "\n".join(p for p in evidence_parts if p)

        # Interesting findings: exposed panels, interesting status codes
        finding_type = "Live Host Discovered"
        severity = "info"
        if status in (401, 403):
            finding_type = "Protected Endpoint (401/403)"
            severity = "low"
        elif status == 200 and any(kw in title.lower() for kw in ("admin", "dashboard", "panel", "login", "manager")):
            finding_type = "Sensitive Panel Exposed"
            severity = "medium"
        elif any(kw in tech_str.lower() for kw in ("wordpress", "drupal", "joomla", "jenkins", "grafana", "kibana")):
            finding_type = "CMS/Service Detected"
            severity = "low"

        findings.append({
            "type": finding_type,
            "severity": severity,
            "url": host_url,
            "detector": "httpx_detector",
            "title": f"[httpx] {host_url} — HTTP {status}",
            "description": (
                f"httpx found live host at {host_url} "
                f"(status={status}, techs={tech_str or 'none'}, title='{title}')"
            ),
            "evidence": evidence,
            "status_code": status,
            "technologies": techs,
            "webserver": webserver,
            "confidence": "high",
            "category": "recon",
        })

    if not findings:
        return []

    # Prepend a summary finding
    findings.insert(0, {
        "type": "HTTP Probe Summary",
        "severity": "info",
        "url": url,
        "detector": "httpx_detector",
        "title": f"httpx: {live_count} live hosts probed for {domain}",
        "description": f"httpx probed {len(all_subs)} hosts and found {live_count} live.",
        "evidence": f"Total probed: {len(all_subs)}\nLive: {live_count}",
        "confidence": "high",
        "category": "recon",
    })
    return findings
