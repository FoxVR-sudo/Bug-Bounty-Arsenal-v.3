"""detectors/dalfox_detector.py

Automated XSS scanning via dalfox (hahwul).
Runs dalfox against the current URL when it contains reflection-friendly
parameters (q, query, search, s, name, msg, etc.).
Rate-limited to avoid running on every URL in a large scan.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

from detectors.registry import register_active, DetectorSkip

# Parameters that commonly reflect user input (potential XSS sinks)
_XSS_PARAMS = {
    "q", "query", "search", "s", "term", "keyword", "name", "title",
    "msg", "message", "content", "text", "comment", "input", "data",
    "redirect", "return", "url", "next", "ref", "page", "p",
    "value", "val", "str", "html", "body", "description",
}


def _has_xss_params(url: str) -> bool:
    qs = parse_qs(urlparse(url).query)
    return bool(set(k.lower() for k in qs) & _XSS_PARAMS)


@register_active
async def dalfox_detector(session, url: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan URL for XSS vulnerabilities using dalfox."""
    if not _has_xss_params(url):
        raise DetectorSkip("URL has no reflection-candidate parameters")

    # Rate-limit: cap to 20 dalfox runs per scan session
    counter_key = "_dalfox_count"
    count = context.get(counter_key, 0)
    if count >= 20:
        raise DetectorSkip("dalfox run limit (20) reached for this scan")
    context[counter_key] = count + 1

    binary = shutil.which("dalfox")
    if not binary:
        raise DetectorSkip("`dalfox` binary not found in PATH")

    blind_url = context.get("dalfox_blind_url") or context.get("blind_xss_url")

    cmd = [
        binary, "url", url,
        "--format", "json",
        "--silence",
        "--worker", "100",
        "--skip-bav",
        "--no-spinner",
    ]
    if blind_url:
        cmd += ["--blind", str(blind_url)]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise DetectorSkip("dalfox timed out after 90s")

    findings: List[Dict[str, Any]] = []
    for line in (stdout or b"").decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        finding_type = item.get("type", "")
        if finding_type not in ("G", "R", "V"):
            continue

        severity = "high" if finding_type == "V" else "medium"
        param = item.get("param", "")
        payload = item.get("payload", "")
        matched_url = item.get("data") or url
        evidence = item.get("evidence", "")

        label_map = {"V": "Verified XSS", "R": "Reflected XSS", "G": "Generic XSS Indicator"}
        vuln_label = label_map.get(finding_type, "XSS")

        findings.append({
            "type": vuln_label,
            "severity": severity,
            "url": matched_url,
            "detector": "dalfox_detector",
            "title": f"[dalfox] {vuln_label} — param: {param}",
            "description": (
                f"dalfox detected {vuln_label} in parameter '{param}'. "
                "Attacker can inject arbitrary JavaScript into the page."
            ),
            "evidence": evidence or f"Parameter: {param}\nPayload: {payload}",
            "payload": payload,
            "param": param,
            "confidence": "high" if finding_type == "V" else "medium",
            "needs_verification": finding_type != "V",
            "category": "web",
        })

    return findings
