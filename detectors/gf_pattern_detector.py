"""detectors/gf_pattern_detector.py

Pattern-based URL filtering using gf (tomnomnom/gf) built-in patterns.
Classifies the current URL into vulnerability categories (idor, ssrf, xss,
sqli, redirect, lfi, rce) and emits informational findings to guide
manual testing. Falls back to built-in regex if gf is not installed.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any, Dict, List

from detectors.registry import register_active, DetectorSkip

# Built-in fallback patterns (same as GfWrapper in tools/external_tools.py)
_PATTERNS: Dict[str, List[str]] = {
    "idor": [r"[?&](id|user_?id|account_?id|doc_?id|file_?id|order_?id)=\d+"],
    "ssrf": [
        r"[?&](url|uri|path|dest|destination|redirect|next|target|src|source|"
        r"host|endpoint|proxy|fetch|load|open)="
    ],
    "xss": [
        r"[?&](q|query|search|s|term|keyword|name|title|msg|message|"
        r"content|text|comment|input|data)="
    ],
    "sqli": [
        r"[?&](id|cat|num|page|type|sort|order|by|key|keyword|search|query|filter)=\d+"
    ],
    "redirect": [
        r"[?&](redirect|return|next|url|dest|destination|redir|go|r|link|forward)="
    ],
    "lfi": [
        r"[?&](file|filename|path|include|page|doc|document|folder|root|dir|"
        r"content|load|template)="
    ],
    "rce": [
        r"[?&](cmd|exec|command|run|shell|code|eval|system|ping|host|target)="
    ],
}

_SEVERITY_MAP = {
    "idor": ("high", "Potential IDOR Parameter"),
    "ssrf": ("high", "Potential SSRF Parameter"),
    "xss": ("medium", "Potential XSS Parameter"),
    "sqli": ("high", "Potential SQL Injection Parameter"),
    "redirect": ("medium", "Potential Open Redirect Parameter"),
    "lfi": ("high", "Potential LFI Parameter"),
    "rce": ("critical", "Potential RCE Parameter"),
}


def _match_pattern(url: str, pattern_name: str) -> bool:
    for rx in _PATTERNS.get(pattern_name, []):
        if re.search(rx, url, re.IGNORECASE):
            return True
    return False


def _gf_match(url: str, pattern_name: str) -> bool:
    """Try gf binary first, then fall back to built-in regex."""
    binary = shutil.which("gf")
    if binary:
        try:
            result = subprocess.run(
                [binary, pattern_name],
                input=url,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            return bool(result.stdout.strip())
        except Exception:
            pass
    return _match_pattern(url, pattern_name)


@register_active
async def gf_pattern_detector(session, url: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Classify URL by vulnerability category using gf patterns."""
    # Only analyse URLs with query parameters — gf is a query-string classifier
    if "?" not in url:
        raise DetectorSkip("URL has no query parameters — nothing to classify")

    findings: List[Dict[str, Any]] = []
    matched_patterns: List[str] = []

    for pattern, (severity, label) in _SEVERITY_MAP.items():
        if _gf_match(url, pattern):
            matched_patterns.append(pattern)
            findings.append({
                "type": f"GF Pattern Match: {pattern}",
                "severity": severity,
                "url": url,
                "detector": "gf_pattern_detector",
                "title": f"[gf] {label} — {url.split('?')[0]}",
                "description": (
                    f"gf pattern '{pattern}' matched this URL. "
                    f"The query parameters suggest susceptibility to {pattern.upper()}. "
                    "Manually verify and test this endpoint."
                ),
                "evidence": f"Pattern: {pattern}\nURL: {url}",
                "pattern": pattern,
                "confidence": "low",
                "needs_verification": True,
                "category": "recon",
            })

    if not findings:
        raise DetectorSkip("no gf patterns matched this URL")

    return findings
