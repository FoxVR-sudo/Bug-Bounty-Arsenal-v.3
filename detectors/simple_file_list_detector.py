"""Simple File List vulnerability detector (CVE-2025-34085).

Identifies vulnerable Simple File List plugin installations (WordPress) by
checking the exposed plugin readme and rename endpoint. Detection is passive
and does not upload or modify any files.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from detectors.registry import await_host_token, register_active

logger = logging.getLogger(__name__)

VULN_VERSION_THRESHOLD = (4, 2, 3)
VERSION_PATTERN = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")
READ_ME_PATTERNS = (
    re.compile(r"^Stable\s+tag:\s*([\w.-]+)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^Version:\s*([\w.-]+)", re.IGNORECASE | re.MULTILINE),
)


def _parse_version(raw: str) -> Optional[Tuple[int, int, int]]:
    if not raw:
        return None
    match = VERSION_PATTERN.search(raw)
    if not match:
        return None
    major = int(match.group(1) or 0)
    minor = int(match.group(2) or 0)
    patch = int(match.group(3) or 0)
    return major, minor, patch


async def _safe_fetch(session, target_url: str, host: str, timeout: float, rate: Optional[float]) -> Tuple[Optional[int], Optional[str], Dict[str, str]]:
    # Throttle only if rate is a valid float > 0
    if isinstance(rate, (int, float)) and rate > 0:
        await await_host_token(host, float(rate))
    try:
        async with session.get(target_url, allow_redirects=True, timeout=timeout) as resp:
            text = await resp.text(errors="ignore")
            return resp.status, text, dict(resp.headers)
    except Exception as exc:
        logger.debug("Simple File List detector request failed for %s: %s", target_url, exc)
        return None, None, {}


@register_active
async def simple_file_list_detector(session, url: str, context: Dict) -> List[Dict]:
    findings: List[Dict] = []

    if context.get("__simple_file_list_checked__"):
        return findings
    context["__simple_file_list_checked__"] = True

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return findings

    host = parsed.netloc.lower()
    timeout = float(context.get("timeout", 10))
    rate = context.get("per_host_rate")

    base = f"{parsed.scheme}://{parsed.netloc}"
    plugin_base = urljoin(base, "/wp-content/plugins/simple-file-list/")
    readme_url = urljoin(plugin_base, "readme.txt")
    engine_url = urljoin(plugin_base, "ee-file-engine.php")

    readme_status, readme_body, _ = await _safe_fetch(session, readme_url, host, timeout, rate)

    detected_version: Optional[Tuple[int, int, int]] = None
    detected_version_raw: str = ""

    if readme_body:
        for pattern in READ_ME_PATTERNS:
            match = pattern.search(readme_body)
            if match:
                raw = match.group(1)
                if raw:
                    detected_version_raw = raw
                    detected_version = _parse_version(detected_version_raw)
                break

    engine_status, _, _ = await _safe_fetch(session, engine_url, host, timeout, rate)

    engine_accessible = False
    if engine_status and 200 <= engine_status < 400:
        engine_accessible = True
    elif engine_status in {401, 403, 405}:
        # Endpoint exists but secured; still interesting when version is vulnerable.
        engine_accessible = True

    if detected_version and detected_version < VULN_VERSION_THRESHOLD and engine_accessible:
        findings.append({
            "type": "Simple File List RCE (CVE-2025-34085)",
            "severity": "high",
            "how_found": "Simple File List detector (safe checks)",
            "evidence": (
                f"Plugin version {detected_version_raw} detected via readme.txt; "
                f"rename engine reachable at {engine_url} (HTTP {engine_status})."
            ),
            "payload": None,
        })
        return findings

    if detected_version and detected_version < VULN_VERSION_THRESHOLD:
        findings.append({
            "type": "Simple File List outdated (CVE-2025-34085)",
            "severity": "medium",
            "how_found": "Simple File List detector (version check)",
            "evidence": (
                f"Plugin readme.txt indicates version {detected_version_raw}, which is vulnerable (< 4.2.3)."
            ),
            "payload": None,
        })
        return findings

    if engine_accessible and (readme_status == 404 or readme_status is None):
        findings.append({
            "type": "Simple File List rename endpoint exposed",
            "severity": "low",
            "how_found": "Simple File List detector (endpoint discovery)",
            "evidence": (
                f"ee-file-engine.php responded with HTTP {engine_status}; version could not be determined."
            ),
            "payload": None,
        })

    return findings
