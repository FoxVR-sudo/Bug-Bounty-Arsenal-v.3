"""detectors/nuclei_detector.py

Nuclei integration with:
  - Auto-template-update (via utils.auto_update) when templates are > 24h stale
  - Confidence scoring based on template type / tags / severity
  - verified=True for templates tagged `verified` in the Nuclei community

Template auto-update is fire-and-forget: the scan proceeds even if the update
fails (e.g. no internet).  The update runs at most once per 24h.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from typing import Any, Dict, List, Optional

from detectors.registry import register_active, DetectorSkip


def _find_templates_dir(context: dict) -> Optional[str]:
    # Explicit context override
    templates = context.get("nuclei_templates") if isinstance(context, dict) else None
    if templates:
        return str(templates)

    # Common env vars
    for key in ("NUCLEI_TEMPLATES", "NUCLEI_TEMPLATE_DIR", "NUCLEI_TEMPLATES_DIR"):
        val = os.environ.get(key)
        if val:
            return val

    # Common locations (nuclei stores templates in ~/nuclei-templates by default)
    candidates = [
        os.path.expanduser("~/nuclei-templates"),
        os.path.expanduser("~/.local/share/nuclei-templates"),
        "/usr/share/nuclei-templates",
        "/opt/nuclei-templates",
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c

    return None


# ── Confidence mapping ────────────────────────────────────────────────────────

def _nuclei_confidence(item: dict) -> int:
    """
    Map Nuclei finding metadata to an integer confidence score (0-100).

    Rules (highest wins):
      - Template tagged `verified`                       → 90
      - Active HTTP matcher (http protocol)              → 75-85 based on severity
      - DNS / network matcher                            → 70
      - File / passive matcher                           → 55
      - Default                                          → 60
    """
    info     = item.get("info") or {}
    tags     = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    tags_set = {t.lower() for t in tags}

    severity = (info.get("severity") or "low").lower()
    protocol = (item.get("type") or item.get("protocol") or "").lower()

    # Nuclei community-verified templates get highest confidence
    if "verified" in tags_set:
        return 90

    # Active HTTP-based detections depend on severity
    if protocol in ("http", "https", ""):
        sev_boost = {"critical": 85, "high": 80, "medium": 75, "low": 65, "info": 50}
        return sev_boost.get(severity, 70)

    # DNS / network probes
    if protocol in ("dns", "network", "tcp", "udp"):
        return 70

    # File / code analysis
    if protocol in ("file", "code"):
        return 55

    return 60


def _nuclei_verified(item: dict) -> bool:
    """True if this finding comes from a Nuclei `verified`-tagged template."""
    info = item.get("info") or {}
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    return "verified" in {t.lower() for t in tags}


# ── Auto-update helper ────────────────────────────────────────────────────────

async def _maybe_update_templates(nuclei_path: str) -> None:
    """Fire-and-forget template update — errors are logged, not raised."""
    try:
        from utils.auto_update import update_nuclei_templates, is_stale
        if not is_stale("nuclei_templates", max_age_hours=24):
            return
        import logging
        log = logging.getLogger(__name__)
        log.info("nuclei_detector: templates stale — triggering background update")
        result = await update_nuclei_templates(nuclei_path)
        if result.get("status") == "ok":
            log.info("nuclei_detector: templates updated")
        elif result.get("status") != "skipped":
            log.warning("nuclei_detector: template update failed: %s", result.get("reason"))
    except Exception:
        pass  # update is best-effort


# ── Main detector ─────────────────────────────────────────────────────────────

@register_active
async def nuclei_detector(session, url: str, context: Dict[str, Any]):
    """Run nuclei against a single URL and translate JSONL output to findings."""

    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        raise DetectorSkip("`nuclei` binary not found in PATH")

    templates_dir = _find_templates_dir(context)
    if not templates_dir or not os.path.isdir(templates_dir):
        raise DetectorSkip("Nuclei templates not found; set NUCLEI_TEMPLATES or context['nuclei_templates']")

    # Kick off auto-update in the background (won't delay this scan)
    asyncio.ensure_future(_maybe_update_templates(nuclei_path))

    timeout_s       = int(context.get("nuclei_timeout", 90))
    severity_filter = context.get("nuclei_severity") or "low,medium,high,critical"
    rate_limit      = int(context.get("nuclei_rate_limit", 150))  # req/sec cap

    cmd = [
        nuclei_path,
        "-u",          url,
        "-t",          templates_dir,
        "-jsonl",
        "-silent",
        "-severity",   str(severity_filter),
        "-rate-limit", str(rate_limit),
        "-no-color",
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise DetectorSkip(f"nuclei timed out after {timeout_s}s")

    out_text = (stdout or b"").decode("utf-8", errors="replace")
    err_text = (stderr or b"").decode("utf-8", errors="replace").strip()

    findings: List[Dict[str, Any]] = []

    for line in out_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue

        info        = item.get("info") or {}
        template_id = item.get("template-id") or item.get("templateID") or "unknown"
        name        = info.get("name") or template_id
        severity    = (info.get("severity") or "low").lower()

        matched_at   = item.get("matched-at") or item.get("host") or url
        matcher_name = item.get("matcher-name")
        extracted    = item.get("extracted-results") or []
        references   = info.get("reference") or info.get("references") or []
        if isinstance(references, str):
            references = [references]

        evidence_parts = [f"matched_at={matched_at}"]
        if matcher_name:
            evidence_parts.append(f"matcher={matcher_name}")
        if extracted:
            evidence_parts.append(f"extracted={extracted[:3]}")

        confidence = _nuclei_confidence(item)
        verified   = _nuclei_verified(item)

        # Extracted data in findings confirms the finding is real
        if extracted:
            confidence = min(100, confidence + 10)
            verified   = True

        findings.append({
            "url":          url,
            "type":         f"Nuclei: {name}",
            "severity":     severity,
            "description":  f"Nuclei template match: {name} ({template_id})",
            "evidence":     "; ".join(evidence_parts),
            "how_found":    "nuclei",
            "detector":     "nuclei_detector",
            "template_id":  template_id,
            "tags":         info.get("tags"),
            "references":   references[:5],
            "confidence":   confidence,
            "verified":     verified,
        })

    if not findings and err_text and proc.returncode not in (0, None):
        raise DetectorSkip(f"nuclei error: {err_text[:200]}")

    return findings

