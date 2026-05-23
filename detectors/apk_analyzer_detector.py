"""detectors/apk_analyzer_detector.py

Android APK static analysis detector.
Wraps mobile_scanner.apk_analyzer.APKAnalyzer for integration with the
standard scan pipeline via context['mobile_file_path'] / context['mobile_platform'].

Skips gracefully when no APK file is present in context.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from detectors.registry import register_active, DetectorSkip

logger = logging.getLogger(__name__)


@register_active
async def apk_analyzer_detector(session, url: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Static security analysis of Android APK files."""
    file_path = context.get("mobile_file_path")
    platform = context.get("mobile_platform", "")

    if not file_path:
        raise DetectorSkip("no mobile_file_path in scan context")

    if platform and platform.lower() != "android":
        raise DetectorSkip("mobile_platform is not android")

    # Run once per scan
    if context.get("_apk_analyzer_done"):
        raise DetectorSkip("already ran apk_analyzer for this scan")
    context["_apk_analyzer_done"] = True

    try:
        from mobile_scanner.apk_analyzer import APKAnalyzer
    except ImportError as exc:
        raise DetectorSkip(f"mobile_scanner not available: {exc}") from exc

    try:
        analyzer = APKAnalyzer(file_path)
        raw = analyzer.analyze()
    except Exception as exc:
        logger.warning("apk_analyzer_detector: analysis failed: %s", exc)
        raise DetectorSkip(f"APK analysis failed: {exc}") from exc

    findings: List[Dict[str, Any]] = []
    for f in raw:
        cvss = float(f.get("cvss_score") or 0)
        severity = str(f.get("severity", "info")).lower()
        findings.append({
            "type": "Android Security Finding",
            "severity": severity,
            "url": url,
            "detector": "apk_analyzer_detector",
            "title": str(f.get("title", "Android Finding"))[:255],
            "description": str(f.get("description", ""))[:2000],
            "evidence": str(f.get("evidence", ""))[:1000],
            "remediation": str(f.get("recommendation", ""))[:1000],
            "cvss_score": cvss or None,
            "confidence": "high" if cvss >= 7.0 else "medium",
            "category": "mobile",
            "raw_data": {
                "cwe": f.get("cwe", ""),
                "owasp": f.get("owasp", ""),
                "source": "Android APK Static Analysis",
            },
        })

    logger.info("apk_analyzer_detector: %d findings from APK analysis", len(findings))
    return findings
