"""detectors/ios_scanner_detector.py

iOS IPA static analysis detector.
Wraps mobile_scanner.ios.ios_scanner.iOSScanner for integration with the
standard scan pipeline via context['mobile_file_path'] / context['mobile_platform'].

Skips gracefully when no IPA file is present in context.
"""
from __future__ import annotations

import logging
import shutil
import tempfile
from typing import Any, Dict, List

from detectors.registry import register_active, DetectorSkip

logger = logging.getLogger(__name__)

_IOS_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}


@register_active
async def ios_scanner_detector(session, url: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Static security analysis of iOS IPA files."""
    file_path = context.get("mobile_file_path")
    platform = context.get("mobile_platform", "")

    if not file_path:
        raise DetectorSkip("no mobile_file_path in scan context")

    if platform and platform.lower() != "ios":
        raise DetectorSkip("mobile_platform is not ios")

    # Run once per scan
    if context.get("_ios_scanner_done"):
        raise DetectorSkip("already ran ios_scanner for this scan")
    context["_ios_scanner_done"] = True

    try:
        from mobile_scanner.ios.ios_scanner import iOSScanner
    except ImportError as exc:
        raise DetectorSkip(f"mobile_scanner.ios not available: {exc}") from exc

    tmp_dir = tempfile.mkdtemp(prefix="ipa_scan_")
    try:
        scanner = iOSScanner(file_path, output_dir=tmp_dir)
        report = scanner.scan()
    except Exception as exc:
        logger.warning("ios_scanner_detector: analysis failed: %s", exc)
        raise DetectorSkip(f"IPA analysis failed: {exc}") from exc
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    raw_findings = report.get("findings", [])
    findings: List[Dict[str, Any]] = []
    for f in raw_findings:
        sev_str = str(f.get("severity", "INFO")).upper()
        severity = _IOS_SEVERITY_MAP.get(sev_str, "info")
        cvss = float(f.get("cvss_score") or 0)
        evidence = f.get("evidence", "")
        if not isinstance(evidence, str):
            evidence = str(evidence)
        findings.append({
            "type": "iOS Security Finding",
            "severity": severity,
            "url": url,
            "detector": "ios_scanner_detector",
            "title": str(f.get("title", "iOS Finding"))[:255],
            "description": str(f.get("description", ""))[:2000],
            "evidence": evidence[:1000],
            "remediation": str(f.get("recommendation", ""))[:1000],
            "cvss_score": cvss or None,
            "confidence": "high" if cvss >= 7.0 else "medium",
            "category": "mobile",
            "raw_data": {
                "cwe": f.get("cwe_id", "") or f.get("cwe", ""),
                "owasp": f.get("owasp_mobile", ""),
                "source": "iOS IPA Static Analysis",
                "cvss_vector": f.get("cvss_vector", ""),
            },
        })

    logger.info("ios_scanner_detector: %d findings from IPA analysis", len(findings))
    return findings
