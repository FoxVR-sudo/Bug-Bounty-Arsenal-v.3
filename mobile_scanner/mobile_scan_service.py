"""
mobile_scanner/mobile_scan_service.py

Unified service for mobile app security scanning.
Supports .apk (Android) and .ipa (iOS) files.

Dispatches to:
  - APKAnalyzer   — pure Python, no external tools required
  - iOSScanner    — pure Python except optional `otool` for binary checks

Returns a list of normalised finding dicts compatible with
scans.models.Vulnerability bulk_create.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# ── Severity normalisation ─────────────────────────────────────────────────

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "HIGH": "high",
    "MEDIUM": "medium",
    "medium": "medium",
    "LOW": "low",
    "low": "low",
    "INFO": "info",
    "INFORMATIONAL": "info",
    "info": "info",
}

# iOS scanner uses uppercase severity names
_IOS_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}


def _norm_severity(s: str) -> str:
    return _SEVERITY_MAP.get(str(s), "info")


def _confidence_from_cvss(cvss: float) -> int:
    """Rough confidence estimate from CVSS score."""
    if cvss >= 9.0:
        return 95
    if cvss >= 7.0:
        return 85
    if cvss >= 5.0:
        return 70
    if cvss >= 3.0:
        return 55
    return 40


# ── APK path ────────────────────────────────────────────────────────────────

def _run_apk_scan(apk_path: str) -> List[Dict[str, Any]]:
    from mobile_scanner.apk_analyzer import APKAnalyzer

    logger.info("mobile_scan_service: starting APK analysis: %s", apk_path)
    analyzer = APKAnalyzer(apk_path)
    raw = analyzer.analyze()

    findings = []
    for f in raw:
        cvss = float(f.get("cvss_score") or 0)
        findings.append({
            "title": str(f.get("title", "Android Finding"))[:255],
            "severity": _norm_severity(f.get("severity", "info")),
            "confidence": _confidence_from_cvss(cvss),
            "cvss_score": cvss or None,
            "description": str(f.get("description", ""))[:2000],
            "evidence": str(f.get("evidence", ""))[:1000],
            "remediation": str(f.get("recommendation", ""))[:1000],
            "detector": "apk_analyzer",
            "url": "",
            "payload": "",
            "raw_data": {
                "cwe": f.get("cwe", ""),
                "owasp": f.get("owasp", ""),
                "source": f.get("source", "Android APK Static Analysis"),
            },
        })

    logger.info("mobile_scan_service: APK scan done — %d findings", len(findings))
    return findings


# ── iOS path ────────────────────────────────────────────────────────────────

def _run_ipa_scan(ipa_path: str) -> List[Dict[str, Any]]:
    from mobile_scanner.ios.ios_scanner import iOSScanner

    tmp_dir = tempfile.mkdtemp(prefix="ipa_scan_")
    try:
        logger.info("mobile_scan_service: starting iOS analysis: %s", ipa_path)
        scanner = iOSScanner(ipa_path, output_dir=tmp_dir)
        report = scanner.scan()
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    raw_findings = report.get("findings", [])
    findings = []
    for f in raw_findings:
        sev_str = str(f.get("severity", "INFO"))
        severity = _IOS_SEVERITY_MAP.get(sev_str.upper(), "info")
        cvss = float(f.get("cvss_score") or 0)
        findings.append({
            "title": str(f.get("title", "iOS Finding"))[:255],
            "severity": severity,
            "confidence": _confidence_from_cvss(cvss),
            "cvss_score": cvss or None,
            "description": str(f.get("description", ""))[:2000],
            "evidence": str(f.get("evidence", "{}"))[:1000]
            if isinstance(f.get("evidence"), str)
            else str(f.get("evidence", ""))[:1000],
            "remediation": str(f.get("recommendation", ""))[:1000],
            "detector": "ios_scanner",
            "url": "",
            "payload": "",
            "raw_data": {
                "cwe": f.get("cwe_id", "") or f.get("cwe", ""),
                "owasp": f.get("owasp_mobile", ""),
                "source": "iOS IPA Static Analysis",
                "cvss_vector": f.get("cvss_vector", ""),
            },
        })

    logger.info("mobile_scan_service: iOS scan done — %d findings", len(findings))
    return findings


# ── Public API ───────────────────────────────────────────────────────────────

def run_mobile_scan(
    file_path: str,
    platform: str,
    progress_callback=None,
) -> List[Dict[str, Any]]:
    """
    Scan a mobile app file and return normalised findings.

    Args:
        file_path  : Absolute path to the APK or IPA file.
        platform   : 'android' | 'ios'
        progress_callback: Optional callable(pct: int, msg: str)

    Returns:
        List of normalised finding dicts.

    Raises:
        ValueError  : Unsupported platform or corrupt file.
        FileNotFoundError : File not found.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Mobile app file not found: {file_path}")

    def _progress(pct: int, msg: str) -> None:
        logger.info("mobile_scan [%s]: %d%% — %s", platform, pct, msg)
        if progress_callback:
            progress_callback(pct, msg)

    _progress(5, f"Starting {platform.upper()} static analysis…")

    if platform == "android":
        _progress(10, "Analysing AndroidManifest.xml…")
        findings = _run_apk_scan(file_path)
    elif platform == "ios":
        _progress(10, "Extracting and analysing IPA…")
        findings = _run_ipa_scan(file_path)
    else:
        raise ValueError(f"Unsupported platform: {platform}. Use 'android' or 'ios'.")

    _progress(100, f"Analysis complete — {len(findings)} findings")
    return findings
