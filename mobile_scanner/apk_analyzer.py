"""
mobile_scanner/apk_analyzer.py

Pure-Python static analyzer for Android APK files.
No external tools required — works on shared hosting.

An APK is just a ZIP archive:
  AndroidManifest.xml   — binary XML (parsed via string scanning)
  classes.dex           — compiled bytecode (scanned as raw bytes)
  res/                  — resources
  assets/               — asset files

Detects:
  - Dangerous permissions (SMS, microphone, contacts, etc.)
  - Debug mode enabled
  - Backup allowed (ADB backup)
  - Cleartext traffic allowed
  - Exported components (activities/services/receivers)
  - Hardcoded secrets (API keys, tokens, passwords)
  - Hardcoded HTTP URLs
  - Weak cryptography usage (DES, MD5, etc.)
  - Certificate pinning absence (informational)
"""

from __future__ import annotations

import io
import logging
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Dangerous permissions ───────────────────────────────────────────────────

_DANGEROUS_PERMISSIONS: Dict[str, Dict[str, str]] = {
    "READ_SMS": {
        "severity": "high",
        "cvss": 6.5,
        "cwe": "CWE-200",
        "description": "App requests READ_SMS permission, allowing it to read all SMS messages.",
        "recommendation": "Remove this permission unless the core functionality requires it.",
    },
    "RECEIVE_SMS": {
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-200",
        "description": "App can intercept incoming SMS messages.",
        "recommendation": "Ensure this is required for core functionality and document the purpose.",
    },
    "RECORD_AUDIO": {
        "severity": "high",
        "cvss": 7.1,
        "cwe": "CWE-200",
        "description": "App requests microphone access.",
        "recommendation": "Confirm microphone access is necessary and request it only when needed.",
    },
    "PROCESS_OUTGOING_CALLS": {
        "severity": "high",
        "cvss": 6.5,
        "cwe": "CWE-200",
        "description": "App can intercept and redirect outgoing calls.",
        "recommendation": "Remove unless strictly necessary.",
    },
    "READ_CALL_LOG": {
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-200",
        "description": "App can read call history.",
        "recommendation": "Verify this permission is required and declared in the privacy policy.",
    },
    "READ_CONTACTS": {
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-200",
        "description": "App can access the device contacts list.",
        "recommendation": "Ensure this is necessary and disclosed to users.",
    },
    "READ_FINE_LOCATION": {
        "severity": "medium",
        "cvss": 4.3,
        "cwe": "CWE-200",
        "description": "App uses precise GPS location.",
        "recommendation": "Use COARSE_LOCATION where possible. Request only when needed.",
    },
    "CAMERA": {
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-200",
        "description": "App requests camera access.",
        "recommendation": "Request camera permission only at the point of use.",
    },
    "WRITE_EXTERNAL_STORAGE": {
        "severity": "low",
        "cvss": 3.3,
        "cwe": "CWE-312",
        "description": "App can write to external storage, potentially exposing data.",
        "recommendation": "Use app-scoped storage (Context.getExternalFilesDir) instead.",
    },
    "READ_EXTERNAL_STORAGE": {
        "severity": "low",
        "cvss": 3.3,
        "cwe": "CWE-200",
        "description": "App can read all files on external storage.",
        "recommendation": "Use scoped storage APIs (Android 10+) to limit file access.",
    },
}

# ── Hardcoded secret patterns ───────────────────────────────────────────────

_SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "Hardcoded AWS Access Key",
        "pattern": rb"AKIA[0-9A-Z]{16}",
        "severity": "critical",
        "cvss": 9.1,
        "cwe": "CWE-798",
    },
    {
        "name": "Hardcoded AWS Secret Key",
        "pattern": rb"(?i)aws.{0,30}secret.{0,10}['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": "critical",
        "cvss": 9.1,
        "cwe": "CWE-798",
    },
    {
        "name": "Hardcoded Google API Key",
        "pattern": rb"AIza[0-9A-Za-z\\-_]{35}",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-798",
    },
    {
        "name": "Hardcoded Firebase URL",
        "pattern": rb"https://[a-zA-Z0-9-]+\\.firebaseio\\.com",
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-200",
    },
    {
        "name": "Hardcoded Private Key Header",
        "pattern": rb"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-321",
    },
    {
        "name": "Hardcoded Password in Code",
        "pattern": rb"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-259",
    },
    {
        "name": "Hardcoded API Token",
        "pattern": rb"(?i)(api_key|apikey|api-key|access_token)\s*[=:]\s*['\"][A-Za-z0-9_\-]{20,}['\"]",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-798",
    },
    {
        "name": "Hardcoded JWT Token",
        "pattern": rb"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-798",
    },
]

# ── Weak crypto patterns ────────────────────────────────────────────────────

_WEAK_CRYPTO: List[Dict[str, str]] = [
    {
        "name": "DES Encryption Usage",
        "pattern": "DES",
        "severity": "medium",
        "cvss": "5.9",
        "cwe": "CWE-326",
        "description": "DES is a broken symmetric cipher (56-bit key). Easily brute-forced.",
        "recommendation": "Replace with AES-256-GCM.",
    },
    {
        "name": "MD5 Hash Usage",
        "pattern": "MD5",
        "severity": "medium",
        "cvss": "5.9",
        "cwe": "CWE-327",
        "description": "MD5 is a broken hash function susceptible to collision attacks.",
        "recommendation": "Use SHA-256 or SHA-3 instead.",
    },
    {
        "name": "SHA-1 Hash Usage",
        "pattern": "SHA-1",
        "severity": "low",
        "cvss": "3.7",
        "cwe": "CWE-327",
        "description": "SHA-1 is considered weak for cryptographic purposes.",
        "recommendation": "Migrate to SHA-256 or SHA-3.",
    },
    {
        "name": "RC4 Cipher Usage",
        "pattern": "RC4",
        "severity": "high",
        "cvss": "7.4",
        "cwe": "CWE-326",
        "description": "RC4 is a broken stream cipher with known vulnerabilities.",
        "recommendation": "Use AES-GCM or ChaCha20-Poly1305.",
    },
]


# ── Binary XML string extractor ─────────────────────────────────────────────

def _extract_strings_from_binary_xml(data: bytes) -> str:
    """
    Extract readable strings from Android binary XML.
    Binary XML stores strings as null-terminated UTF-16LE.
    We decode both UTF-16LE and ASCII to maximise coverage.
    """
    results = []

    # UTF-16LE strings (most manifest strings)
    try:
        decoded = data.decode("utf-16-le", errors="replace")
        results.append(decoded)
    except Exception:
        pass

    # ASCII strings (fallback, finds short attribute values)
    ascii_strings = re.findall(rb"[\x20-\x7e]{4,}", data)
    results.append(b" ".join(ascii_strings).decode("ascii", errors="replace"))

    return "\n".join(results)


def _extract_dex_strings(data: bytes) -> str:
    """Extract printable strings from .dex bytecode."""
    strings = re.findall(rb"[\x20-\x7e]{8,}", data)
    return b"\n".join(strings).decode("ascii", errors="replace")


# ── Main analyzer ───────────────────────────────────────────────────────────

class APKAnalyzer:
    """
    Static analyzer for Android APK files.

    Usage:
        analyzer = APKAnalyzer("/tmp/app.apk")
        findings = analyzer.analyze()
    """

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.app_name = Path(apk_path).stem
        self.findings: List[Dict[str, Any]] = []

    # ── Public API ───────────────────────────────────────────────────────────

    def analyze(self) -> List[Dict[str, Any]]:
        """Run all checks and return a list of normalised findings."""
        self.findings = []

        try:
            with zipfile.ZipFile(self.apk_path, "r") as apk:
                self._check_manifest(apk)
                self._check_dex_files(apk)
        except zipfile.BadZipFile as exc:
            raise ValueError(f"Invalid APK file (not a valid ZIP): {exc}") from exc

        return self.findings

    # ── Manifest checks ──────────────────────────────────────────────────────

    def _check_manifest(self, apk: zipfile.ZipFile) -> None:
        names = apk.namelist()
        if "AndroidManifest.xml" not in names:
            logger.warning("apk_analyzer: AndroidManifest.xml not found in APK")
            return

        data = apk.read("AndroidManifest.xml")
        manifest_text = _extract_strings_from_binary_xml(data)

        self._check_permissions(manifest_text)
        self._check_debuggable(manifest_text)
        self._check_backup(manifest_text)
        self._check_cleartext(manifest_text)
        self._check_exported(manifest_text)
        self._check_network_security_config(names, apk)

    def _check_permissions(self, manifest_text: str) -> None:
        for perm, info in _DANGEROUS_PERMISSIONS.items():
            if perm in manifest_text:
                self._add_finding(
                    title=f"Dangerous Permission: android.permission.{perm}",
                    severity=info["severity"],
                    cvss_score=info["cvss"],
                    cwe=info["cwe"],
                    owasp="M1: Improper Platform Usage",
                    description=info["description"],
                    recommendation=info["recommendation"],
                    evidence=f"Found in AndroidManifest.xml: android.permission.{perm}",
                )

    def _check_debuggable(self, manifest_text: str) -> None:
        if "debuggable" in manifest_text and "true" in manifest_text:
            self._add_finding(
                title="Application is Debuggable",
                severity="high",
                cvss_score=7.1,
                cwe="CWE-489",
                owasp="M7: Client Code Quality",
                description=(
                    "The android:debuggable attribute is set to true. "
                    "This allows attackers to attach a debugger to the process, "
                    "extract sensitive data, and bypass security controls."
                ),
                recommendation=(
                    "Set android:debuggable=false in release builds. "
                    "Use build variants so debug mode is only enabled in debug builds."
                ),
                evidence="android:debuggable=\"true\" found in AndroidManifest.xml",
            )

    def _check_backup(self, manifest_text: str) -> None:
        if "allowBackup" in manifest_text and "true" in manifest_text:
            self._add_finding(
                title="Application Data Backup Allowed",
                severity="medium",
                cvss_score=4.3,
                cwe="CWE-312",
                owasp="M2: Insecure Data Storage",
                description=(
                    "android:allowBackup=true enables ADB backup. "
                    "An attacker with USB access can extract all app data without root."
                ),
                recommendation=(
                    "Set android:allowBackup=false, or use android:fullBackupContent "
                    "to explicitly exclude sensitive data."
                ),
                evidence="android:allowBackup=\"true\" found in AndroidManifest.xml",
            )

    def _check_cleartext(self, manifest_text: str) -> None:
        if "usesCleartextTraffic" in manifest_text and "true" in manifest_text:
            self._add_finding(
                title="Cleartext HTTP Traffic Allowed",
                severity="high",
                cvss_score=7.4,
                cwe="CWE-319",
                owasp="M3: Insecure Communication",
                description=(
                    "android:usesCleartextTraffic=true allows the app to make unencrypted "
                    "HTTP requests, exposing data to network interception."
                ),
                recommendation=(
                    "Set android:usesCleartextTraffic=false and use a Network Security Config "
                    "to enforce HTTPS for all connections."
                ),
                evidence="android:usesCleartextTraffic=\"true\" found in AndroidManifest.xml",
            )

    def _check_exported(self, manifest_text: str) -> None:
        count = manifest_text.count("exported")
        if count > 0 and "true" in manifest_text:
            self._add_finding(
                title="Exported Components Detected",
                severity="medium",
                cvss_score=5.3,
                cwe="CWE-926",
                owasp="M1: Improper Platform Usage",
                description=(
                    f"The manifest contains exported components (android:exported=true). "
                    f"Exported activities, services, or broadcast receivers can be invoked "
                    f"by other apps without authentication."
                ),
                recommendation=(
                    "Set android:exported=false on components that should not be accessible "
                    "to other apps. Add android:permission attributes where export is required."
                ),
                evidence="android:exported=\"true\" found in AndroidManifest.xml",
            )

    def _check_network_security_config(
        self, names: List[str], apk: zipfile.ZipFile
    ) -> None:
        nsc_files = [n for n in names if "network_security_config" in n.lower()]
        if not nsc_files:
            self._add_finding(
                title="No Network Security Config Defined",
                severity="info",
                cvss_score=0.0,
                cwe="CWE-319",
                owasp="M3: Insecure Communication",
                description=(
                    "No network_security_config.xml was found. "
                    "Without this file the app uses Android platform defaults, "
                    "which may allow cleartext traffic on older Android versions."
                ),
                recommendation=(
                    "Add a res/xml/network_security_config.xml that pins certificates "
                    "and disables cleartext HTTP."
                ),
                evidence="network_security_config.xml not present in APK",
            )
        else:
            for nsc in nsc_files:
                try:
                    content = apk.read(nsc).decode("utf-8", errors="replace")
                    if "cleartextTrafficPermitted=\"true\"" in content:
                        self._add_finding(
                            title="Network Security Config Allows Cleartext Traffic",
                            severity="medium",
                            cvss_score=5.9,
                            cwe="CWE-319",
                            owasp="M3: Insecure Communication",
                            description="The Network Security Config explicitly allows cleartext HTTP traffic.",
                            recommendation="Set cleartextTrafficPermitted=\"false\".",
                            evidence=f"Found in {nsc}",
                        )
                except Exception:
                    pass

    # ── DEX / code checks ────────────────────────────────────────────────────

    def _check_dex_files(self, apk: zipfile.ZipFile) -> None:
        dex_files = [n for n in apk.namelist() if n.endswith(".dex")]
        if not dex_files:
            return

        # Combine all DEX strings for efficient scanning
        combined = b""
        for dex_name in dex_files[:5]:  # limit to first 5 to avoid huge APKs
            try:
                combined += apk.read(dex_name)
            except Exception:
                pass

        if not combined:
            return

        self._check_secrets(combined)
        self._check_weak_crypto(combined)
        self._check_hardcoded_http(combined)
        self._check_certificate_pinning(combined)

    def _check_secrets(self, data: bytes) -> None:
        seen_names: set = set()
        for spec in _SECRET_PATTERNS:
            matches = re.findall(spec["pattern"], data)
            if matches and spec["name"] not in seen_names:
                seen_names.add(spec["name"])
                # Truncate match for evidence (avoid storing real secrets at length)
                sample = matches[0][:40].decode("ascii", errors="replace")
                self._add_finding(
                    title=spec["name"],
                    severity=spec["severity"],
                    cvss_score=spec["cvss"],
                    cwe=spec["cwe"],
                    owasp="M9: Reverse Engineering",
                    description=(
                        f"A potential hardcoded credential or secret was found in the APK "
                        f"bytecode. Secrets embedded in app binaries can be extracted by "
                        f"anyone who decompiles the APK."
                    ),
                    recommendation=(
                        "Remove all hardcoded secrets. Use Android Keystore, secure remote "
                        "configuration, or environment-based injection at build time."
                    ),
                    evidence=f"Pattern matched: {sample}… ({len(matches)} occurrence(s))",
                )

    def _check_weak_crypto(self, data: bytes) -> None:
        text = _extract_dex_strings(data)
        seen: set = set()
        for spec in _WEAK_CRYPTO:
            if spec["pattern"] in text and spec["name"] not in seen:
                seen.add(spec["name"])
                self._add_finding(
                    title=spec["name"],
                    severity=spec["severity"],
                    cvss_score=float(spec["cvss"]),
                    cwe=spec["cwe"],
                    owasp="M5: Insufficient Cryptography",
                    description=spec["description"],
                    recommendation=spec["recommendation"],
                    evidence=f"String '{spec['pattern']}' found in DEX bytecode",
                )

    def _check_hardcoded_http(self, data: bytes) -> None:
        http_urls = re.findall(rb"http://[a-zA-Z0-9.\-/]{6,80}", data)
        # Filter localhost and test URLs
        external = [
            u for u in http_urls
            if not any(x in u for x in [b"localhost", b"127.0.0.1", b"10.0.0.", b"example.com"])
        ]
        if external:
            samples = list({u.decode("ascii", errors="replace") for u in external[:5]})
            self._add_finding(
                title="Hardcoded HTTP URLs (Unencrypted Endpoints)",
                severity="medium",
                cvss_score=5.3,
                cwe="CWE-319",
                owasp="M3: Insecure Communication",
                description=(
                    f"Found {len(external)} hardcoded HTTP URL(s) in the APK code. "
                    "Unencrypted HTTP connections are vulnerable to MITM attacks."
                ),
                recommendation="Replace all HTTP endpoints with HTTPS.",
                evidence=f"Sample URLs: {'; '.join(samples[:3])}",
            )

    def _check_certificate_pinning(self, data: bytes) -> None:
        pinning_indicators = [
            b"CertificatePinner",
            b"TrustManager",
            b"X509TrustManager",
            b"checkServerTrusted",
            b"OkHttp",
        ]
        found = any(ind in data for ind in pinning_indicators)
        if not found:
            self._add_finding(
                title="No Certificate Pinning Detected",
                severity="info",
                cvss_score=0.0,
                cwe="CWE-295",
                owasp="M3: Insecure Communication",
                description=(
                    "No certificate pinning implementation was detected. "
                    "Without pinning, the app accepts any certificate issued by a trusted CA, "
                    "making it susceptible to MITM attacks using rogue certificates."
                ),
                recommendation=(
                    "Implement certificate pinning using OkHttp CertificatePinner, "
                    "TrustKit, or Android Network Security Config pin-set."
                ),
                evidence="No pinning-related classes found in DEX bytecode",
            )

    # ── Helper ───────────────────────────────────────────────────────────────

    def _add_finding(
        self,
        title: str,
        severity: str,
        cvss_score: float,
        cwe: str,
        owasp: str,
        description: str,
        recommendation: str,
        evidence: str,
    ) -> None:
        self.findings.append({
            "title": title,
            "severity": severity.lower(),
            "cvss_score": cvss_score,
            "cwe": cwe,
            "owasp": owasp,
            "description": description,
            "recommendation": recommendation,
            "evidence": evidence,
            "detector": "apk_analyzer",
            "source": "Android APK Static Analysis",
        })
        logger.debug("apk_analyzer: [%s] %s", severity, title)
