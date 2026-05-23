"""
Vulnerability Scoring Utility
Calculates confidence scores (0-100%) and CVSS base scores for findings.

Confidence reflects how certain the detector is that the finding is a real vulnerability:
  - 90-100: Direct output confirmation (e.g. command output, reflected XSS, SQL error)
  - 75-89:  Strong indirect evidence (e.g. time-based with large delta, OOB callback)
  - 55-74:  Moderate evidence (e.g. pattern match with context)
  - 35-54:  Weak evidence (e.g. passive pattern match, header anomaly)
  - 0-34:   Very low confidence (informational, requires manual verification)
"""


# Severity → CVSS v3.1 base score (approximate midpoint of each band)
SEVERITY_CVSS: dict[str, float] = {
    'critical': 9.5,
    'high':     8.0,
    'medium':   5.5,
    'low':      2.0,
    'info':     0.0,
}

# Detection method → confidence modifier
METHOD_CONFIDENCE: dict[str, int] = {
    'output_based':    90,
    'reflected':       88,
    'oob_callback':    85,
    'error_based':     82,
    'time_based':      65,
    'blind':           60,
    'pattern_match':   55,
    'passive':         45,
    'header_match':    50,
    'informational':   30,
}

# Per-detector base confidence when method is not specified
DETECTOR_CONFIDENCE: dict[str, int] = {
    # High confidence — direct output or OOB confirmation
    'command_injection_detector':      80,
    'xxe_detector':                    78,
    'ssrf_oob_detector':               85,
    'ssrf_oob_advanced_detector':      85,
    'advanced_ssrf_detector':          75,
    'ssti_detector':                   80,
    'nosql_injection_detector':        78,
    'graphql_injection_detector':      80,
    'lfi_detector':                    75,
    'sql_pattern_detector':            72,
    'jwt_detector':                    82,
    'jwt_vulnerability_scanner':       80,

    # Medium confidence — reflected/pattern + context
    'xss_pattern_detector':            72,
    'reflection_detector':             68,
    'open_redirect_detector':          70,
    'cors_detector':                   75,
    'csrf_detector':                   70,
    'auth_bypass_detector':            72,
    'idor_detector':                   68,
    'file_upload_detector':            74,
    'prototype_pollution_detector':    68,
    'race_condition_detector':         65,
    'cache_poisoning_detector':        68,
    'rate_limit_bypass_detector':      65,
    'oauth_detector':                  70,
    'api_security_detector':           65,
    'graphql_detector':                65,
    'header_injection_detector':       68,
    'subdomain_takeover_detector':     78,

    # Lower confidence — passive pattern matching
    'ssrf_detector':                   50,
    'fuzz_detector':                   55,
    'basic_param_fuzzer':              55,
    'parameter_fuzzer':                55,
    'secret_detector':                 60,
    'security_headers_detector':       45,
    'dir_listing_detector':            65,
    'backup_file_hunter':              60,
    'js_file_analyzer':                50,
    'injector':                        58,
    'cve_database_detector':           60,
    'nuclei_detector':                 70,
    'brute_force_detector':            70,

    # Informational
    'api_docs_discovery':              40,
    'simple_file_list_detector':       40,
    'old_domain_hunter':               35,
    'github_osint':                    45,
}


# String confidence labels → integer mapping (for detectors that use text labels)
STRING_CONFIDENCE_MAP: dict[str, int] = {
    'very_high': 95,
    'very high': 95,
    'high':      85,
    'medium':    65,
    'moderate':  65,
    'low':       45,
    'very_low':  25,
    'very low':  25,
}


def calculate_confidence(finding: dict) -> int:
    """
    Return an integer confidence score 0-100 for a finding.

    Priority:
    1. Detector-provided 'confidence' key — integer (0-100) or string label
    2. Detection method-based override
    3. Per-detector default
    4. Generic fallback of 50
    """
    # 1. Use detector-provided confidence if valid
    raw = finding.get('confidence')
    if raw is not None:
        # Integer path
        if isinstance(raw, (int, float)):
            val = int(raw)
            if 0 <= val <= 100:
                return val
        # String label path
        if isinstance(raw, str):
            mapped = STRING_CONFIDENCE_MAP.get(raw.lower().strip())
            if mapped is not None:
                return mapped

    # 2. Method-based
    method = str(finding.get('method') or finding.get('how_found') or '').lower()
    for key, score in METHOD_CONFIDENCE.items():
        if key in method:
            return score

    # 3. Per-detector default
    detector = str(finding.get('detector') or '').lower()
    if detector in DETECTOR_CONFIDENCE:
        return DETECTOR_CONFIDENCE[detector]

    # 4. Fallback
    return 50


def calculate_cvss_score(finding: dict) -> float:
    """
    Return a CVSS v3.1 base score (0.0–10.0) derived from severity.
    Uses detector-provided 'cvss_score' if already set and valid.
    """
    raw = finding.get('cvss_score')
    if raw is not None:
        try:
            val = float(raw)
            if 0.0 <= val <= 10.0:
                return round(val, 1)
        except (ValueError, TypeError):
            pass

    severity = str(finding.get('severity') or 'low').lower().strip()
    return SEVERITY_CVSS.get(severity, 2.0)


def score_finding(finding: dict) -> dict:
    """
    Enrich a finding dict with 'confidence' and 'cvss_score' in-place.
    Returns the same dict for convenience.
    """
    finding['confidence'] = calculate_confidence(finding)
    finding['cvss_score'] = calculate_cvss_score(finding)
    return finding


def confidence_label(confidence: int) -> str:
    """Return a human-readable label for a confidence score."""
    if confidence >= 90:
        return 'Very High'
    if confidence >= 75:
        return 'High'
    if confidence >= 55:
        return 'Medium'
    if confidence >= 35:
        return 'Low'
    return 'Very Low'


# ── Signal-strength aware scoring ─────────────────────────────────────────────

def score_finding_with_signal(finding: dict) -> dict:
    """
    Extended version of score_finding() that incorporates:
      - verified flag      → boosts confidence to ≥ 90
      - signal_strength    → used when the detector exposes it (e.g. secret_detector)
      - needs_verification → caps confidence at 70 for unverified high-impact findings

    Updates finding in-place with 'confidence', 'cvss_score'.
    Returns the same dict.
    """
    # 1. Base confidence from normal pipeline
    conf = calculate_confidence(finding)

    # 2. Incorporate signal_strength from detectors that compute it
    sig = finding.get('signal_strength')
    if sig is not None:
        try:
            sig_float = float(sig)
            # signal_strength is 0.0–1.0; convert to 0–100 for comparison
            sig_conf = int(min(100, sig_float * 100))
            # Take the higher of the two estimates
            conf = max(conf, sig_conf)
        except (ValueError, TypeError):
            pass

    # 3. Verified flag overrides — a confirmed finding gets at least 90
    if finding.get('verified'):
        conf = max(conf, 90)

    # 4. Safety cap: unverified high-impact findings should not exceed 70
    if finding.get('needs_verification') and not finding.get('verified') and conf > 70:
        conf = 70

    # 5. Clamp
    conf = max(0, min(100, conf))

    finding['confidence'] = conf
    finding['cvss_score'] = calculate_cvss_score(finding)
    return finding


def aggregate_scan_confidence(findings: list) -> dict:
    """
    Compute summary statistics for a list of scored findings.

    Returns:
        {
          "total":        int,
          "verified":     int,
          "avg_confidence": float,
          "high_confidence_count": int,   # confidence >= 75
          "false_positive_risk": str,     # 'low' | 'medium' | 'high'
        }
    """
    if not findings:
        return {
            "total": 0, "verified": 0,
            "avg_confidence": 0.0,
            "high_confidence_count": 0,
            "false_positive_risk": "low",
        }

    total = len(findings)
    verified = sum(1 for f in findings if f.get('verified'))
    confidences = [int(f.get('confidence') or 0) for f in findings]
    avg_conf = sum(confidences) / total
    high_conf_count = sum(1 for c in confidences if c >= 75)

    # False-positive risk heuristic
    low_conf_ratio = sum(1 for c in confidences if c < 50) / total
    if low_conf_ratio > 0.6:
        fp_risk = 'high'
    elif low_conf_ratio > 0.3:
        fp_risk = 'medium'
    else:
        fp_risk = 'low'

    return {
        "total":                 total,
        "verified":              verified,
        "avg_confidence":        round(avg_conf, 1),
        "high_confidence_count": high_conf_count,
        "false_positive_risk":   fp_risk,
    }
