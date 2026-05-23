# detectors/ssrf_detector.py
# Passive detector: търси известни SSRF/metadata endpoints в съдържанието.
import re
from detectors.registry import register_passive


@register_passive
def detect_ssrf_from_text(text, context):
    patterns = [
        (r"http://169\.254\.169\.254", "AWS metadata"),
        (r"http://metadata\.google\.internal", "GCP metadata"),
        (r"http://127\.0\.0\.1", "Localhost"),
        (r"http://localhost", "Localhost"),
        (r"http://0\.0\.0\.0", "0.0.0.0"),
    ]

    findings = []
    if not text:
        return findings

    for pat, name in patterns:
        if re.search(pat, text, re.IGNORECASE):
            findings.append({
                "type": "SSRF Indicator",
                "evidence": name,
                "how_found": f"Matched pattern {pat}",
                "severity": "medium",
                "confidence": 50,
                "payload": None
            })
    return findings
