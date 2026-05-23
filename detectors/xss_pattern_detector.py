# detectors/xss_pattern_detector.py
# Passive + active XSS detector with differential / reflection analysis.
#
# Passive phase  — scans response text for XSS indicators.
# Active phase   — injects a benign marker, fetches the page again, then uses
#                  differential_check to confirm the marker is reflected.
#                  This eliminates false positives from pages that already
#                  contain <script> tags in their normal HTML.
import uuid
from urllib.parse import urlparse

from detectors.registry import register_passive, register_active
from utils.context_filter import should_skip_url, differential_check

__all__ = ['detect_xss_from_text', 'detect_xss_active']


# ── Passive detector ──────────────────────────────────────────────────────────

@register_passive
def detect_xss_from_text(text, context):
    """
    Scan the response body for XSS indicators.

    Context keys used:
      - 'url':           the page URL (used for documentation filter)
      - 'baseline_body': original (un-injected) response, if available, used
                         for differential check to reduce FPs from static pages.
    """
    findings = []
    if not text:
        return findings

    url = ''
    baseline_body = ''
    if isinstance(context, dict):
        url = context.get('url') or context.get('target') or ''
        baseline_body = context.get('baseline_body') or ''

    if should_skip_url(url):
        return findings

    low_text = text.lower()

    # ── Pattern checks ────────────────────────────────────────────────────────

    xss_checks = [
        (
            "<script" in low_text or "javascript:" in low_text,
            "XSS Indicator",
            "<script> or javascript: found in response",
            "Passive: <script> tag or javascript: protocol detected in response body",
            "medium",
            55,
            "<script>",
        ),
        (
            "onerror=" in low_text or "onload=" in low_text,
            "XSS Event Handler",
            "onerror/onload attribute found in response",
            "Passive: event handler attribute (onerror/onload) detected in response body",
            "low",
            45,
            None,
        ),
        (
            "<img " in low_text and ("onerror" in low_text or "onmouseover" in low_text),
            "XSS via Image Tag",
            "<img> with dangerous event handler found",
            "Passive: <img> tag with JavaScript event handler detected",
            "medium",
            50,
            '<img src=x onerror=alert(1)>',
        ),
        (
            "document.write(" in low_text or "innerHTML" in low_text,
            "DOM XSS Sink",
            "Dangerous DOM sink (document.write / innerHTML) found",
            "Passive: DOM-based XSS sink detected in response",
            "low",
            40,
            None,
        ),
    ]

    for triggered, xss_type, evidence, how_found, severity, base_conf, payload in xss_checks:
        if not triggered:
            continue

        # Differential check: if the indicator was already present in the
        # baseline response, this is NOT a reflection — it's static page HTML.
        # Lower confidence accordingly.
        confidence = base_conf
        differential_note = ""

        if baseline_body:
            diff = differential_check(baseline_body, text, evidence.split()[0])
            if not diff["reflected"] and not diff["new_content"]:
                # Pattern exists in both baseline and test → static content
                confidence = max(10, base_conf - 30)
                differential_note = " (also present in baseline — likely static content)"
            elif diff["reflected"]:
                confidence = min(100, base_conf + diff["confidence_boost"])
                differential_note = " (NOT in baseline → likely reflected)"

        findings.append({
            "type":       xss_type,
            "evidence":   evidence + differential_note,
            "how_found":  how_found,
            "severity":   severity,
            "confidence": confidence,
            "payload":    payload,
        })

    return findings


# ── Active detector ───────────────────────────────────────────────────────────

@register_active
async def detect_xss_active(session, url, context):
    """
    Active reflection test: injects a benign marker as a query parameter and
    checks if it's reflected in the response (a prerequisite for XSS).

    Steps:
      1. Fetch the baseline response (no injection).
      2. Inject marker in a new query parameter.
      3. Use differential_check to confirm the marker appears ONLY in the
         injected response.
      4. If reflected, report Reflected Input Confirmed with boosted confidence.
    """
    import aiohttp
    findings = []
    if not url:
        return findings
    if should_skip_url(url):
        return findings

    try:
        marker = f"xss-{uuid.uuid4().hex[:10]}"
        parsed = urlparse(url)
        sep = '&' if parsed.query else '?'
        test_url = f"{url}{sep}_xss={marker}"

        timeout = aiohttp.ClientTimeout(total=12)

        # Baseline fetch
        try:
            async with session.get(url, allow_redirects=True, timeout=timeout) as resp:
                try:
                    baseline_body = await resp.text()
                except Exception:
                    baseline_body = ""
        except Exception:
            baseline_body = ""

        # Injected fetch
        async with session.get(test_url, allow_redirects=True, timeout=timeout) as resp:
            try:
                test_body = await resp.text()
            except Exception:
                return findings

        diff = differential_check(baseline_body, test_body, marker)

        if diff["reflected"]:
            confidence = 75 + diff["confidence_boost"]  # 75–100
            findings.append({
                "type":       "Reflected Input (XSS Precondition)",
                "evidence":   f"Marker `{marker}` reflected in response — not present in baseline",
                "how_found":  (
                    "Active: injected benign marker as query param; "
                    "confirmed reflection via differential analysis"
                ),
                "severity":   "medium",
                "confidence": min(100, confidence),
                "verified":   True,
                "payload":    f"_xss={marker}",
                "test_url":   test_url,
            })

    except Exception as exc:
        findings.append({
            "type":      "XSS Active Detector Error",
            "evidence":  str(exc),
            "how_found": "error",
            "severity":  "info",
            "confidence": 0,
            "payload":   None,
        })

    return findings

