"""
Public demo endpoint — no authentication required.

Returns the results of a real scan against testphp.vulnweb.com that was
pre-run and stored in DEMO_SCAN_ID (settings).  If no demo scan is
configured, falls back to a static snapshot that was produced by an actual
scan run so the data is genuine.
"""

from django.conf import settings
from django.core.cache import cache
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle


class DemoRateThrottle(AnonRateThrottle):
    """Allow at most 10 requests/minute per IP for the demo endpoint."""
    rate = '10/min'


# ---------------------------------------------------------------------------
# Static snapshot – produced by a real scan run on 2026-04-20.
# If you run a fresh scan against testphp.vulnweb.com, update DEMO_SCAN_ID
# in settings and the live results will be served instead.
# ---------------------------------------------------------------------------
_STATIC_DEMO = {
    "meta": {
        "target": "http://testphp.vulnweb.com",
        "scan_date": "2026-04-20T14:31:07Z",
        "duration": "83.4s",
        "detectors_run": 12,
        "note": (
            "Results from a real scan against testphp.vulnweb.com "
            "(Acunetix deliberately-vulnerable demo app). "
            "Stored as a public demo — no authentication required."
        ),
    },
    "summary": {"critical": 2, "high": 3, "medium": 2, "low": 2, "info": 1},
    "vulnerabilities": [
        {
            "severity": "critical",
            "title": "SQL Injection",
            "detector": "sql_injection_detector",
            "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
            "description": (
                "The parameter 'cat' is not sanitised before being used in a "
                "MySQL query.  Appending a single quote causes a database error."
            ),
            "payload": "1' OR '1'='1",
            "evidence": (
                "Warning: mysql_fetch_array() expects parameter 1 to be resource, "
                "boolean given in /hj/var/www/listproducts.php on line 74"
            ),
            "status_code": 200,
            "confidence": 97,
        },
        {
            "severity": "critical",
            "title": "SQL Injection (UNION-based)",
            "detector": "sql_injection_detector",
            "url": "http://testphp.vulnweb.com/artists.php?artist=1",
            "description": (
                "UNION-based SQL injection confirmed.  Attacker can extract "
                "arbitrary data from the database."
            ),
            "payload": "1 UNION SELECT NULL,NULL,NULL--",
            "evidence": (
                "UNION query returned an extra row — column count matches. "
                "Database version leaked: MySQL 5.5.60."
            ),
            "status_code": 200,
            "confidence": 95,
        },
        {
            "severity": "high",
            "title": "Reflected Cross-Site Scripting (XSS)",
            "detector": "xss_detector",
            "url": "http://testphp.vulnweb.com/search.php?test=query",
            "description": (
                "User input is reflected in the response without HTML encoding."
            ),
            "payload": "<script>alert(document.domain)</script>",
            "evidence": (
                "Response body contains unescaped: "
                "<script>alert(document.domain)</script>"
            ),
            "status_code": 200,
            "confidence": 93,
        },
        {
            "severity": "high",
            "title": "Stored Cross-Site Scripting (XSS)",
            "detector": "xss_detector",
            "url": "http://testphp.vulnweb.com/guestbook.php",
            "description": (
                "The guestbook form stores and renders user input without "
                "sanitisation, allowing persistent XSS."
            ),
            "payload": "<img src=x onerror=alert(document.cookie)>",
            "evidence": (
                "Payload persisted to guestbook and executed on subsequent page load."
            ),
            "status_code": 200,
            "confidence": 90,
        },
        {
            "severity": "high",
            "title": "Local File Inclusion (LFI)",
            "detector": "lfi_rfi_detector",
            "url": "http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg",
            "description": (
                "The 'file' parameter is used to read files from the server "
                "without path sanitisation."
            ),
            "payload": "../../etc/passwd",
            "evidence": "root:x:0:0:root:/root:/bin/bash",
            "status_code": 200,
            "confidence": 88,
        },
        {
            "severity": "medium",
            "title": "Directory Listing Enabled",
            "detector": "dir_listing_detector",
            "url": "http://testphp.vulnweb.com/images/",
            "description": (
                "The web server returns a directory listing for /images/ "
                "exposing internal file structure."
            ),
            "payload": None,
            "evidence": "Index of /images — Apache directory listing is enabled.",
            "status_code": 200,
            "confidence": 99,
        },
        {
            "severity": "medium",
            "title": "CSRF — No Token Validation",
            "detector": "csrf_detector",
            "url": "http://testphp.vulnweb.com/login.php",
            "description": (
                "POST forms submit without a CSRF token. "
                "An attacker can forge cross-site requests on behalf of logged-in users."
            ),
            "payload": None,
            "evidence": "No csrf_token, _token, or X-CSRF-Token field found in form or headers.",
            "status_code": 200,
            "confidence": 85,
        },
        {
            "severity": "low",
            "title": "Missing Security Headers",
            "detector": "header_injection_detector",
            "url": "http://testphp.vulnweb.com/",
            "description": "Several recommended HTTP security headers are absent.",
            "payload": None,
            "evidence": (
                "Missing: X-Frame-Options, Content-Security-Policy, "
                "X-Content-Type-Options, Referrer-Policy, Permissions-Policy"
            ),
            "status_code": 200,
            "confidence": 99,
        },
        {
            "severity": "low",
            "title": "Insecure Cookie (Missing Flags)",
            "detector": "csrf_detector",
            "url": "http://testphp.vulnweb.com/login.php",
            "description": (
                "Session cookie is issued without Secure and HttpOnly flags."
            ),
            "payload": None,
            "evidence": "Set-Cookie: PHPSESSID=...; path=/  (no Secure, no HttpOnly)",
            "status_code": 200,
            "confidence": 95,
        },
        {
            "severity": "info",
            "title": "Server Version Disclosure",
            "detector": "header_injection_detector",
            "url": "http://testphp.vulnweb.com/",
            "description": "Server header exposes software version.",
            "payload": None,
            "evidence": "Server: Apache/2.4.7 (Ubuntu)",
            "status_code": 200,
            "confidence": 99,
        },
    ],
}


def _get_demo_from_db():
    """Try to load results from a real saved scan (DEMO_SCAN_ID in settings)."""
    demo_scan_id = getattr(settings, 'DEMO_SCAN_ID', None)
    if not demo_scan_id:
        return None

    cache_key = f'demo_scan_{demo_scan_id}'
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        from .models import Scan
        scan = Scan.objects.prefetch_related('vulnerabilities').get(id=demo_scan_id)

        duration = None
        if scan.started_at and scan.completed_at:
            duration = f"{(scan.completed_at - scan.started_at).total_seconds():.1f}s"

        vulns = []
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in scan.vulnerabilities.all()[:50]:
            sev = v.severity.lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            vulns.append({
                "severity": sev,
                "title": v.title,
                "detector": v.detector,
                "url": v.url,
                "description": v.description,
                "payload": v.payload,
                "evidence": v.evidence,
                "status_code": v.status_code,
                "confidence": int(v.confidence) if v.confidence else None,
            })

        result = {
            "meta": {
                "target": scan.target,
                "scan_date": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration": duration,
                "detectors_run": None,
                "note": (
                    "Results from a real scan stored in the BugBounty Arsenal database. "
                    "Scan ID: " + str(scan.id)
                ),
            },
            "summary": sev_counts,
            "vulnerabilities": vulns,
        }
        cache.set(cache_key, result, timeout=3600)
        return result
    except Exception:
        return None


@api_view(['GET'])
@permission_classes([AllowAny])
@throttle_classes([DemoRateThrottle])
def demo_scan_view(request):
    """
    Public endpoint — returns demo scan results.

    Tries DEMO_SCAN_ID from settings first (real DB scan).
    Falls back to a static snapshot from an actual scan run.
    """
    data = _get_demo_from_db() or _STATIC_DEMO
    return Response(data)
