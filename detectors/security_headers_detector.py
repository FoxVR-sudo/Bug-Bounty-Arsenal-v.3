# detectors/security_headers_detector.py
# Active detector: checks for missing important security headers via a HEAD/GET request.
import logging

from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)


@register_active
async def security_headers_detector(session, url, context):
    findings = []
    if not url:
        return findings

    per_host_rate = context.get("per_host_rate", None)

    try:
        parsed_host = url.split("/")[2] if "//" in url else None
        host = parsed_host or ""
        await await_host_token(host, per_host_rate)
        try:
            # Use GET (some servers don't respond to HEAD consistently)
            async with session.get(url, allow_redirects=True) as resp:
                headers = dict(resp.headers)
                status = resp.status
        except Exception as e:
            logger.debug("Security headers request failed for %s: %s", url, e)
            return findings

        missing = []
        required = {
            "x-frame-options": "X-Frame-Options",
            "content-security-policy": "Content-Security-Policy",
            "x-content-type-options": "X-Content-Type-Options",
            "strict-transport-security": "Strict-Transport-Security",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }
        low_headers = {k.lower(): v for k, v in headers.items()}
        for key, nice in required.items():
            if key not in low_headers:
                missing.append(nice)

        if missing:
            findings.append({
                "type": "Missing Security Headers",
                "evidence": f"Missing headers: {', '.join(missing)}",
                "how_found": "Performed request and inspected response headers",
                "severity": "low",
                "payload": None,
                "evidence_url": url,
                "evidence_body": "",
                "evidence_headers": headers,
                "evidence_status": status,
            })

        # CSP value checks: a present CSP can still be weak
        csp_value = low_headers.get("content-security-policy", "")
        if csp_value:
            csp_issues = []
            if "unsafe-inline" in csp_value:
                csp_issues.append("'unsafe-inline' allows inline scripts/styles — negates XSS protection")
            if "unsafe-eval" in csp_value:
                csp_issues.append("'unsafe-eval' allows eval() — allows script injection via eval")
            if "unsafe-hashes" in csp_value:
                csp_issues.append("'unsafe-hashes' weakens CSP hash enforcement")
            if "*" in csp_value.split():
                csp_issues.append("Wildcard (*) source allows loading resources from any origin")

            if csp_issues:
                findings.append({
                    "type": "Weak Content-Security-Policy",
                    "evidence": f"CSP contains weak directives: {'; '.join(csp_issues)}",
                    "how_found": "Inspected Content-Security-Policy header value",
                    "severity": "low",
                    "confidence": 80,
                    "payload": None,
                    "evidence_url": url,
                    "evidence_body": "",
                    "evidence_headers": headers,
                    "evidence_status": status,
                })
    except Exception:
        pass

    return findings
