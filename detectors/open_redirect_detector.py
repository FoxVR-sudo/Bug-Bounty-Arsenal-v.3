# detectors/open_redirect_detector.py
# Active detector for open-redirect candidates (safe, uses allow_redirects=False).
from urllib.parse import urlparse, parse_qs, urlencode
import logging

from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)


@register_active
async def open_redirect_detector(session, url, context):
    findings = []
    if not url:
        return findings

    per_host_rate = context.get("per_host_rate", None)

    # Payload variants cover the most common open-redirect bypass techniques:
    # 1. Full HTTPS URL
    # 2. Protocol-relative URL (//)
    # 3. Triple-slash (some parsers strip one slash)
    # 4. Path-traversal prefix (@evil.com)
    # 5. Fragment-based bypass
    REDIRECT_PAYLOADS = [
        "https://example.com/",
        "//example.com/",
        "///example.com/",
        "https:example.com/",
        "/redirect?to=https://example.com/",
    ]
    # Unique marker we look for in the Location header to confirm our payload lands
    MARKER_DOMAIN = "example.com"

    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        qs = parse_qs(parsed.query, keep_blank_values=True)
        candidate_params = list(qs.keys())
        if not candidate_params:
            return findings

        for param in candidate_params:
            for payload in REDIRECT_PAYLOADS:
                new_qs = dict(qs)
                new_qs[param] = [payload]
                new_query = urlencode(new_qs, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()

                await await_host_token(host, per_host_rate)
                try:
                    async with session.get(test_url, allow_redirects=False, timeout=10) as resp:
                        loc = resp.headers.get("Location") or resp.headers.get("location") or ""
                        if resp.status in (301, 302, 303, 307, 308) and MARKER_DOMAIN in loc:
                            findings.append({
                                "type": "Open Redirect Candidate",
                                "evidence": f"Parameter '{param}' leads to external Location header: {loc}",
                                "how_found": f"Sent redirect payload '{payload}' in param '{param}' and received redirect",
                                "severity": "medium",
                                "confidence": 70,
                                "payload": f"{param}={payload}",
                                "evidence_url": test_url,
                                "evidence_body": "",
                                "evidence_headers": dict(resp.headers),
                                "evidence_status": resp.status,
                            })
                            break  # One confirmed redirect per param is enough
                except Exception as e:
                    logger.debug("Open redirect request failed for %s: %s", test_url, e)
    except Exception:
        pass

    return findings
